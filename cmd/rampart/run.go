package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/visigoth/rampart/internal/ca"
	"github.com/visigoth/rampart/internal/proxy"
	"github.com/visigoth/rampart/internal/session"
	"github.com/visigoth/rampart/internal/supervisor"
	"github.com/visigoth/rampart/internal/tmux"
)

// runLaunch performs the FT13 wiring: load+compile policy, build a
// platform-specific sandboxed *exec.Cmd, construct the supervisor subsystems,
// then call supervisor.Run. Returns the supervisor's Result.ExitCode and any
// fatal error. The caller is responsible for translating that to os.Exit.
func runLaunch(ctx context.Context, flags *runFlags, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 1, fmt.Errorf("no command specified")
	}

	wd, err := os.Getwd()
	if err != nil {
		return 1, fmt.Errorf("getwd: %w", err)
	}

	cp, err := loadPolicy(flags, wd)
	if err != nil {
		return 1, err
	}

	cmd, err := buildSandboxedCmd(cp, flags, args, wd)
	if err != nil {
		return 1, fmt.Errorf("building sandboxed command: %w", err)
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// FatalSubsystems: failures here end the session before, or alongside, the child.
	fatal := []supervisor.Subsystem{}

	// FT16: HTTP forward proxy. Bind the listener now so the allocated port can
	// be injected into the child's environment before exec; the supervisor's
	// Phase 5 starts the child before fatal subsystems run, so deferring
	// proxy.Start to a goroutine inside Run would race the child.
	//
	// Skipped when NetworkMode is "full" — the policy has explicitly opted
	// out of filtering (via `allowed_domains = ["*"]` or an empty wildcard
	// `network { domain "*" {} }` block). The Seatbelt template already
	// emits `(allow network*)` for full mode, so the proxy would only add
	// latency without enforcing anything.
	if len(cp.Policy.ProxyACLs) > 0 && cp.Policy.NetworkMode != "full" {
		ps, env, err := startProxyForPolicy(cp)
		if err != nil {
			return 1, err
		}
		cmd.Env = dedupEnv(append(cmd.Env, env...))
		fatal = append(fatal, ps)
	}

	// Session socket: subscribers (e.g. `rampart escalations --watch`) connect
	// here to receive escalation pushes and presence updates. Required for the
	// escalation flow to function; bind failure is fatal.
	socketPath, err := session.DefaultSocketPath()
	if err != nil {
		return 1, fmt.Errorf("session socket path: %w", err)
	}
	bridge := newSessionBridge()
	srv := session.NewServer(session.ServerConfig{
		SocketPath: socketPath,
		Commands:   bridge,
		Lister:     bridge,
	})
	fatal = append(fatal, srv)

	// Authorization engine + platform violation monitor (FT12 / FT7). The
	// engine is fatal; the monitor needs the child's PID and is wired via
	// PostStartHook below. On non-darwin builds these are nil — a future
	// task will wire the linux NotifRespond applier and seccomp supervisor.
	enforcing := flags.mode != "permissive"
	engineSub, postStart, childExitCh := newAuthSubsystems(srv, bridge, enforcing)
	if engineSub != nil {
		fatal = append(fatal, engineSub)
	}

	// FT10 / TR117: tmux UI pane. Created SYNCHRONOUSLY here, before
	// supervisor.Run starts the child, so:
	//   - the agent pane's pty geometry is final at child startup — no
	//     mid-startup SIGWINCH that can break the agent's initial TUI
	//     render (claude/ink/Bun were susceptible to this)
	//   - tmux split-window -d keeps focus on the agent pane so the user's
	//     keystrokes drive the agent, not the watch pane
	// Failures are recoverable: log and degrade to interactive-direct.
	var recoverable []supervisor.Subsystem
	if DetectMode(flags) == ModeInteractiveTmux {
		// Spawn the watch pane via our own executable rather than the
		// bare name "rampart". `tmux split-window` runs the command
		// through the shell, which resolves the bare name against PATH.
		// In production a PATH lookup finds the installed binary; in
		// tests the binary lives in a tmpdir that isn't on PATH and the
		// pane would immediately exit. Self-reference is the most
		// faithful choice anyway — guarantees the watch runs the same
		// build as the agent supervisor.
		paneCmd := "rampart escalations --watch"
		if self, err := os.Executable(); err == nil {
			paneCmd = fmt.Sprintf("%s escalations --watch", shellQuote(self))
		}
		pane, err := tmux.Setup(tmux.PaneConfig{
			PaneCommand: paneCmd,
			NewSession:  flags.newSession,
			NewWindow:   flags.newWindow,
		})
		if err != nil {
			fmt.Fprintf(stderr, "rampart: tmux pane setup failed (continuing without escalation pane): %v\n", err)
		} else {
			recoverable = append(recoverable, &tmuxPaneSubsystem{pane: pane})
		}
	}

	cfg := supervisor.Config{
		Cmd:                   cmd,
		FatalSubsystems:       fatal,
		RecoverableSubsystems: recoverable,
		Verbose:               flags.verbose,
		PostStartHook:         postStart,
		ChildExitInfo:         childExitCh,
	}

	result := supervisor.Run(ctx, cfg)
	if result.Err != nil && flags.verbose {
		fmt.Fprintf(stderr, "rampart: %v\n", result.Err)
	}
	return result.ExitCode, nil
}

// startProxyForPolicy compiles ACL rules from the resolved policy, loads the
// MITM CA when any rule needs it, starts the forward proxy on a loopback port,
// and writes a CA cert PEM to a temp file when the proxy is in MITM mode.
// Returns the supervisor adapter, the env additions for the sandboxed Cmd,
// and any startup error.
func startProxyForPolicy(cp *compiledPolicy) (*proxySubsystem, []string, error) {
	rules := proxy.CompileACLRules(cp.Policy.ProxyACLs, cp.Policy.MitmDomains)

	// no_tls_mitm: force every rule to tunnel-mode regardless of paths or
	// mitm_domains. The proxy still enforces domain-level allow/deny at
	// CONNECT, but skips TLS decryption — so no CA is needed.
	if cp.Policy.NoTLSMITM {
		for i := range rules {
			rules[i].MITM = false
		}
	}

	var caCert *tls.Certificate
	mitmRequired := false
	for _, r := range rules {
		if r.MITM {
			mitmRequired = true
			break
		}
	}
	if mitmRequired {
		loaded, err := ca.LoadCA()
		if err != nil {
			if errors.Is(err, ca.ErrNotInstalled) {
				return nil, nil, fmt.Errorf("MITM required by ACL rules but CA not installed: run 'rampart init'")
			}
			return nil, nil, fmt.Errorf("load CA: %w", err)
		}
		caCert = loaded.TLSCert()
	}

	p, err := proxy.Start(proxy.Config{Rules: rules, CA: caCert})
	if err != nil {
		return nil, nil, fmt.Errorf("starting proxy: %w", err)
	}

	var caCertPath string
	if len(p.CACertPEM) > 0 {
		f, ferr := os.CreateTemp("", "rampart-ca-*.pem")
		if ferr != nil {
			_ = p.Close()
			return nil, nil, fmt.Errorf("writing CA pem: %w", ferr)
		}
		if _, werr := f.Write(p.CACertPEM); werr != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			_ = p.Close()
			return nil, nil, fmt.Errorf("writing CA pem: %w", werr)
		}
		_ = f.Close()
		caCertPath = f.Name()
	}

	return &proxySubsystem{p: p, caCertPath: caCertPath}, proxyEnvVars(p.Port, caCertPath), nil
}

// buildSandboxedCmd is implemented per-platform in run_<goos>.go.
//
// Contract: given a compiled policy and the user-supplied target command +
// args, return an *exec.Cmd whose argv0 is the platform sandbox launcher
// (sandbox-exec on darwin, bwrap on linux) and whose argv tail re-execs the
// target under the sandbox restrictions encoded in cp.Policy.
var _ = exec.Cmd{}

// shellQuote single-quotes s for safe inclusion in a shell command. Used
// to embed os.Executable() paths in the tmux pane command, which tmux
// hands to /bin/sh. Single-quotes disable interpretation of every
// shell-special character except for the closing single-quote itself —
// embedded single-quotes are escaped via the standard '\'' sequence.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
