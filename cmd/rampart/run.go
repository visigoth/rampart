package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/visigoth/rampart/internal/session"
	"github.com/visigoth/rampart/internal/supervisor"
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

	// Session socket: subscribers (e.g. `rampart escalations --watch`) connect
	// here to receive escalation pushes and presence updates. Required for the
	// escalation flow to function; bind failure is fatal.
	socketPath, err := session.DefaultSocketPath()
	if err != nil {
		return 1, fmt.Errorf("session socket path: %w", err)
	}
	srv := session.NewServer(session.ServerConfig{SocketPath: socketPath})
	fatal = append(fatal, srv)

	cfg := supervisor.Config{
		Cmd:                   cmd,
		FatalSubsystems:       fatal,
		RecoverableSubsystems: nil,
		Verbose:               flags.verbose,
	}

	result := supervisor.Run(ctx, cfg)
	if result.Err != nil && flags.verbose {
		fmt.Fprintf(stderr, "rampart: %v\n", result.Err)
	}
	return result.ExitCode, nil
}

// buildSandboxedCmd is implemented per-platform in run_<goos>.go.
//
// Contract: given a compiled policy and the user-supplied target command +
// args, return an *exec.Cmd whose argv0 is the platform sandbox launcher
// (sandbox-exec on darwin, bwrap on linux) and whose argv tail re-execs the
// target under the sandbox restrictions encoded in cp.Policy.
var _ = exec.Cmd{}
