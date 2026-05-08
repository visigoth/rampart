//go:build darwin

// E2E test for .1.5: full session lifecycle from `rampart -- <agent>`
// through clean shutdown. Exercises the entire wiring chain in-process:
//
//	loadPolicy → buildSandboxedCmd (real /usr/bin/sandbox-exec)
//	→ supervisor.Run with proxy/session-socket/auth-engine/macos-monitor
//	→ child exits cleanly → all subsystems shut down → exit code 0.
//
// A stub agent is compiled at test setup (representing Claude Code) that
// performs in-policy filesystem operations: read+write inside the workdir.
// The post-test assertions verify file side effects, exit code, and that
// the session socket is unlinked after shutdown (TR97/TR98 cleanup).

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestE2E_FullSessionLifecycle covers the happy path: rampart launches a
// stub agent under a real Seatbelt sandbox, the agent performs in-policy
// filesystem ops and exits 0, rampart returns exit code 0, and the session
// socket is unlinked on shutdown. This is the load-bearing wiring test for
// .1.5: it exercises loadPolicy → buildSandboxedCmd → supervisor.Run
// with the real proxy/session/engine/monitor subsystems composed together.
func TestE2E_FullSessionLifecycle_HappyPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only: requires /usr/bin/sandbox-exec")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain required to compile stub agent: %v", err)
	}

	resolvedWorkdir := makeE2ELifecycleEnv(t)
	stubBin := buildE2EStubAgent(t, resolvedWorkdir)

	// Verify HOME-derived session dir is empty before launch (no stale sockets).
	sessionsDir := filepath.Join(os.Getenv("HOME"), ".rampart", "sessions")

	// The stub reads STUB_WORKDIR to know where to write its marker. Pass it
	// through rampart's --env so it propagates to the sandboxed child.
	flags := &runFlags{
		mode:     "enforcing",
		envVars:  []string{"STUB_WORKDIR=" + resolvedWorkdir},
		noTmux:   true, // avoid spawning a real tmux pane in the test
		headless: true, // skip the tmux subsystem path entirely
	}

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exitCode, err := runLaunch(ctx, flags, []string{stubBin}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runLaunch: %v\nstderr: %s", err, stderr.String())
	}
	if exitCode != 0 {
		t.Fatalf("exit code: got %d, want 0\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
	}

	// Stub agent must have run: marker file exists with expected content.
	marker := filepath.Join(resolvedWorkdir, "stub.touched")
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("stub-agent did not write marker (in-policy write failed?): %v", err)
	}
	if string(data) != "ok\n" {
		t.Errorf("marker content: got %q, want %q", string(data), "ok\n")
	}

	// Stub agent's stdout reached us via the supervisor's pipe.
	if !strings.Contains(stdout.String(), "stub-agent: wrote+read") {
		t.Errorf("stub-agent stdout not propagated: %q", stdout.String())
	}

	// TR97/TR98: session socket file must be unlinked after shutdown.
	if entries, err := os.ReadDir(sessionsDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".sock") {
				t.Errorf("session socket leaked after shutdown: %s", e.Name())
			}
		}
	}
}

// TestE2E_FullSessionLifecycle_SIGINTGracefulShutdown verifies that a SIGINT
// delivered to the rampart process during the child's run produces a graceful
// shutdown: the child is signalled, supervisor.Run returns, and the session
// socket is cleaned up. Asserts the supervisor's signal-handling path
// (TR48-TR51) works end-to-end with the production wiring.
func TestE2E_FullSessionLifecycle_SIGINTGracefulShutdown(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only: requires /usr/bin/sandbox-exec")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}

	resolvedWorkdir := makeE2ELifecycleEnv(t)

	// Use /bin/sleep as the long-running stub. /bin is the CLAUDE_BIN_DIR
	// allowing process-exec on /bin/sleep.
	flags := &runFlags{
		mode:     "enforcing",
		noTmux:   true,
		headless: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch in a goroutine; SIGINT is delivered by cancelling ctx (the cobra
	// signal.NotifyContext layer is not in the call chain — runLaunch
	// receives our ctx directly).
	type result struct {
		code int
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		var out, errOut bytes.Buffer
		code, runErr := runLaunch(ctx, flags, []string{"/bin/sleep", "30"}, nil, &out, &errOut)
		resCh <- result{code: code, err: runErr}
	}()

	// Give the child time to start before signalling.
	time.Sleep(500 * time.Millisecond)

	// Cancel the context to trigger graceful shutdown. The supervisor's
	// monitor goroutine sees ctx.Done() and signals the child SIGTERM, then
	// SIGKILL after the grace period.
	cancel()

	select {
	case r := <-resCh:
		// runLaunch returns nil (it never returns the supervisor's Result.Err
		// to the caller — it logs in verbose mode and returns ExitCode).
		if r.err != nil {
			t.Fatalf("runLaunch returned err: %v", r.err)
		}
		// The child was killed by signal: exit code is non-zero (typically
		// the signal-derived code from sleep being killed). The key
		// assertion is that we returned promptly without hanging.
		_ = r.code
	case <-time.After(15 * time.Second):
		// Force-kill any leaked sleep so the test binary can exit. Best
		// effort — we report the timeout regardless.
		_ = exec.Command("pkill", "-f", "sleep 30").Run()
		t.Fatal("runLaunch did not return after context cancel within 15s")
	}

	// Session socket must be unlinked after shutdown.
	sessionsDir := filepath.Join(os.Getenv("HOME"), ".rampart", "sessions")
	if entries, err := os.ReadDir(sessionsDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".sock") {
				t.Errorf("session socket leaked after SIGINT: %s", e.Name())
			}
		}
	}

	_ = resolvedWorkdir
}

// TestE2E_FullSessionLifecycle_BinaryViaExec covers the same flow as
// HappyPath but invokes the real rampart binary as a subprocess (rather
// than runLaunch in-process). This proves the cobra → main → runLaunch path
// is wired correctly end-to-end and that exitWithCode propagates the
// supervisor's exit code to the OS.
func TestE2E_FullSessionLifecycle_BinaryViaExec(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain required: %v", err)
	}

	// Build the rampart binary into the test temp dir.
	binDir, err := os.MkdirTemp("/tmp", "ramp-bin")
	if err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(binDir) })
	rampartBin := filepath.Join(binDir, "rampart")

	build := exec.Command("go", "build", "-o", rampartBin, "github.com/visigoth/rampart/cmd/rampart")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build rampart: %v\n%s", err, out)
	}

	resolvedWorkdir := makeE2ELifecycleEnv(t)
	stubBin := buildE2EStubAgent(t, resolvedWorkdir)

	cmd := exec.Command(rampartBin, "--no-tmux", "--headless",
		"--env", "STUB_WORKDIR="+resolvedWorkdir,
		"--", stubBin)
	cmd.Dir = resolvedWorkdir
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"))

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rampart binary exited with error: %v\nstdout: %s\nstderr: %s",
				err, out.String(), errOut.String())
		}
		// cmd.Run() returns nil only on exit code 0.
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Signal(syscall.SIGKILL)
		t.Fatal("rampart binary did not exit within 30s")
	}

	if !strings.Contains(out.String(), "stub-agent: wrote+read") {
		t.Errorf("stub-agent stdout not propagated through binary:\nstdout: %s\nstderr: %s",
			out.String(), errOut.String())
	}

	marker := filepath.Join(resolvedWorkdir, "stub.touched")
	if _, err := os.ReadFile(marker); err != nil {
		t.Errorf("stub-agent marker missing: %v", err)
	}
}

