//go:build darwin

// Integration test for .2.2: real Seatbelt SIGKILL → Monitor.Run flow.
//
// Launches the test binary under /usr/bin/sandbox-exec with a profile that
// pairs (allow default) with a single deny+(with send-signal SIGKILL) rule
// on a canary path. The helper attempts to read the canary, Seatbelt fires
// SIGKILL, and the supervisor's Monitor reaps the child via cmd.Wait, queries
// the unified log for context, and forwards a ViolationEvent to the engine.

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	e2eVioOpEnv     = "RAMPART_VIOLATION_E2E_OP"
	e2eVioTargetEnv = "RAMPART_VIOLATION_E2E_TARGET"
)

func init() {
	op := os.Getenv(e2eVioOpEnv)
	if op == "" {
		return
	}
	runViolationHelper(op, os.Getenv(e2eVioTargetEnv))
	// unreachable
}

// runViolationHelper performs op against target and exits. Under Seatbelt's
// kill rule the read never returns — the kernel sends SIGKILL synchronously.
func runViolationHelper(op, target string) {
	switch op {
	case "read":
		_, err := os.ReadFile(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "violation-helper read: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "violation-helper: unknown op %q\n", op)
		os.Exit(2)
	}
}

// spyLogReader wraps a LogReader, recording the PID it was queried with.
type spyLogReader struct {
	inner  LogReader
	called bool
	gotPID int
}

func (s *spyLogReader) QuerySandboxLogs(pid int) ([]string, error) {
	s.called = true
	s.gotPID = pid
	return s.inner.QuerySandboxLogs(pid)
}

// cmdWaitFunc adapts exec.Cmd.Wait() into the Monitor's WaitFunc shape so
// the test process and Monitor don't both call syscall.Wait4 on the same PID.
func cmdWaitFunc(cmd *exec.Cmd) func(int) (int, int, error) {
	return func(_ int) (int, int, error) {
		err := cmd.Wait()
		if err == nil {
			return cmd.ProcessState.ExitCode(), 0, nil
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return 0, 0, err
		}
		ws := ee.Sys().(syscall.WaitStatus)
		if ws.Signaled() {
			return 0, int(ws.Signal()), nil
		}
		return ws.ExitStatus(), 0, nil
	}
}

// TestMonitor_E2E_SeatbeltSIGKILLToEngine is the FT7 integration test.
// Real sandbox-exec, real waitpid, real log query — only the engine and the
// LogReader call site are inspected via test doubles.
func TestMonitor_E2E_SeatbeltSIGKILLToEngine(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}

	// Resolve the temp dir so the SBPL literal matches the kernel-resolved
	// path Seatbelt evaluates (e.g. /var/folders → /private/var/folders).
	dir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", dir, err)
	}
	canary := filepath.Join(resolvedDir, "canary")
	if err := os.WriteFile(canary, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write canary: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", exe, err)
	}

	sbpl := fmt.Sprintf(`(version 1)
(allow default)
(deny file-read* (literal "%s") (with send-signal SIGKILL))
`, canary)

	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", sbpl, exe)
	cmd.Env = append(os.Environ(),
		e2eVioOpEnv+"=read",
		e2eVioTargetEnv+"="+canary,
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		t.Fatalf("sandbox-exec start: %v", err)
	}
	pid := cmd.Process.Pid

	spy := &spyLogReader{inner: realLogReader{}}
	engine := &captureEngine{}

	m := NewMonitor(MonitorConfig{
		PID:       pid,
		Engine:    engine,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})),
		WaitFunc:  cmdWaitFunc(cmd),
		LogReader: spy,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Monitor.Run: %v\nhelper stderr: %s", err, stderr.String())
	}

	if !spy.called {
		t.Errorf("expected sandbox log query to be invoked on SIGKILL")
	}
	if spy.gotPID != pid {
		t.Errorf("log query PID = %d, want %d", spy.gotPID, pid)
	}

	if engine.last == nil {
		t.Fatalf("expected ViolationEvent to reach AuthEngine; helper stderr: %s", stderr.String())
	}
	if engine.last.PID != uint32(pid) {
		t.Errorf("ViolationEvent.PID = %d, want %d", engine.last.PID, pid)
	}

	// Operation/path extraction depends on the unified log having indexed the
	// sandboxd entry. Best-effort: assert when we got a parsed line, log when
	// not. The waitpid+SIGKILL+engine-routing path is the load-bearing flow.
	switch {
	case engine.last.Path == "(unknown)":
		t.Logf("unified log returned no parseable sandboxd entry within window; "+
			"event=%+v helper-stderr=%q", *engine.last, stderr.String())
	case !strings.Contains(engine.last.Path, "canary"):
		t.Errorf("ViolationEvent.Path = %q, expected to contain 'canary'", engine.last.Path)
	default:
		if engine.last.Syscall != "read" {
			t.Errorf("ViolationEvent.Syscall = %q, want \"read\"", engine.last.Syscall)
		}
	}
}

// TestMonitor_E2E_SeatbeltCleanExitNoViolation is the negative integration
// test: when the sandboxed child exits cleanly, the Monitor must not query
// the log or notify the engine.
func TestMonitor_E2E_SeatbeltCleanExitNoViolation(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}

	dir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", dir, err)
	}
	allowed := filepath.Join(resolvedDir, "allowed")
	if err := os.WriteFile(allowed, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write allowed: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	sbpl := `(version 1)
(allow default)
`

	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", sbpl, exe)
	cmd.Env = append(os.Environ(),
		e2eVioOpEnv+"=read",
		e2eVioTargetEnv+"="+allowed,
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		t.Fatalf("sandbox-exec start: %v", err)
	}

	spy := &spyLogReader{inner: realLogReader{}}
	engine := &captureEngine{}

	m := NewMonitor(MonitorConfig{
		PID:       cmd.Process.Pid,
		Engine:    engine,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})),
		WaitFunc:  cmdWaitFunc(cmd),
		LogReader: spy,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.Run(ctx); err != nil {
		t.Fatalf("Monitor.Run: %v\nhelper stderr: %s", err, stderr.String())
	}
	if spy.called {
		t.Error("did not expect sandbox log query on clean exit")
	}
	if engine.last != nil {
		t.Errorf("did not expect ViolationEvent on clean exit, got %+v", *engine.last)
	}
}
