//go:build darwin

package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeLogBinary writes scripted ndjson lines to stdout and exits, simulating
// the macOS `log` command. The script is a JSONL string passed via env var
// FAKE_LOG_SCRIPT; each line is written as-is to stdout. Optional sleep ms
// between lines via FAKE_LOG_SLEEP_MS to simulate the live tail cadence.
const fakeLogScriptEnv = "FAKE_LOG_SCRIPT"
const fakeLogSleepEnv = "FAKE_LOG_SLEEP_MS"
const fakeLogModeEnv = "FAKE_LOG_MODE"

func init() {
	if os.Getenv(fakeLogModeEnv) == "" {
		return
	}
	runFakeLog()
	os.Exit(0)
}

// runFakeLog emits the scripted ndjson then either exits or hangs until
// SIGKILL — matching `log stream`, which never returns on its own.
func runFakeLog() {
	script := os.Getenv(fakeLogScriptEnv)
	for _, line := range strings.Split(script, "\n") {
		if line == "" {
			continue
		}
		fmt.Println(line)
	}
	if mode := os.Getenv(fakeLogModeEnv); mode == "hang" {
		// Block forever — exec.CommandContext will SIGKILL on ctx-done.
		select {}
	}
}

// buildFakeLog returns the [path, args...] slice that, when used as
// realLogStreamer.Cmd, re-executes the test binary in fake-log mode.
func buildFakeLog(t *testing.T) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return []string{exe}
}

// jlineSandbox builds an ndjson line emulating a `log stream` record from
// the sandbox.reporting subsystem.
func jlineSandbox(pid int, eventMessage string) string {
	rec := map[string]any{
		"subsystem":    "com.apple.sandbox.reporting",
		"eventType":    "logEvent",
		"processID":    pid,
		"eventMessage": eventMessage,
	}
	b, _ := json.Marshal(rec)
	return string(b)
}

// jlineNoise builds an ndjson line for a different subsystem / pid that
// the streamer must ignore.
func jlineNoise(pid int, subsystem, msg string) string {
	rec := map[string]any{
		"subsystem":    subsystem,
		"eventType":    "logEvent",
		"processID":    pid,
		"eventMessage": msg,
	}
	b, _ := json.Marshal(rec)
	return string(b)
}

func collectEvents(t *testing.T, ch <-chan ViolationEvent, want int, timeout time.Duration) []ViolationEvent {
	t.Helper()
	got := make([]ViolationEvent, 0, want)
	deadline := time.Now().Add(timeout)
	for len(got) < want && time.Now().Before(deadline) {
		select {
		case ev, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, ev)
		case <-time.After(time.Until(deadline)):
			return got
		}
	}
	return got
}

// TestRealLogStreamer_ParsesSandboxViolation drives the streamer through a
// fake `log` binary that emits one parseable sandbox.reporting line for the
// supervised pid; expects exactly one ViolationEvent on the channel.
func TestRealLogStreamer_ParsesSandboxViolation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	pid := 7777
	script := strings.Join([]string{
		jlineSandbox(pid, "Sandbox: 7777 deny(1) file-read-data /etc/ssh/sshd_config"),
	}, "\n")

	s := &realLogStreamer{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cmd:    buildFakeLog(t),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := s.Cmd
	t.Setenv(fakeLogModeEnv, "exit")
	t.Setenv(fakeLogScriptEnv, script)
	_ = cmd

	ch, err := s.Stream(ctx, pid)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	events := collectEvents(t, ch, 1, 2*time.Second)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.PID != uint32(pid) {
		t.Errorf("PID = %d, want %d", ev.PID, pid)
	}
	if ev.Syscall != "read" {
		t.Errorf("Syscall = %q, want \"read\"", ev.Syscall)
	}
	if ev.Path != "/etc/ssh/sshd_config" {
		t.Errorf("Path = %q, want \"/etc/ssh/sshd_config\"", ev.Path)
	}
	if ev.Required != CapRead {
		t.Errorf("Required = %v, want CapRead", ev.Required)
	}
}

// TestRealLogStreamer_FiltersOtherPIDs ensures records whose processID does
// not match are dropped — the Subsystem must never deliver another process's
// violations into the supervised child's killer.
func TestRealLogStreamer_FiltersOtherPIDs(t *testing.T) {
	pid := 100
	script := strings.Join([]string{
		jlineSandbox(99, "Sandbox: 99 deny(1) file-read-data /etc/passwd"),
		jlineSandbox(101, "Sandbox: 101 deny(1) file-read-data /etc/hosts"),
		jlineSandbox(pid, "Sandbox: 100 deny(1) file-write-data /var/log/foo"),
	}, "\n")

	s := &realLogStreamer{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cmd:    buildFakeLog(t),
	}
	t.Setenv(fakeLogModeEnv, "exit")
	t.Setenv(fakeLogScriptEnv, script)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Stream(ctx, pid)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Drain everything until close.
	var got []ViolationEvent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case ev, ok := <-ch:
			if !ok {
				goto done
			}
			got = append(got, ev)
		case <-time.After(100 * time.Millisecond):
		}
	}
done:
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 event for pid %d, got %d (%+v)", pid, len(got), got)
	}
	if got[0].PID != uint32(pid) {
		t.Errorf("event for wrong pid: %d", got[0].PID)
	}
	if got[0].Path != "/var/log/foo" {
		t.Errorf("path = %q", got[0].Path)
	}
}

// TestRealLogStreamer_IgnoresOtherSubsystems guards against future predicate
// drift: even if a non-sandbox.reporting record sneaks past the predicate,
// the streamer must drop it.
func TestRealLogStreamer_IgnoresOtherSubsystems(t *testing.T) {
	pid := 42
	script := strings.Join([]string{
		jlineNoise(pid, "com.apple.coreduet", "Fetching uncached value for /etc/hosts"),
		jlineSandbox(pid, "Sandbox: 42 deny(1) file-read-data /etc/hosts"),
	}, "\n")

	s := &realLogStreamer{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cmd:    buildFakeLog(t),
	}
	t.Setenv(fakeLogModeEnv, "exit")
	t.Setenv(fakeLogScriptEnv, script)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Stream(ctx, pid)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	got := collectEvents(t, ch, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 event after ignoring noise, got %d", len(got))
	}
}

// TestRealLogStreamer_ContextCancelStopsSubprocess verifies ctx cancel kills
// the long-running `log stream` subprocess and closes the output channel.
func TestRealLogStreamer_ContextCancelStopsSubprocess(t *testing.T) {
	pid := 1
	s := &realLogStreamer{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cmd:    buildFakeLog(t),
	}
	t.Setenv(fakeLogModeEnv, "hang")
	t.Setenv(fakeLogScriptEnv, "")

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := s.Stream(ctx, pid)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	// Cancel almost immediately — subprocess is in select{} so it would
	// otherwise block forever.
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			// Spurious event tolerated; loop until close.
			for range ch {
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("output channel did not close after ctx cancel")
	}
}

// TestRealLogStreamer_DropsNoiseLines feeds banner output and malformed
// lines and asserts the streamer keeps going past them to the real event.
func TestRealLogStreamer_DropsNoiseLines(t *testing.T) {
	pid := 9
	script := strings.Join([]string{
		`Filtering the log data using "subsystem == \"com.apple.sandbox.reporting\""`,
		"not-json-at-all",
		"{",
		jlineSandbox(pid, "Sandbox: 9 deny(1) file-read-data /tmp/secret"),
	}, "\n")

	s := &realLogStreamer{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cmd:    buildFakeLog(t),
	}
	t.Setenv(fakeLogModeEnv, "exit")
	t.Setenv(fakeLogScriptEnv, script)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Stream(ctx, pid)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	got := collectEvents(t, ch, 1, 2*time.Second)
	if len(got) != 1 || got[0].Path != "/tmp/secret" {
		t.Fatalf("expected single event for /tmp/secret, got %+v", got)
	}
}
