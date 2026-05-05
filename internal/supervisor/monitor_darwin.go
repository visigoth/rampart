//go:build darwin

package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// MonitorConfig holds the inputs for the macOS waitpid monitor.
type MonitorConfig struct {
	// PID is the sandboxed child's process ID.
	PID int

	// Engine receives ViolationEvents when SIGKILL is detected.
	// If nil, violations are only logged.
	Engine AuthEngine

	// Logger is the diagnostic sink. Defaults to slog.Default() if nil.
	Logger *slog.Logger

	// LogReader is injectable for tests. Defaults to realLogReader when nil.
	LogReader LogReader

	// WaitFunc is injectable for tests. Defaults to syscall.Wait4 when nil.
	WaitFunc func(pid int) (exitStatus int, signal int, err error)
}

func (c *MonitorConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *MonitorConfig) logReader() LogReader {
	if c.LogReader != nil {
		return c.LogReader
	}
	return realLogReader{}
}

func (c *MonitorConfig) waitFunc() func(pid int) (int, int, error) {
	if c.WaitFunc != nil {
		return c.WaitFunc
	}
	return defaultWait4
}

// LogReader abstracts the macOS system log query (injectable for tests).
type LogReader interface {
	// QuerySandboxLogs returns log lines from the system log matching the given
	// PID and sandbox-related predicates.
	QuerySandboxLogs(pid int) ([]string, error)
}

// realLogReader queries the macOS unified log.
type realLogReader struct{}

func (realLogReader) QuerySandboxLogs(pid int) ([]string, error) {
	// Query the last 10 seconds of log for Sandbox entries matching this PID.
	// Allow up to 500ms for the log to flush (AC16 buffer delay).
	time.Sleep(300 * time.Millisecond)
	args := []string{
		"log", "show",
		"--last", "10s",
		"--predicate",
		fmt.Sprintf(`subsystem == "com.apple.sandbox.reporting" AND eventMessage CONTAINS "%d"`, pid),
		"--info",
		"--style", "compact",
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		// Non-fatal: log unavailable. Return empty slice.
		return nil, nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "deny") || strings.Contains(line, "violation") || strings.Contains(line, "Sandbox") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// Monitor is a Subsystem that watches the sandboxed child on macOS.
// It calls waitpid, detects SIGKILL (Seatbelt violation), parses the log,
// and sends a ViolationEvent to the authorization engine.
type Monitor struct {
	cfg MonitorConfig
}

// NewMonitor creates a new macOS violation monitor.
func NewMonitor(cfg MonitorConfig) *Monitor {
	return &Monitor{cfg: cfg}
}

// Name implements Subsystem.
func (m *Monitor) Name() string { return "macos-monitor" }

// Run implements Subsystem. It blocks until the child exits or ctx is cancelled.
// Returns nil on clean shutdown.
func (m *Monitor) Run(ctx context.Context) error {
	waitFn := m.cfg.waitFunc()

	// Poll waitpid in a goroutine since it's blocking.
	type waitResult struct {
		exitStatus int
		signal     int
		err        error
	}
	ch := make(chan waitResult, 1)
	go func() {
		status, sig, err := waitFn(m.cfg.PID)
		ch <- waitResult{exitStatus: status, signal: sig, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil
	case result := <-ch:
		if result.err != nil {
			return fmt.Errorf("waitpid(%d): %w", m.cfg.PID, result.err)
		}
		m.handleExit(ctx, result.exitStatus, result.signal)
		return nil
	}
}

// handleExit processes the child's exit status.
func (m *Monitor) handleExit(ctx context.Context, exitStatus, signal int) {
	log := m.cfg.logger()

	// FR32.1: only SIGKILL is a sandbox violation.
	if signal != int(syscall.SIGKILL) {
		switch {
		case exitStatus == 0:
			log.Info("macos-monitor: child exited cleanly", "pid", m.cfg.PID)
		case signal != 0:
			log.Info("macos-monitor: child exited by signal (not sandbox)",
				"pid", m.cfg.PID, "signal", signal)
		default:
			log.Info("macos-monitor: child exited with code",
				"pid", m.cfg.PID, "exit_code", exitStatus)
		}
		return
	}

	log.Info("macos-monitor: child killed by SIGKILL — likely sandbox violation",
		"pid", m.cfg.PID)

	// FR33: query the system log for violation context.
	lines, err := m.cfg.logReader().QuerySandboxLogs(m.cfg.PID)
	if err != nil {
		log.Warn("macos-monitor: log query failed", "err", err)
	}

	ev := m.buildViolationEvent(lines)

	log.Info("macos-monitor: sandbox violation detected",
		"pid", m.cfg.PID,
		"operation", ev.Syscall,
		"path", ev.Path,
		"summary", ViolationSummary(ev))

	if m.cfg.Engine != nil {
		m.cfg.Engine.Authorize(ctx, ev)
	}
}

// buildViolationEvent constructs a ViolationEvent from log lines.
// Falls back to generic values when parsing fails.
func (m *Monitor) buildViolationEvent(logLines []string) ViolationEvent {
	ev := ViolationEvent{
		PID:     uint32(m.cfg.PID),
		Syscall: "unknown",
		Path:    "(unknown)",
	}
	for _, line := range logLines {
		op, path, ok := parseSandboxLogLine(line)
		if ok {
			ev.Syscall = op
			ev.Path = path
			ev.Required = capFromOperation(op)
			break
		}
	}
	return ev
}

// ViolationSummary returns a human-readable summary for a sandbox SIGKILL (FR34).
func ViolationSummary(ev ViolationEvent) string {
	return fmt.Sprintf("Process killed: tried to %s %s", ev.Syscall, ev.Path)
}

// PolicySuggestion returns a short text hint for updating the policy (FR35.1).
func PolicySuggestion(ev ViolationEvent) string {
	if ev.Path == "" || ev.Path == "(unknown)" {
		return ""
	}
	dir := ev.Path
	if idx := strings.LastIndex(dir, "/"); idx > 0 {
		dir = dir[:idx]
	}
	return fmt.Sprintf("add %s to %s", dir, ev.Syscall)
}

// Patterns for parsing Apple Sandbox log lines.
// Typical line: "... deny(1) file-read-data /etc/ssh/sshd_config"
var (
	sandboxLogPattern = regexp.MustCompile(
		`deny\(\d+\)\s+([\w\-\*]+)\s+(/[^\s]+)`)
	// Alternative compact form: "Sandbox: PID deny file-read /etc/passwd"
	sandboxCompactPattern = regexp.MustCompile(
		`Sandbox:\s+\d+\s+deny\s+([\w\-\*]+)\s+(/[^\s]+)`)
)

// parseSandboxLogLine extracts (operation, path, ok) from a sandbox log line.
func parseSandboxLogLine(line string) (op, path string, ok bool) {
	if m := sandboxLogPattern.FindStringSubmatch(line); m != nil {
		return normalizeSandboxOp(m[1]), m[2], true
	}
	if m := sandboxCompactPattern.FindStringSubmatch(line); m != nil {
		return normalizeSandboxOp(m[1]), m[2], true
	}
	return "", "", false
}

// normalizeSandboxOp maps raw SBPL operation names to our canonical form.
func normalizeSandboxOp(raw string) string {
	switch {
	case strings.HasPrefix(raw, "file-write"):
		return "write"
	case strings.HasPrefix(raw, "file-read"):
		return "read"
	case strings.HasPrefix(raw, "process-exec"):
		return "exec"
	case strings.HasPrefix(raw, "network"):
		return "connect"
	default:
		return raw
	}
}

// capFromOperation maps operation name to Capability.
func capFromOperation(op string) Capability {
	switch op {
	case "write":
		return CapWrite
	case "exec":
		return CapExec
	case "read":
		return CapRead
	default:
		return CapStat
	}
}

// defaultWait4 wraps syscall.Wait4 for the real implementation.
func defaultWait4(pid int) (exitStatus int, signal int, err error) {
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		return 0, 0, err
	}
	if ws.Exited() {
		return ws.ExitStatus(), 0, nil
	}
	if ws.Signaled() {
		return 0, int(ws.Signal()), nil
	}
	return 0, 0, nil
}

// FormatPID converts pid int to string (helper used in log queries).
func FormatPID(pid int) string {
	return strconv.Itoa(pid)
}

// Ensure realLogReader satisfies LogReader at compile time.
var _ LogReader = realLogReader{}

// Ensure Monitor satisfies Subsystem at compile time.
var _ Subsystem = (*Monitor)(nil)

// Ensure os is used (imported for os.Getpid stub in non-darwin builds).
var _ = os.Stderr
