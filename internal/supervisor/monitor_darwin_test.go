//go:build darwin

package supervisor

import (
	"context"
	"testing"
)

// mockLogReader returns canned log output for tests.
type mockLogReader struct {
	lines []string
	err   error
}

func (m *mockLogReader) QuerySandboxLogs(_ int) ([]string, error) {
	return m.lines, m.err
}

// captureEngine records the last ViolationEvent it receives.
type captureEngine struct {
	last *ViolationEvent
}

func (c *captureEngine) Authorize(_ context.Context, ev ViolationEvent) Decision {
	c.last = &ev
	return Deny
}

func makeWaitFunc(exitStatus, signal int, err error) func(int) (int, int, error) {
	return func(_ int) (int, int, error) {
		return exitStatus, signal, err
	}
}

func TestMonitor_NormalExit_NoViolation(t *testing.T) {
	engine := &captureEngine{}
	m := NewMonitor(MonitorConfig{
		PID:    1234,
		Engine: engine,
		WaitFunc: makeWaitFunc(0, 0, nil),
		LogReader: &mockLogReader{},
	})

	err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if engine.last != nil {
		t.Error("expected no violation on normal exit (status 0)")
	}
}

func TestMonitor_NonZeroExit_NoViolation(t *testing.T) {
	engine := &captureEngine{}
	m := NewMonitor(MonitorConfig{
		PID:    1234,
		Engine: engine,
		WaitFunc: makeWaitFunc(1, 0, nil),
		LogReader: &mockLogReader{},
	})

	err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if engine.last != nil {
		t.Error("expected no violation on non-zero exit code")
	}
}

func TestMonitor_SIGTERM_NotViolation(t *testing.T) {
	engine := &captureEngine{}
	m := NewMonitor(MonitorConfig{
		PID:    1234,
		Engine: engine,
		WaitFunc: makeWaitFunc(0, 15 /* SIGTERM */, nil),
		LogReader: &mockLogReader{},
	})

	err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if engine.last != nil {
		t.Error("expected no violation for SIGTERM (not a sandbox kill)")
	}
}

func TestMonitor_SIGKILL_IsViolation(t *testing.T) {
	engine := &captureEngine{}
	logLines := []string{
		`deny(1) file-read-data /etc/ssh/sshd_config`,
	}
	m := NewMonitor(MonitorConfig{
		PID:    9999,
		Engine: engine,
		WaitFunc: makeWaitFunc(0, 9 /* SIGKILL */, nil),
		LogReader: &mockLogReader{lines: logLines},
	})

	err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if engine.last == nil {
		t.Fatal("expected ViolationEvent on SIGKILL, got nil")
	}
	if engine.last.PID != 9999 {
		t.Errorf("ViolationEvent.PID = %d, want 9999", engine.last.PID)
	}
}

func TestMonitor_SIGKILL_ParsesOperation(t *testing.T) {
	engine := &captureEngine{}
	m := NewMonitor(MonitorConfig{
		PID:    1234,
		Engine: engine,
		WaitFunc: makeWaitFunc(0, 9, nil),
		LogReader: &mockLogReader{lines: []string{
			`deny(1) file-read-data /etc/ssh/sshd_config`,
		}},
	})
	_ = m.Run(context.Background())

	if engine.last == nil {
		t.Fatal("no violation event")
	}
	if engine.last.Syscall != "read" {
		t.Errorf("Syscall = %q, want read", engine.last.Syscall)
	}
	if engine.last.Path != "/etc/ssh/sshd_config" {
		t.Errorf("Path = %q, want /etc/ssh/sshd_config", engine.last.Path)
	}
}

func TestMonitor_SIGKILL_ParsesWriteOperation(t *testing.T) {
	engine := &captureEngine{}
	m := NewMonitor(MonitorConfig{
		PID:    1234,
		Engine: engine,
		WaitFunc: makeWaitFunc(0, 9, nil),
		LogReader: &mockLogReader{lines: []string{
			`deny(1) file-write-create /tmp/evil.sh`,
		}},
	})
	_ = m.Run(context.Background())

	if engine.last == nil {
		t.Fatal("no violation event")
	}
	if engine.last.Syscall != "write" {
		t.Errorf("Syscall = %q, want write", engine.last.Syscall)
	}
}

func TestMonitor_SIGKILL_NoLogs_FallsBackToUnknown(t *testing.T) {
	engine := &captureEngine{}
	m := NewMonitor(MonitorConfig{
		PID:    1234,
		Engine: engine,
		WaitFunc: makeWaitFunc(0, 9, nil),
		LogReader: &mockLogReader{lines: nil},
	})
	_ = m.Run(context.Background())

	if engine.last == nil {
		t.Fatal("expected violation event even with no log lines")
	}
	if engine.last.Path != "(unknown)" {
		t.Errorf("Path = %q, want (unknown) when no log available", engine.last.Path)
	}
}

func TestMonitor_ContextCancel_Exits(t *testing.T) {
	// Block waitpid forever; context cancel should unblock Run.
	blocked := make(chan struct{})
	m := NewMonitor(MonitorConfig{
		PID: 1234,
		WaitFunc: func(_ int) (int, int, error) {
			<-blocked
			return 0, 0, nil
		},
		LogReader: &mockLogReader{},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	cancel()
	err := <-done
	if err != nil {
		t.Errorf("Run after ctx cancel: %v", err)
	}
}

func TestViolationSummary(t *testing.T) {
	ev := ViolationEvent{Syscall: "read", Path: "/etc/ssh/sshd_config"}
	got := ViolationSummary(ev)
	want := "Process killed: tried to read /etc/ssh/sshd_config"
	if got != want {
		t.Errorf("ViolationSummary = %q, want %q", got, want)
	}
}

func TestPolicySuggestion(t *testing.T) {
	ev := ViolationEvent{Syscall: "read", Path: "/etc/ssh/sshd_config"}
	got := PolicySuggestion(ev)
	want := "add /etc/ssh to read"
	if got != want {
		t.Errorf("PolicySuggestion = %q, want %q", got, want)
	}
}

func TestParseSandboxLogLine(t *testing.T) {
	tests := []struct {
		line    string
		wantOp  string
		wantPath string
		wantOK  bool
	}{
		{
			line:     `deny(1) file-read-data /etc/ssh/sshd_config`,
			wantOp:   "read",
			wantPath: "/etc/ssh/sshd_config",
			wantOK:   true,
		},
		{
			line:     `deny(2) file-write-create /tmp/pwned`,
			wantOp:   "write",
			wantPath: "/tmp/pwned",
			wantOK:   true,
		},
		{
			line:     `deny(1) process-exec* /usr/bin/curl`,
			wantOp:   "exec",
			wantPath: "/usr/bin/curl",
			wantOK:   true,
		},
		{
			line:     `Sandbox: 1234 deny file-read-data /home/user/.ssh/id_rsa`,
			wantOp:   "read",
			wantPath: "/home/user/.ssh/id_rsa",
			wantOK:   true,
		},
		{
			line:    `just some other log line`,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		op, path, ok := parseSandboxLogLine(tt.line)
		if ok != tt.wantOK {
			t.Errorf("parseSandboxLogLine(%q): ok=%v, want %v", tt.line, ok, tt.wantOK)
			continue
		}
		if ok {
			if op != tt.wantOp {
				t.Errorf("parseSandboxLogLine(%q): op=%q, want %q", tt.line, op, tt.wantOp)
			}
			if path != tt.wantPath {
				t.Errorf("parseSandboxLogLine(%q): path=%q, want %q", tt.line, path, tt.wantPath)
			}
		}
	}
}
