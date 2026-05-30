package tmux_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/tmux"
)

// mockRunner records all tmux invocations and returns canned responses.
type mockRunner struct {
	calls   [][]string
	outputs map[string]string // keyed on "cmd arg1 arg2 ..."
	errors  map[string]error
}

func newMockRunner() *mockRunner {
	return &mockRunner{
		// Output keys are tmux subcommands ("split-window", "new-session",
		// …) rather than full prefixes ("tmux split-window"). subcommandOf
		// extracts the subcommand from the recorded argv, which lets the
		// mock match calls regardless of whether tmux.go injected a `-S
		// <socket>` between the program name and the subcommand.
		outputs: map[string]string{
			"split-window": "%5",
			"new-session":  "",
			"resize-pane":  "",
			"kill-pane":    "",
			"kill-session": "",
			"select-pane":  "",
			"new-window":   "%3",
			"tput cols":    "220",
			"tput lines":   "50",
		},
		errors: map[string]error{},
	}
}

// subcommandOf returns the first non-flag, non-socket-argument token after
// the program name in argv. For "tmux -S /x split-window -v" it returns
// "split-window". For "tput cols" it returns "cols". Returns "" when no
// subcommand is recognisable.
func subcommandOf(args []string) string {
	if len(args) < 2 {
		return ""
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "-S" || a == "-L" {
			i++ // also skip the value
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func (m *mockRunner) Run(args ...string) (string, error) {
	m.calls = append(m.calls, args)
	// Try the full-args key first for tput-style "cmd arg" outputs.
	key := strings.Join(args, " ")
	if out, ok := m.outputs[key]; ok {
		return out, m.errors[key]
	}
	// Subcommand-based lookup tolerates injected -S/-L flags between the
	// program name and the operation.
	if sub := subcommandOf(args); sub != "" {
		if out, ok := m.outputs[sub]; ok {
			return out, m.errors[sub]
		}
	}
	return "", nil
}

func (m *mockRunner) LookPath(name string) (string, error) {
	if name == "tmux" {
		return "/usr/bin/tmux", nil
	}
	return "", fmt.Errorf("%s: not found", name)
}

// calledWith returns true if any recorded call contains the given args as
// a contiguous substring of its argv. The substring match (rather than
// prefix) lets tests query for "tmux split-window -v" and still match
// invocations that include an injected `-S <socket>` between `tmux` and
// the subcommand. The runner records the full argv including the
// program name, so callers should start their query with "tmux".
func (m *mockRunner) calledWith(args ...string) bool {
	needle := strings.Join(args, " ")
	for _, call := range m.calls {
		if strings.Contains(strings.Join(call, " "), needle) {
			return true
		}
	}
	return false
}

func TestSetup_InTmux_SplitsCurrentWindow(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	mock.outputs["split-window"] = "%7"
	p, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if p.PaneID != "%7" {
		t.Errorf("PaneID = %q, want %%7", p.PaneID)
	}
	if p.SessionName != "" {
		t.Errorf("SessionName should be empty for split-window mode, got %q", p.SessionName)
	}
	if !mock.calledWith("split-window", "-v") {
		t.Error("expected tmux split-window -v to be called")
	}
}

func TestSetup_InTmux_SplitTargetsCurrentPaneViaTMUX_PANE(t *testing.T) {
	// Without `-t $TMUX_PANE` on the split-window call, tmux uses the
	// server's currently active client, which can land in a different
	// session entirely when the tmux server is shared. Pin the target
	// pane explicitly so the watch pane always appears next to rampart.
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")
	t.Setenv("TMUX_PANE", "%42")

	mock := newMockRunner()
	if _, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand:    "rampart escalations --watch",
		RunnerOverride: mock,
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	var splitCall []string
	for _, call := range mock.calls {
		if subcommandOf(call) == "split-window" {
			splitCall = call
			break
		}
	}
	if splitCall == nil {
		t.Fatalf("split-window was not called; calls = %v", mock.calls)
	}

	foundTarget := false
	for i := 0; i < len(splitCall)-1; i++ {
		if splitCall[i] == "-t" && splitCall[i+1] == "%42" {
			foundTarget = true
			break
		}
	}
	if !foundTarget {
		t.Errorf("expected `-t %%42` in split-window args, got %v", splitCall)
	}
}

func TestSetup_InTmux_BottomPaneIdleLines(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	_, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Default idle lines = 3; check tmux split-window was called with -l 3.
	found := false
	for _, call := range mock.calls {
		if subcommandOf(call) == "split-window" {
			for i, a := range call {
				if a == "-l" && i+1 < len(call) && call[i+1] == "3" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("expected split-window with -l 3, calls: %v", mock.calls)
	}
}

func TestSetup_NotInTmux_CreatesNewSession(t *testing.T) {
	t.Setenv("TMUX", "")

	mock := newMockRunner()
	mock.outputs["split-window"] = "%9"
	pid := os.Getpid()
	expectedSession := fmt.Sprintf("rampart-%d", pid)

	p, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if p.SessionName != expectedSession {
		t.Errorf("SessionName = %q, want %q", p.SessionName, expectedSession)
	}
	if !mock.calledWith("new-session", "-d", "-s", expectedSession) {
		t.Errorf("expected new-session with name %q, calls: %v", expectedSession, mock.calls)
	}
}

func TestSetup_NotInTmux_SelectsMainPane(t *testing.T) {
	t.Setenv("TMUX", "")

	mock := newMockRunner()
	_, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !mock.calledWith("select-pane") {
		t.Error("expected select-pane to be called")
	}
}

func TestSetup_NewSessionFlag_ForcesNewSession(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	_, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		NewSession:  true,
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !mock.calledWith("new-session") {
		t.Error("expected new-session when --new-session flag set, even if in tmux")
	}
}

func TestSetup_NewWindowFlag(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	mock.outputs["new-window"] = "%3"
	mock.outputs["split-window"] = "%4"
	_, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		NewWindow:   true,
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !mock.calledWith("new-window") {
		t.Error("expected new-window to be called with --new-window flag")
	}
}

func TestSetup_TmuxNotInstalled_ReturnsError(t *testing.T) {
	mock := newMockRunner()
	noTmuxRunner := &noLookPathRunner{mockRunner: mock}

	_, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand:    "rampart escalations --watch",
		RunnerOverride: noTmuxRunner,
	})
	if err == nil {
		t.Fatal("expected error when tmux not installed")
	}
	if err != tmux.ErrTmuxNotFound {
		t.Errorf("error = %v, want ErrTmuxNotFound", err)
	}
}

type noLookPathRunner struct{ *mockRunner }

func (n *noLookPathRunner) LookPath(name string) (string, error) {
	return "", fmt.Errorf("%s: executable file not found in $PATH", name)
}

func (n *noLookPathRunner) Run(args ...string) (string, error) {
	return n.mockRunner.Run(args...)
}

func TestPane_Expand_ResizesToActiveLines(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	mock.outputs["split-window"] = "%5"
	p, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		ActiveLines: 6,
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if err := p.Expand(); err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !mock.calledWith("resize-pane", "-t", "%5", "-y", "6") {
		t.Errorf("expected resize-pane -y 6, calls: %v", mock.calls)
	}
}

func TestPane_Shrink_ResizesToIdleLines(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	mock.outputs["split-window"] = "%5"
	p, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		IdleLines:   3,
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if err := p.Shrink(); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if !mock.calledWith("resize-pane", "-t", "%5", "-y", "3") {
		t.Errorf("expected resize-pane -y 3, calls: %v", mock.calls)
	}
}

func TestPane_Close_JoinedSession_KillsPane(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	mock.outputs["split-window"] = "%5"
	p, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !mock.calledWith("kill-pane", "-t", "%5") {
		t.Errorf("expected kill-pane -t %%5, calls: %v", mock.calls)
	}
	// Session should NOT be killed.
	if mock.calledWith("kill-session") {
		t.Error("kill-session should not be called when joining existing session (TR123)")
	}
}

func TestPane_Close_CreatedSession_KillsSession(t *testing.T) {
	t.Setenv("TMUX", "")

	mock := newMockRunner()
	mock.outputs["split-window"] = "%6"
	p, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	sessionName := fmt.Sprintf("rampart-%d", os.Getpid())
	if !mock.calledWith("kill-session", "-t", sessionName) {
		t.Errorf("expected kill-session -t %s, calls: %v", sessionName, mock.calls)
	}
}

func TestPane_PaneCommand_IsPassedToSplitWindow(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")

	mock := newMockRunner()
	_, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand: "rampart escalations --watch",
		RunnerOverride: mock,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	found := false
	for _, call := range mock.calls {
		if subcommandOf(call) == "split-window" {
			for _, arg := range call {
				if arg == "rampart escalations --watch" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("expected pane command in split-window args, calls: %v", mock.calls)
	}
}
