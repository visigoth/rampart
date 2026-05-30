package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/tmux"
)

// fakeTmuxRunner records tmux invocations and returns canned responses.
type fakeTmuxRunner struct {
	mu       sync.Mutex
	calls    [][]string
	hasTmux  bool
	splitOut string
	splitErr error
}

func newFakeTmuxRunner() *fakeTmuxRunner {
	return &fakeTmuxRunner{
		hasTmux:  true,
		splitOut: "%9",
	}
}

func (f *fakeTmuxRunner) Run(args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	if subcommandOf(args) == "split-window" {
		return f.splitOut, f.splitErr
	}
	if len(args) >= 2 && args[0] == "tput" {
		return "100", nil
	}
	return "", nil
}

func (f *fakeTmuxRunner) LookPath(name string) (string, error) {
	if name == "tmux" && f.hasTmux {
		return "/usr/bin/tmux", nil
	}
	return "", fmt.Errorf("%s: not found", name)
}

// called returns true when any recorded invocation matches. The query is
// matched against the tmux SUBCOMMAND (split-window, kill-pane, …) and
// any extra args, ignoring `-S <socket>` / `-L <name>` flags that
// tmux.go injects between the program name and the subcommand.
func (f *fakeTmuxRunner) called(query ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(query) == 0 {
		return false
	}
	// Drop a leading "tmux" / "tput" from the query — we match starting
	// at the subcommand.
	if query[0] == "tmux" || query[0] == "tput" {
		query = query[1:]
		if len(query) == 0 {
			return false
		}
	}
	wantSub := query[0]
	wantTail := strings.Join(query[1:], " ")
	for _, c := range f.calls {
		if subcommandOf(c) != wantSub {
			continue
		}
		if wantTail == "" {
			return true
		}
		joined := strings.Join(c, " ")
		if strings.Contains(joined, wantTail) {
			return true
		}
	}
	return false
}

// subcommandOf returns the first non-flag, non-socket-argument token after
// the program name in argv. Mirrors the same helper in tmux_test.go;
// duplicated here to keep package boundaries clean.
func subcommandOf(args []string) string {
	if len(args) < 2 {
		return ""
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "-S" || a == "-L" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// TestTmuxPaneSubsystem_NameStable pins the diagnostic name.
func TestTmuxPaneSubsystem_NameStable(t *testing.T) {
	ts := &tmuxPaneSubsystem{}
	if got := ts.Name(); got != "tmux-pane" {
		t.Errorf("Name() = %q, want %q", got, "tmux-pane")
	}
}

// TestTmuxPaneSubsystem_HoldsOpenUntilCancelThenCloses confirms the
// subsystem blocks until ctx is cancelled and then closes the pane it was
// given. The pane is now created by run.go BEFORE supervisor.Run starts
// the child (so the agent's pty geometry is settled at startup), and the
// subsystem only owns the teardown.
func TestTmuxPaneSubsystem_HoldsOpenUntilCancelThenCloses(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux/default,1234,0")

	r := newFakeTmuxRunner()
	pane, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand:    "rampart escalations --watch",
		RunnerOverride: r,
	})
	if err != nil {
		t.Fatalf("tmux.Setup: %v", err)
	}
	if !r.called("tmux", "split-window") {
		t.Fatal("setup did not invoke split-window")
	}

	ts := &tmuxPaneSubsystem{pane: pane}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ts.Run(ctx) }()

	// Run must not return before cancel.
	select {
	case err := <-done:
		t.Fatalf("Run returned before ctx cancel: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}

	if !r.called("tmux", "kill-pane") {
		t.Error("expected kill-pane on shutdown when joined existing session")
	}
}

// TestTmuxPaneSubsystem_SplitWindowKeepsAgentFocused verifies the pane
// creation uses -d so tmux doesn't auto-focus the new (watch) pane —
// otherwise the user's keystrokes would route to the watch pane instead
// of the agent.
func TestTmuxPaneSubsystem_SplitWindowKeepsAgentFocused(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux/default,1234,0")

	r := newFakeTmuxRunner()
	_, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand:    "rampart escalations --watch",
		RunnerOverride: r,
	})
	if err != nil {
		t.Fatalf("tmux.Setup: %v", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	foundDFlag := false
	for _, c := range r.calls {
		if subcommandOf(c) != "split-window" {
			continue
		}
		joined := strings.Join(c, " ")
		if strings.Contains(joined, " -d") {
			foundDFlag = true
			break
		}
	}
	if !foundDFlag {
		t.Errorf("split-window must include -d to keep agent pane focused; calls: %v", r.calls)
	}
}

// TestTmuxPaneSubsystem_NilPaneIsHarmless ensures the subsystem degrades
// cleanly when run.go couldn't create the pane (tmux.Setup failed). The
// subsystem just blocks on ctx until shutdown.
func TestTmuxPaneSubsystem_NilPaneIsHarmless(t *testing.T) {
	ts := &tmuxPaneSubsystem{pane: nil}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ts.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run with nil pane: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel with nil pane")
	}
}
