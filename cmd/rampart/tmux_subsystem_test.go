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
	if len(args) >= 2 && args[0] == "tmux" && args[1] == "split-window" {
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

func (f *fakeTmuxRunner) called(prefix ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := strings.Join(prefix, " ")
	for _, c := range f.calls {
		if strings.HasPrefix(strings.Join(c, " "), want) {
			return true
		}
	}
	return false
}

// TestTmuxPaneSubsystem_NameStable pins the diagnostic name.
func TestTmuxPaneSubsystem_NameStable(t *testing.T) {
	ts := &tmuxPaneSubsystem{}
	if got := ts.Name(); got != "tmux-pane" {
		t.Errorf("Name() = %q, want %q", got, "tmux-pane")
	}
}

// TestTmuxPaneSubsystem_RunSetsUpAndClosesOnCancel verifies the subsystem
// creates the pane, blocks until ctx is cancelled, then tears it down.
func TestTmuxPaneSubsystem_RunSetsUpAndClosesOnCancel(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux/default,1234,0")

	r := newFakeTmuxRunner()
	ts := &tmuxPaneSubsystem{
		cfg: tmux.PaneConfig{
			PaneCommand:    "rampart escalations --watch",
			RunnerOverride: r,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ts.Run(ctx) }()

	// Wait for setup to register the split-window call.
	deadline := time.Now().Add(2 * time.Second)
	for !r.called("tmux", "split-window") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !r.called("tmux", "split-window") {
		t.Fatal("subsystem never invoked tmux split-window")
	}

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

// TestTmuxPaneSubsystem_RunReturnsErrWhenTmuxMissing surfaces a recoverable
// error so the supervisor logs and degrades to interactive-direct (TR117).
func TestTmuxPaneSubsystem_RunReturnsErrWhenTmuxMissing(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux/default,1234,0")

	r := newFakeTmuxRunner()
	r.hasTmux = false
	ts := &tmuxPaneSubsystem{
		cfg: tmux.PaneConfig{
			PaneCommand:    "rampart escalations --watch",
			RunnerOverride: r,
		},
	}

	err := ts.Run(context.Background())
	if err == nil {
		t.Fatal("expected error when tmux missing")
	}
	if err != tmux.ErrTmuxNotFound {
		t.Errorf("err = %v, want ErrTmuxNotFound", err)
	}
}
