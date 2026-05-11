package main

import (
	"context"

	"github.com/visigoth/rampart/internal/tmux"
)

// tmuxPaneSubsystem manages the lifecycle of an already-created rampart
// escalation pane. The pane is created synchronously by runLaunch BEFORE
// Cmd.Start() so the agent's pty geometry is already settled when claude
// starts — running the split as a goroutine after Cmd.Start() raced the
// agent's initial TUI render and caused mid-startup SIGWINCH events.
//
// Registered as a RecoverableSubsystem: failures here only mean we
// couldn't close the pane cleanly, which doesn't affect agent behaviour.
type tmuxPaneSubsystem struct {
	pane *tmux.Pane
}

func (t *tmuxPaneSubsystem) Name() string { return "tmux-pane" }

func (t *tmuxPaneSubsystem) Run(ctx context.Context) error {
	if t.pane == nil {
		<-ctx.Done()
		return nil
	}
	<-ctx.Done()
	return t.pane.Close()
}
