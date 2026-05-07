package main

import (
	"context"

	"github.com/visigoth/rampart/internal/tmux"
)

// tmuxPaneSubsystem manages the lifecycle of the rampart escalation pane
// inside a tmux session. Setup splits the current window (or creates a new
// session) to run `rampart escalations --watch`; on shutdown the pane is
// closed and the session torn down if rampart created it.
//
// Registered as a RecoverableSubsystem: tmux is a UI affordance, so failures
// (tmux missing per TR117, split-window errors) log and degrade to
// interactive-direct rather than ending the session.
type tmuxPaneSubsystem struct {
	cfg  tmux.PaneConfig
	pane *tmux.Pane
}

func (t *tmuxPaneSubsystem) Name() string { return "tmux-pane" }

func (t *tmuxPaneSubsystem) Run(ctx context.Context) error {
	pane, err := tmux.Setup(t.cfg)
	if err != nil {
		return err
	}
	t.pane = pane

	<-ctx.Done()
	return pane.Close()
}
