//go:build !darwin

package main

import (
	"github.com/visigoth/rampart/internal/session"
	"github.com/visigoth/rampart/internal/supervisor"
)

// newAuthSubsystems is a stub for non-darwin builds. The Linux equivalent
// (NotifRespond applier + seccomp supervisor) is wired by FT6 in a separate
// task.
func newAuthSubsystems(srv *session.Server, bridge *sessionBridge, enforcing bool) (supervisor.Subsystem, func(pid int) ([]supervisor.Subsystem, error), chan supervisor.ChildExit) {
	_ = srv
	_ = bridge
	_ = enforcing
	return nil, nil, nil
}
