//go:build darwin

package main

import (
	"github.com/visigoth/rampart/internal/session"
	"github.com/visigoth/rampart/internal/supervisor"
)

// newAuthSubsystems wires the authorization engine and the macOS violation
// monitor for one supervisor session. The engine is returned as a fatal
// subsystem; the monitor is returned via a PostStartHook because it needs the
// child's PID, which is only known after Cmd.Start().
//
// The bridge is attached to srv so command messages received on the session
// socket are routed back to the engine's per-escalation response channel.
func newAuthSubsystems(srv *session.Server, bridge *sessionBridge, enforcing bool) (supervisor.Subsystem, func(pid int) ([]supervisor.Subsystem, error)) {
	bridge.attachServer(srv)

	engine := supervisor.NewEngine(supervisor.EngineConfig{
		Enforcing: enforcing,
		Applier:   supervisor.LogApplier{},
		Publisher: bridge,
		// Hook left nil: hook subprocess wiring is a separate task.
	})

	postStart := func(pid int) ([]supervisor.Subsystem, error) {
		mon := supervisor.NewMonitor(supervisor.MonitorConfig{
			PID:    pid,
			Engine: engine,
		})
		return []supervisor.Subsystem{mon}, nil
	}

	return engine, postStart
}
