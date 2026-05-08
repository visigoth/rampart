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
//
// childExitCh is the channel the caller will register with
// supervisor.Config.ChildExitInfo: the supervisor pushes the child's exit
// info there once cmd.Wait() returns, and the Monitor's WaitFunc reads from
// it. This avoids the Monitor calling Wait4(pid) itself, which would race
// with the supervisor's cmd.Wait and produce ECHILD on the loser.
func newAuthSubsystems(srv *session.Server, bridge *sessionBridge, enforcing bool) (supervisor.Subsystem, func(pid int) ([]supervisor.Subsystem, error), chan supervisor.ChildExit) {
	bridge.attachServer(srv)

	engine := supervisor.NewEngine(supervisor.EngineConfig{
		Enforcing: enforcing,
		Applier:   supervisor.LogApplier{},
		Publisher: bridge,
		// Hook left nil: hook subprocess wiring is a separate task.
	})

	childExitCh := make(chan supervisor.ChildExit, 1)
	postStart := func(pid int) ([]supervisor.Subsystem, error) {
		mon := supervisor.NewMonitor(supervisor.MonitorConfig{
			PID:    pid,
			Engine: engine,
			WaitFunc: func(_ int) (int, int, error) {
				ce := <-childExitCh
				return ce.ExitStatus, ce.Signal, ce.Err
			},
		})
		return []supervisor.Subsystem{mon}, nil
	}

	return engine, postStart, childExitCh
}
