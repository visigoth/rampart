//go:build darwin

package main

import (
	"github.com/visigoth/rampart/internal/session"
	"github.com/visigoth/rampart/internal/supervisor"
)

// newAuthSubsystems wires the authorization engine, the macOS post-mortem
// violation monitor, and (in enforcing mode) the live ViolationKiller — for
// one supervisor session. The engine is returned as a fatal subsystem; the
// monitor and killer are returned via a PostStartHook because they need the
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
//
// FR23: when enforcing is true, a third post-start subsystem is launched —
// a ViolationKiller fed by realLogStreamer — that consumes live sandbox.reporting
// events and signals SIGKILL to the child on Deny decisions. In test/permissive
// mode the killer is omitted entirely so violations remain pure-EPERM.
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
		subs := []supervisor.Subsystem{
			supervisor.NewMonitor(supervisor.MonitorConfig{
				PID:    pid,
				Engine: engine,
				WaitFunc: func(_ int) (int, int, error) {
					ce := <-childExitCh
					return ce.ExitStatus, ce.Signal, ce.Err
				},
			}),
		}

		if enforcing {
			subs = append(subs, supervisor.NewViolationKiller(supervisor.ViolationKillerConfig{
				PID:       pid,
				Streamer:  supervisor.NewLogStreamer(nil),
				Engine:    engine,
				Enforcing: true,
			}))
		}

		return subs, nil
	}

	return engine, postStart, childExitCh
}
