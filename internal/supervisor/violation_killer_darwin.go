//go:build darwin

package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"syscall"
)

// ViolationKiller is the macOS supervisor-level enforcement of FR23: when a
// sandbox violation is reported live (via the unified-log stream) it consults
// the auth engine, and if the decision is Deny in enforcing mode it sends
// SIGKILL to the child process.
//
// In test mode, ViolationKiller is a pass-through observer: events are still
// routed to the engine (so escalations and approvals are recorded), but the
// child is never killed — the kernel's own EPERM remains the user-visible
// effect, matching the existing test-REPL behavior.
//
// The actual log-stream source is injected as a chan ViolationEvent so this
// subsystem is independently testable. The live `log stream` subprocess is
// produced by a separate component.
type ViolationKiller struct {
	cfg ViolationKillerConfig
}

// ViolationKillerConfig holds the inputs for the kill-on-deny subsystem.
type ViolationKillerConfig struct {
	// PID is the sandboxed child to potentially kill. Required.
	PID int

	// Events delivers live violation events for the child. The subsystem
	// drains this channel until ctx is cancelled or the channel closes.
	// Required.
	Events <-chan ViolationEvent

	// Engine is consulted for each event. Required when Enforcing is true;
	// optional otherwise (test mode just observes).
	Engine AuthEngine

	// Enforcing toggles SIGKILL action. When true, a Deny decision triggers
	// Killer(PID, SIGKILL). When false, the engine is still consulted (for
	// caching / escalation persistence) but no signal is sent.
	Enforcing bool

	// Killer is the function used to terminate the child. Defaults to
	// syscall.Kill. Injected for tests so they can avoid sending real
	// signals to PIDs they don't own.
	Killer func(pid int, sig syscall.Signal) error

	// Logger is the diagnostic sink. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

func (c *ViolationKillerConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *ViolationKillerConfig) killer() func(int, syscall.Signal) error {
	if c.Killer != nil {
		return c.Killer
	}
	return syscall.Kill
}

// NewViolationKiller constructs a ViolationKiller from cfg.
func NewViolationKiller(cfg ViolationKillerConfig) *ViolationKiller {
	return &ViolationKiller{cfg: cfg}
}

// Name implements Subsystem.
func (v *ViolationKiller) Name() string { return "macos-violation-killer" }

// Run implements Subsystem. Blocks until ctx is cancelled, the Events channel
// closes, or — in enforcing mode — a Deny decision triggers SIGKILL (after
// which the subsystem returns nil; the supervisor's own cmd.Wait sees the
// resulting child exit and ends the session).
func (v *ViolationKiller) Run(ctx context.Context) error {
	log := v.cfg.logger()

	if v.cfg.Events == nil {
		return fmt.Errorf("violation-killer: Events channel required")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-v.cfg.Events:
			if !ok {
				return nil
			}
			v.handle(ctx, ev, log)
			// Continue draining: a single Deny+Enforcing kill ends this
			// session because cmd.Wait returns; we don't need to bail
			// early — the supervisor loop will cancel ctx for us.
		}
	}
}

// handle dispatches a single violation event.
func (v *ViolationKiller) handle(ctx context.Context, ev ViolationEvent, log *slog.Logger) {
	if uint32(v.cfg.PID) != 0 && ev.PID != 0 && uint32(v.cfg.PID) != ev.PID {
		return // event for a different process
	}

	var decision Decision = Deny // default-deny when engine absent
	if v.cfg.Engine != nil {
		decision = v.cfg.Engine.Authorize(ctx, ev)
	}

	if decision == Allow {
		log.Info("violation-killer: allowed (cached or hook approval)",
			"pid", v.cfg.PID,
			"path", ev.Path,
			"capability", ev.Required.String())
		return
	}

	if !v.cfg.Enforcing {
		log.Info("violation-killer: deny (test mode — no kill)",
			"pid", v.cfg.PID,
			"path", ev.Path,
			"capability", ev.Required.String())
		return
	}

	log.Warn("violation-killer: deny in enforcing mode — sending SIGKILL",
		"pid", v.cfg.PID,
		"path", ev.Path,
		"capability", ev.Required.String(),
		"summary", ViolationSummary(ev))

	if err := v.cfg.killer()(v.cfg.PID, syscall.SIGKILL); err != nil {
		log.Warn("violation-killer: SIGKILL failed",
			"pid", v.cfg.PID, "err", err)
	}
}

// Ensure ViolationKiller satisfies Subsystem at compile time.
var _ Subsystem = (*ViolationKiller)(nil)
