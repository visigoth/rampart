//go:build darwin

package supervisor

import "log/slog"

// LogApplier is the macOS DecisionApplier. macOS sandbox enforcement happens
// in-kernel via Seatbelt: by the time a violation is reported the child has
// already received SIGKILL, so there is no kernel-side ack to send back. The
// Applier only logs the resolved decision; the engine's session cache and
// persisted-approvals store handle the "remember next time" half on its own.
type LogApplier struct {
	Logger *slog.Logger
}

// Apply implements DecisionApplier.
func (a LogApplier) Apply(ev ViolationEvent, approved bool) error {
	log := a.Logger
	if log == nil {
		log = slog.Default()
	}
	log.Info("auth-engine: decision applied",
		"approved", approved,
		"path", ev.Path,
		"capability", ev.Required.String(),
		"syscall", ev.Syscall,
		"pid", ev.PID,
	)
	return nil
}

var _ DecisionApplier = LogApplier{}
