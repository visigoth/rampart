//go:build darwin

package supervisor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"syscall"
	"testing"
	"time"
)

// allowEngine returns Allow for every event.
type allowEngine struct{}

func (allowEngine) Authorize(_ context.Context, _ ViolationEvent) Decision { return Allow }

// denyEngine returns Deny for every event.
type denyEngine struct{}

func (denyEngine) Authorize(_ context.Context, _ ViolationEvent) Decision { return Deny }

// recordingKiller captures every (pid, sig) signal call.
type recordingKiller struct {
	mu    sync.Mutex
	calls []killCall
	err   error
}

type killCall struct {
	pid int
	sig syscall.Signal
}

func (r *recordingKiller) kill(pid int, sig syscall.Signal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, killCall{pid: pid, sig: sig})
	return r.err
}

func (r *recordingKiller) snapshot() []killCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]killCall, len(r.calls))
	copy(out, r.calls)
	return out
}

func killerLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// runKiller starts the subsystem and returns a stop func that cancels and
// awaits clean exit (with a hard timeout so test failures surface clearly).
func runKiller(t *testing.T, k *ViolationKiller) (cancel func(), wait func() error) {
	t.Helper()
	ctx, cancelFn := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- k.Run(ctx) }()
	wait = func() error {
		select {
		case err := <-errCh:
			return err
		case <-time.After(2 * time.Second):
			return errors.New("violation-killer: Run did not return within 2s")
		}
	}
	return cancelFn, wait
}

// TestViolationKiller_Enforcing_DenyTriggersSIGKILL is the load-bearing
// path: enforcing mode + Deny decision must call killer(pid, SIGKILL).
func TestViolationKiller_Enforcing_DenyTriggersSIGKILL(t *testing.T) {
	events := make(chan ViolationEvent, 1)
	rk := &recordingKiller{}

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       4242,
		Events:    events,
		Engine:    denyEngine{},
		Enforcing: true,
		Killer:    rk.kill,
		Logger:    killerLogger(),
	})

	cancel, wait := runKiller(t, k)
	defer cancel()

	events <- ViolationEvent{PID: 4242, Syscall: "openat", Path: "/etc/shadow", Required: CapRead}

	// Allow scheduling for the kill to land.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rk.snapshot()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	calls := rk.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 kill call, got %d (%+v)", len(calls), calls)
	}
	if calls[0].pid != 4242 {
		t.Errorf("kill pid = %d, want 4242", calls[0].pid)
	}
	if calls[0].sig != syscall.SIGKILL {
		t.Errorf("kill sig = %v, want SIGKILL", calls[0].sig)
	}

	cancel()
	if err := wait(); err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}

// TestViolationKiller_TestMode_DenyDoesNotKill verifies that in non-enforcing
// (test/observer) mode a Deny decision is logged but no signal is sent —
// preserving the EPERM-only behavior used by the test REPL.
func TestViolationKiller_TestMode_DenyDoesNotKill(t *testing.T) {
	events := make(chan ViolationEvent, 1)
	rk := &recordingKiller{}

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       4242,
		Events:    events,
		Engine:    denyEngine{},
		Enforcing: false, // test mode
		Killer:    rk.kill,
		Logger:    killerLogger(),
	})

	cancel, wait := runKiller(t, k)
	defer cancel()

	events <- ViolationEvent{PID: 4242, Path: "/etc/shadow", Required: CapRead}

	// Give the handler a chance to run.
	time.Sleep(50 * time.Millisecond)

	if calls := rk.snapshot(); len(calls) != 0 {
		t.Errorf("test mode must not signal, got %+v", calls)
	}

	cancel()
	if err := wait(); err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}

// TestViolationKiller_Enforcing_AllowDoesNotKill verifies the engine's
// Allow decision short-circuits the kill in enforcing mode (cached approval
// or hook-approved escalation).
func TestViolationKiller_Enforcing_AllowDoesNotKill(t *testing.T) {
	events := make(chan ViolationEvent, 1)
	rk := &recordingKiller{}

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       7,
		Events:    events,
		Engine:    allowEngine{},
		Enforcing: true,
		Killer:    rk.kill,
		Logger:    killerLogger(),
	})

	cancel, wait := runKiller(t, k)
	defer cancel()

	events <- ViolationEvent{PID: 7, Path: "/usr/lib/libfoo.dylib", Required: CapRead}
	time.Sleep(50 * time.Millisecond)

	if calls := rk.snapshot(); len(calls) != 0 {
		t.Errorf("Allow must not signal, got %+v", calls)
	}

	cancel()
	if err := wait(); err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}

// TestViolationKiller_PIDMismatch_Ignored ensures stray events for a
// different PID never trigger a kill of the supervised child. (Defensive:
// the live-tail predicate already filters on PID, but a fan-out source
// could deliver mixed events.)
func TestViolationKiller_PIDMismatch_Ignored(t *testing.T) {
	events := make(chan ViolationEvent, 1)
	rk := &recordingKiller{}

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       1000,
		Events:    events,
		Engine:    denyEngine{},
		Enforcing: true,
		Killer:    rk.kill,
		Logger:    killerLogger(),
	})

	cancel, wait := runKiller(t, k)
	defer cancel()

	events <- ViolationEvent{PID: 9999, Path: "/etc/shadow", Required: CapRead}
	time.Sleep(50 * time.Millisecond)

	if calls := rk.snapshot(); len(calls) != 0 {
		t.Errorf("mismatched PID must not signal supervised child, got %+v", calls)
	}

	cancel()
	if err := wait(); err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}

// TestViolationKiller_ContextCancel_StopsCleanly ensures the subsystem
// honors ctx.Done — the supervisor cancels egCtx during shutdown and the
// killer must not block the errgroup.
func TestViolationKiller_ContextCancel_StopsCleanly(t *testing.T) {
	events := make(chan ViolationEvent)

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       1,
		Events:    events,
		Engine:    denyEngine{},
		Enforcing: true,
		Killer:    func(int, syscall.Signal) error { return nil },
		Logger:    killerLogger(),
	})

	cancel, wait := runKiller(t, k)
	cancel()
	if err := wait(); err != nil {
		t.Errorf("Run returned error after cancel: %v", err)
	}
}

// TestViolationKiller_ChannelClose_StopsCleanly verifies natural source
// termination ends the subsystem without error.
func TestViolationKiller_ChannelClose_StopsCleanly(t *testing.T) {
	events := make(chan ViolationEvent)

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       1,
		Events:    events,
		Engine:    denyEngine{},
		Enforcing: true,
		Killer:    func(int, syscall.Signal) error { return nil },
		Logger:    killerLogger(),
	})

	_, wait := runKiller(t, k)
	close(events)
	if err := wait(); err != nil {
		t.Errorf("Run returned error after channel close: %v", err)
	}
}

// TestViolationKiller_NilEvents_ReturnsError catches the misconfiguration of
// a caller that forgot to wire the event source.
func TestViolationKiller_NilEvents_ReturnsError(t *testing.T) {
	k := NewViolationKiller(ViolationKillerConfig{
		PID:       1,
		Events:    nil,
		Engine:    denyEngine{},
		Enforcing: true,
		Logger:    killerLogger(),
	})
	if err := k.Run(context.Background()); err == nil {
		t.Error("expected error for nil Events channel")
	}
}

// TestViolationKiller_NilEngine_DefaultsToDeny ensures a missing engine
// (e.g. early bring-up before auth-engine wiring) still kills in enforcing
// mode rather than silently dropping the violation.
func TestViolationKiller_NilEngine_DefaultsToDeny(t *testing.T) {
	events := make(chan ViolationEvent, 1)
	rk := &recordingKiller{}

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       50,
		Events:    events,
		Engine:    nil,
		Enforcing: true,
		Killer:    rk.kill,
		Logger:    killerLogger(),
	})

	cancel, wait := runKiller(t, k)
	defer cancel()

	events <- ViolationEvent{PID: 50, Path: "/etc/shadow", Required: CapRead}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rk.snapshot()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if calls := rk.snapshot(); len(calls) != 1 {
		t.Errorf("expected default-deny kill with nil engine, got %+v", calls)
	}

	cancel()
	if err := wait(); err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}
