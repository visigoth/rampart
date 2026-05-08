//go:build darwin

package supervisor

import (
	"context"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestViolationKill_E2E_StreamerToKill validates the realLogStreamer →
// ViolationKiller pipeline end to end using the fake-log subprocess: an
// ndjson sandbox.reporting line for the supervised PID is parsed, routed
// to the engine, and a Deny+Enforcing decision triggers SIGKILL via the
// injected killer.
func TestViolationKill_E2E_StreamerToKill(t *testing.T) {
	pid := 8181
	script := strings.Join([]string{
		jlineSandbox(pid, "Sandbox: 8181 deny(1) file-read-data /etc/ssh/sshd_config"),
	}, "\n")

	t.Setenv(fakeLogModeEnv, "hang") // keep stream open until ctx cancel
	t.Setenv(fakeLogScriptEnv, script)

	streamer := &realLogStreamer{
		Cmd:    buildFakeLog(t),
		Logger: killerLogger(),
	}

	var killed atomic.Bool
	var killSig atomic.Int32
	killer := func(_ int, sig syscall.Signal) error {
		killSig.Store(int32(sig))
		killed.Store(true)
		return nil
	}

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       pid,
		Streamer:  streamer,
		Engine:    denyEngine{},
		Enforcing: true,
		Killer:    killer,
		Logger:    killerLogger(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	// Wait for the kill to land via the live tail.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !killed.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if !killed.Load() {
		t.Fatal("expected SIGKILL within 2s — streamer→killer path broken")
	}
	if syscall.Signal(killSig.Load()) != syscall.SIGKILL {
		t.Errorf("kill sig = %v, want SIGKILL", syscall.Signal(killSig.Load()))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v after cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// TestViolationKill_E2E_TestModeNoKill confirms the same input under
// non-enforcing mode produces no SIGKILL — the test REPL contract.
func TestViolationKill_E2E_TestModeNoKill(t *testing.T) {
	pid := 8282
	script := strings.Join([]string{
		jlineSandbox(pid, "Sandbox: 8282 deny(1) file-write-data /etc/passwd"),
	}, "\n")

	t.Setenv(fakeLogModeEnv, "hang")
	t.Setenv(fakeLogScriptEnv, script)

	streamer := &realLogStreamer{Cmd: buildFakeLog(t), Logger: killerLogger()}

	var killed atomic.Bool
	killer := func(int, syscall.Signal) error { killed.Store(true); return nil }

	k := NewViolationKiller(ViolationKillerConfig{
		PID:       pid,
		Streamer:  streamer,
		Engine:    denyEngine{},
		Enforcing: false, // test mode
		Killer:    killer,
		Logger:    killerLogger(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	// Give the event time to flow through; expect no kill.
	time.Sleep(800 * time.Millisecond)
	if killed.Load() {
		t.Error("test mode must not SIGKILL on Deny")
	}

	cancel()
	<-done
}
