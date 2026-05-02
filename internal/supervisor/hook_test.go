package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

// scriptHook creates a temporary executable shell script and returns its path.
func scriptHook(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := fmt.Sprintf("%s/hook.sh", dir)
	content := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write hook script: %v", err)
	}
	return path
}

func makeHook(t *testing.T, cmd string) *SubprocessHookExecutor {
	t.Helper()
	return &SubprocessHookExecutor{
		Command: cmd,
		Timeout: 5 * time.Second,
		logger:  slog.Default(),
	}
}

func invokeOne(t *testing.T, h *SubprocessHookExecutor, path string, cap Capability) HookResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ev := ViolationEvent{Path: path, Required: cap}
	resp, err := h.Invoke(ctx, []ViolationEvent{ev})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	return resp
}

// --- Tests: happy path actions ---

func TestHookExecutor_Approve(t *testing.T) {
	h := makeHook(t, scriptHook(t, `echo '{"action":"approve"}'`))
	resp := invokeOne(t, h, "/etc/hosts", CapStat)
	if resp.Action != "approve" {
		t.Errorf("got %q, want approve", resp.Action)
	}
}

func TestHookExecutor_Deny(t *testing.T) {
	h := makeHook(t, scriptHook(t, `echo '{"action":"deny"}'`))
	resp := invokeOne(t, h, "/etc/shadow", CapStat)
	if resp.Action != "deny" {
		t.Errorf("got %q, want deny", resp.Action)
	}
}

func TestHookExecutor_Persist(t *testing.T) {
	h := makeHook(t, scriptHook(t, `echo '{"action":"persist","pattern":"/etc/ssh/*"}'`))
	resp := invokeOne(t, h, "/etc/ssh/sshd_config", CapRead)
	if resp.Action != "persist" {
		t.Errorf("action: got %q, want persist", resp.Action)
	}
	if resp.Pattern != "/etc/ssh/*" {
		t.Errorf("pattern: got %q, want /etc/ssh/*", resp.Pattern)
	}
}

func TestHookExecutor_Defer(t *testing.T) {
	h := makeHook(t, scriptHook(t, `echo '{"action":"defer"}'`))
	resp := invokeOne(t, h, "/etc/hosts", CapStat)
	if resp.Action != "defer" {
		t.Errorf("got %q, want defer", resp.Action)
	}
}

// --- Tests: exit code fallback (API3.3) ---

func TestHookExecutor_ExitCodeZero_NoJSON_IsDefer(t *testing.T) {
	h := makeHook(t, scriptHook(t, `exit 0`))
	resp := invokeOne(t, h, "/etc/hosts", CapStat)
	if resp.Action != "defer" {
		t.Errorf("exit 0 + no JSON: got %q, want defer", resp.Action)
	}
}

func TestHookExecutor_ExitCodeNonZero_IsDefer(t *testing.T) {
	h := makeHook(t, scriptHook(t, `exit 1`))
	resp := invokeOne(t, h, "/etc/hosts", CapStat)
	if resp.Action != "defer" {
		t.Errorf("exit 1: got %q, want defer", resp.Action)
	}
}

func TestHookExecutor_InvalidJSON_ExitZero_IsDefer(t *testing.T) {
	h := makeHook(t, scriptHook(t, `echo "not json {{ invalid"`))
	resp := invokeOne(t, h, "/etc/hosts", CapStat)
	if resp.Action != "defer" {
		t.Errorf("invalid JSON: got %q, want defer", resp.Action)
	}
}

func TestHookExecutor_UnknownAction_IsDefer(t *testing.T) {
	h := makeHook(t, scriptHook(t, `echo '{"action":"unknown-action"}'`))
	resp := invokeOne(t, h, "/etc/hosts", CapStat)
	if resp.Action != "defer" {
		t.Errorf("unknown action: got %q, want defer", resp.Action)
	}
}

// --- Tests: timeout and crash ---

func TestHookExecutor_Timeout_IsDefer(t *testing.T) {
	// Use `exec` so the shell replaces itself with sleep — no child processes
	// hold the pipe open after SIGKILL, so cmd.Wait() returns promptly.
	h := &SubprocessHookExecutor{
		Command: scriptHook(t, `exec sleep 99999`),
		Timeout: 100 * time.Millisecond, // very short for testing
		logger:  slog.Default(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ev := ViolationEvent{Path: "/etc/hosts", Required: CapStat}
	start := time.Now()
	resp, err := h.Invoke(ctx, []ViolationEvent{ev})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.Action != "defer" {
		t.Errorf("timeout: got %q, want defer", resp.Action)
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout took too long: %v (expected ~100ms)", elapsed)
	}
}

func TestHookExecutor_Crash_IsDefer(t *testing.T) {
	h := makeHook(t, scriptHook(t, `kill -ABRT $$`)) // crash with SIGABRT
	resp := invokeOne(t, h, "/etc/hosts", CapStat)
	if resp.Action != "defer" {
		t.Errorf("crash: got %q, want defer", resp.Action)
	}
}

// --- Tests: startup validation (FR50.1, TR94) ---

func TestHookExecutor_MissingBinary_SilentDefer(t *testing.T) {
	h := &SubprocessHookExecutor{
		Command:    "/nonexistent/hook-binary",
		Timeout:    5 * time.Second,
		logger:     slog.Default(),
		startupErr: fmt.Errorf("not found"),
	}
	ctx := context.Background()
	ev := ViolationEvent{Path: "/etc/hosts", Required: CapStat}
	resp, err := h.Invoke(ctx, []ViolationEvent{ev})
	if err != nil {
		t.Fatalf("Invoke with missing binary: %v", err)
	}
	if resp.Action != "defer" {
		t.Errorf("missing binary: got %q, want defer", resp.Action)
	}
}

func TestNewSubprocessHookExecutor_MissingBinary_LogsOnce(t *testing.T) {
	// NewSubprocessHookExecutor should log a warning and set startupErr.
	e := NewSubprocessHookExecutor("/nonexistent/hook-for-test-"+t.Name(), 0, nil)
	if e.startupErr == nil {
		t.Error("expected startupErr to be set for missing binary")
	}
}

// --- Tests: context cancellation ---

func TestHookExecutor_ContextCancelled_IsDefer(t *testing.T) {
	h := makeHook(t, scriptHook(t, `exec sleep 30`))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	ev := ViolationEvent{Path: "/etc/hosts", Required: CapStat}
	resp, err := h.Invoke(ctx, []ViolationEvent{ev})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.Action != "defer" {
		t.Errorf("cancelled context: got %q, want defer", resp.Action)
	}
}

// --- Tests: input JSON schema (ENT10) ---

func TestHookExecutor_InputJSON_MatchesSchema(t *testing.T) {
	// Write the stdin JSON to a temp file so we can inspect it.
	dir := t.TempDir()
	capturePath := dir + "/stdin.json"
	script := scriptHook(t, fmt.Sprintf(`cat > %s; echo '{"action":"defer"}'`, capturePath))

	h := &SubprocessHookExecutor{
		Command: script,
		Timeout: 5 * time.Second,
		Agent:   "coding",
		Profile: "myproject/default",
		logger:  slog.Default(),
	}

	ctx := context.Background()
	ev := ViolationEvent{Path: "/etc/ssh/sshd_config", Required: CapRead}
	_, _ = h.Invoke(ctx, []ViolationEvent{ev})

	data, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("reading captured stdin: %v", err)
	}

	var input HookInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatalf("parsing captured HookInput: %v", err)
	}

	if input.Operation != "read" {
		t.Errorf("operation: got %q, want read", input.Operation)
	}
	if input.Resource != "/etc/ssh/sshd_config" {
		t.Errorf("resource: got %q, want /etc/ssh/sshd_config", input.Resource)
	}
	if input.Agent != "coding" {
		t.Errorf("agent: got %q, want coding", input.Agent)
	}
	if input.Profile != "myproject/default" {
		t.Errorf("profile: got %q, want myproject/default", input.Profile)
	}
	if input.ID == 0 {
		t.Error("id should be non-zero")
	}
	if input.Timestamp.IsZero() {
		t.Error("timestamp should be set")
	}
	if !input.Presence.HookConfigured {
		t.Error("presence.hook_configured should be true")
	}
}

func TestHookExecutor_PresenceInjection(t *testing.T) {
	dir := t.TempDir()
	capturePath := dir + "/stdin.json"
	script := scriptHook(t, fmt.Sprintf(`cat > %s; echo '{"action":"defer"}'`, capturePath))

	ps := PresenceState{
		TmuxPane:    true,
		PaneFocused: false,
		HasTTY:      true,
		InTmux:      true,
		SSHSession:  true,
		Headless:    false,
	}

	h := &SubprocessHookExecutor{
		Command:  script,
		Timeout:  5 * time.Second,
		Presence: &staticPresence{ps},
		logger:   slog.Default(),
	}

	ctx := context.Background()
	ev := ViolationEvent{Path: "/etc/hosts", Required: CapStat}
	_, _ = h.Invoke(ctx, []ViolationEvent{ev})

	data, _ := os.ReadFile(capturePath)
	var input HookInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatalf("parsing HookInput: %v", err)
	}

	checks := map[string]bool{
		"tmux_pane":       input.Presence.TmuxPane,
		"has_tty":         input.Presence.HasTTY,
		"in_tmux":         input.Presence.InTmux,
		"ssh_session":     input.Presence.SSHSession,
		"hook_configured": input.Presence.HookConfigured,
	}
	for field, got := range checks {
		if !got {
			t.Errorf("presence.%s should be true", field)
		}
	}
	if input.Presence.PaneFocused {
		t.Error("presence.pane_focused should be false")
	}
	if input.Presence.Headless {
		t.Error("presence.headless should be false")
	}
}

// --- Tests: ID monotonically increments ---

func TestHookExecutor_IDMonotonicallyIncreases(t *testing.T) {
	// Reuse the SAME executor; IDs must increase across consecutive invocations.
	capPath := t.TempDir() + "/stdin.json"
	cs := scriptHook(t, fmt.Sprintf(`cat > %s; echo '{"action":"defer"}'`, capPath))
	ce := makeHook(t, cs)

	ctx := context.Background()
	ev := ViolationEvent{Path: "/etc/hosts", Required: CapStat}

	var lastID int64
	for i := 0; i < 3; i++ {
		ce.Invoke(ctx, []ViolationEvent{ev})
		data, _ := os.ReadFile(capPath)
		var inp HookInput
		json.Unmarshal(data, &inp)
		if i > 0 && inp.ID <= lastID {
			t.Errorf("iteration %d: ID not increasing: %d <= %d", i, inp.ID, lastID)
		}
		lastID = inp.ID
	}
}

// --- Test helpers ---

// staticPresence is a PresenceProvider that returns a fixed PresenceState.
type staticPresence struct {
	state PresenceState
}

func (s *staticPresence) PresenceState() PresenceState { return s.state }
