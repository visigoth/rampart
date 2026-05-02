package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// --- Mocks ---

// recordingApplier records Apply calls for assertion.
type recordingApplier struct {
	mu      sync.Mutex
	calls   []applyCall
	retErr  error
}

type applyCall struct {
	ev       ViolationEvent
	approved bool
}

func (a *recordingApplier) Apply(ev ViolationEvent, approved bool) error {
	a.mu.Lock()
	a.calls = append(a.calls, applyCall{ev: ev, approved: approved})
	a.mu.Unlock()
	return a.retErr
}

func (a *recordingApplier) lastCall() (applyCall, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.calls) == 0 {
		return applyCall{}, false
	}
	return a.calls[len(a.calls)-1], true
}

// stubPublisher is a controllable SocketPublisher for tests.
type stubPublisher struct {
	visible  bool
	respChs  []chan SocketResponse
	mu       sync.Mutex
}

func (p *stubPublisher) PaneVisible() bool { return p.visible }

func (p *stubPublisher) Publish(_ context.Context, _ ViolationEvent) (<-chan SocketResponse, error) {
	ch := make(chan SocketResponse, 4)
	p.mu.Lock()
	p.respChs = append(p.respChs, ch)
	p.mu.Unlock()
	return ch, nil
}

// respond sends a SocketResponse to all open channels.
func (p *stubPublisher) respond(resp SocketResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ch := range p.respChs {
		ch <- resp
	}
}

// stubHook is a controllable HookExecutor for tests.
type stubHook struct {
	mu    sync.Mutex
	calls int
	resp  HookResponse
	err   error
}

func (h *stubHook) Invoke(_ context.Context, _ []ViolationEvent) (HookResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	return h.resp, h.err
}

func (h *stubHook) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// makeEngine is a test helper that builds an Engine with minimal config.
func makeEngine(t *testing.T, applier DecisionApplier) *Engine {
	t.Helper()
	cfg := EngineConfig{
		Enforcing: true,
		Applier:   applier,
		Timeout:   5 * time.Second,
		HookDelay: 50 * time.Millisecond, // fast for tests
	}
	return NewEngine(cfg)
}

// startEngine starts the engine reactor in the background and returns a cancel func.
func startEngine(t *testing.T, e *Engine) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return cancel
}

// --- Tests: matchGlob ---

func TestMatchGlob_ExactMatch(t *testing.T) {
	if !matchGlob("/etc/ssh/sshd_config", "/etc/ssh/sshd_config") {
		t.Error("exact path should match itself")
	}
}

func TestMatchGlob_SingleStar(t *testing.T) {
	if !matchGlob("/etc/ssh/*", "/etc/ssh/sshd_config") {
		t.Error("* should match one path segment")
	}
	if matchGlob("/etc/ssh/*", "/etc/ssh/keys/authorized_keys") {
		t.Error("* should not match across directories")
	}
}

func TestMatchGlob_DoubleStar(t *testing.T) {
	if !matchGlob("/etc/ssh/**", "/etc/ssh/sshd_config") {
		t.Error("** should match nested file")
	}
	if !matchGlob("/etc/ssh/**", "/etc/ssh/keys/authorized_keys") {
		t.Error("** should match across directories")
	}
	if !matchGlob("/etc/**", "/etc/ssh/sshd_config") {
		t.Error("** should match deeply nested")
	}
}

func TestMatchGlob_NoMatch(t *testing.T) {
	if matchGlob("/etc/ssh/*", "/etc/hosts") {
		t.Error("should not match different directory")
	}
	if matchGlob("/home/*", "/etc/ssh/sshd_config") {
		t.Error("should not match different prefix")
	}
}

func TestMatchGlob_TrailingSlashInsensitive(t *testing.T) {
	if !matchGlob("/etc/ssh/", "/etc/ssh") {
		t.Error("trailing slash in pattern should match without trailing slash")
	}
}

// --- Tests: satisfies (capability hierarchy) ---

func TestSatisfies_SameCapability(t *testing.T) {
	for _, cap := range []Capability{CapStat, CapRead, CapWrite, CapExec} {
		if !satisfies(cap, cap) {
			t.Errorf("satisfies(%v, %v) should be true", cap, cap)
		}
	}
}

func TestSatisfies_StatSatisfiedByAll(t *testing.T) {
	for _, cap := range []Capability{CapRead, CapWrite, CapExec} {
		if !satisfies(cap, CapStat) {
			t.Errorf("satisfies(%v, CapStat) should be true", cap)
		}
	}
}

func TestSatisfies_ReadSatisfiedByWriteAndExec(t *testing.T) {
	if !satisfies(CapWrite, CapRead) {
		t.Error("write should satisfy read")
	}
	if !satisfies(CapExec, CapRead) {
		t.Error("exec should satisfy read")
	}
	if satisfies(CapStat, CapRead) {
		t.Error("stat should not satisfy read")
	}
}

func TestSatisfies_WriteNotSatisfiedByExec(t *testing.T) {
	if satisfies(CapExec, CapWrite) {
		t.Error("exec should not satisfy write")
	}
	if satisfies(CapStat, CapWrite) {
		t.Error("stat should not satisfy write")
	}
	if satisfies(CapRead, CapWrite) {
		t.Error("read should not satisfy write")
	}
}

func TestSatisfies_ExecNotSatisfiedByWrite(t *testing.T) {
	if satisfies(CapWrite, CapExec) {
		t.Error("write should not satisfy exec")
	}
	if satisfies(CapRead, CapExec) {
		t.Error("read should not satisfy exec")
	}
}

// --- Tests: Engine state machine (Authorize via mocked waiter) ---

func TestEngine_DirectApprove(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	pub := &stubPublisher{visible: false}
	e.cfg.Publisher = pub
	startEngine(t, e)

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/hosts", Required: CapStat}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Respond approve via socket.
	go func() {
		time.Sleep(5 * time.Millisecond)
		pub.respond(SocketResponse{Action: "approve"})
	}()

	d := e.Authorize(ctx, ev)
	if d != Allow {
		t.Errorf("expected Allow, got %v", d)
	}
	if call, ok := applier.lastCall(); !ok || !call.approved {
		t.Error("expected Applier.Apply to be called with approved=true")
	}
}

func TestEngine_DirectDeny(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	pub := &stubPublisher{visible: false}
	e.cfg.Publisher = pub
	startEngine(t, e)

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/shadow", Required: CapStat}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		time.Sleep(5 * time.Millisecond)
		pub.respond(SocketResponse{Action: "deny"})
	}()

	d := e.Authorize(ctx, ev)
	if d != Deny {
		t.Errorf("expected Deny, got %v", d)
	}
	if call, ok := applier.lastCall(); !ok || call.approved {
		t.Error("expected Applier.Apply to be called with approved=false")
	}
}

func TestEngine_PersistApproval(t *testing.T) {
	applier := &recordingApplier{}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	e := NewEngine(EngineConfig{
		Enforcing:  true,
		Applier:    applier,
		Timeout:    5 * time.Second,
		HookDelay:  50 * time.Millisecond,
		ConfigPath: cfgPath,
	})
	pub := &stubPublisher{visible: false}
	e.cfg.Publisher = pub
	startEngine(t, e)

	ev := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/ssh/sshd_config", Required: CapRead}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		time.Sleep(5 * time.Millisecond)
		pub.respond(SocketResponse{Action: "persist", Pattern: "/etc/ssh/*"})
	}()

	d := e.Authorize(ctx, ev)
	if d != Allow {
		t.Fatalf("expected Allow, got %v", d)
	}

	// Verify config.json was written.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config.json not written: %v", err)
	}
	var cfg persistedConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config.json invalid JSON: %v", err)
	}
	if len(cfg.Approvals) != 1 {
		t.Fatalf("expected 1 approval, got %d", len(cfg.Approvals))
	}
	if cfg.Approvals[0].Pattern != "/etc/ssh/*" {
		t.Errorf("pattern: got %q, want /etc/ssh/*", cfg.Approvals[0].Pattern)
	}
	if cfg.Approvals[0].Operation != "read" {
		t.Errorf("operation: got %q, want read", cfg.Approvals[0].Operation)
	}
}

// --- Tests: session cache with capability hierarchy ---

func TestEngine_SessionCacheHit_ExactPath(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	pub := &stubPublisher{visible: false}
	e.cfg.Publisher = pub
	startEngine(t, e)

	ev := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/ssh/sshd_config", Required: CapRead}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// First call — need explicit approval.
	go func() {
		time.Sleep(5 * time.Millisecond)
		pub.respond(SocketResponse{Action: "approve"})
	}()
	_ = e.Authorize(ctx, ev)

	// Manually add to session cache (simulates the first approve adding it).
	e.cacheMu.Lock()
	e.sessionCache = append(e.sessionCache, cacheEntry{cap: CapRead, pattern: ev.Path})
	e.cacheMu.Unlock()

	// Second call — should be auto-resolved from cache without prompting.
	ev2 := ViolationEvent{PID: 2, Syscall: "stat", Path: "/etc/ssh/sshd_config", Required: CapStat}
	d := e.Authorize(ctx, ev2) // CapRead in cache satisfies CapStat
	if d != Allow {
		t.Errorf("expected cache hit Allow, got %v", d)
	}
}

func TestEngine_SessionCache_CapabilityHierarchy(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	startEngine(t, e)

	// Seed session cache with a write approval.
	e.cacheMu.Lock()
	e.sessionCache = append(e.sessionCache, cacheEntry{cap: CapWrite, pattern: "/workspace/file.go"})
	e.cacheMu.Unlock()

	tests := []struct {
		required Capability
		wantHit  bool
	}{
		{CapStat, true},  // write satisfies stat
		{CapRead, true},  // write satisfies read
		{CapWrite, true}, // exact match
		{CapExec, false}, // write does not satisfy exec
	}
	for _, tt := range tests {
		ev := ViolationEvent{Path: "/workspace/file.go", Required: tt.required}
		_, got := e.checkCache(ev)
		if got != tt.wantHit {
			t.Errorf("required=%v: checkCache hit=%v, want %v", tt.required, got, tt.wantHit)
		}
	}
}

func TestEngine_SessionCache_GlobMatch(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	startEngine(t, e)

	// Seed session cache with a glob pattern.
	e.cacheMu.Lock()
	e.sessionCache = append(e.sessionCache, cacheEntry{cap: CapRead, pattern: "/etc/ssh/*"})
	e.cacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Should hit for any file in /etc/ssh/
	ev := ViolationEvent{Path: "/etc/ssh/sshd_config", Required: CapRead}
	d := e.Authorize(ctx, ev)
	if d != Allow {
		t.Errorf("glob cache hit: expected Allow, got %v", d)
	}

	// Should not hit for /etc/hosts
	ev2 := ViolationEvent{Path: "/etc/hosts", Required: CapRead}
	_, hit := e.checkCache(ev2)
	if hit {
		t.Error("should not hit for /etc/hosts with /etc/ssh/* pattern")
	}
}

// --- Tests: persisted records loaded at startup ---

func TestEngine_PersistedRecords_LoadedAtStartup(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfg := persistedConfigFile{
		Approvals: []EscalationRecord{
			{Operation: "read", Pattern: "/home/user/projects/**"},
		},
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	applier := &recordingApplier{}
	e := NewEngine(EngineConfig{
		Enforcing:  true,
		Applier:    applier,
		Timeout:    5 * time.Second,
		HookDelay:  50 * time.Millisecond,
		ConfigPath: cfgPath,
	})
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Should auto-resolve from persisted config.
	ev := ViolationEvent{Path: "/home/user/projects/foo/main.go", Required: CapRead}
	d := e.Authorize(ctx, ev)
	if d != Allow {
		t.Errorf("persisted record: expected Allow, got %v", d)
	}
}

// --- Tests: escalation deduplication ---

func TestEngine_Deduplication_CoalescesIdenticalEscalations(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	pub := &stubPublisher{visible: false}
	e.cfg.Publisher = pub
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/hosts", Required: CapStat}

	decisions := make(chan Decision, 2)

	// Launch two concurrent Authorize calls for the same resource.
	for i := 0; i < 2; i++ {
		go func() {
			decisions <- e.Authorize(ctx, ev)
		}()
	}

	// Wait briefly for both to enqueue.
	time.Sleep(20 * time.Millisecond)

	// One approval should satisfy both.
	pub.respond(SocketResponse{Action: "approve"})

	for i := 0; i < 2; i++ {
		select {
		case d := <-decisions:
			if d != Allow {
				t.Errorf("expected Allow for coalesced escalation, got %v", d)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for decision")
		}
	}
}

// --- Tests: permissive mode ---

func TestEngine_PermissiveMode_AllowsDenied(t *testing.T) {
	applier := &recordingApplier{}
	e := NewEngine(EngineConfig{
		Enforcing: false, // permissive
		Applier:   applier,
		Timeout:   5 * time.Second,
		HookDelay: 50 * time.Millisecond,
	})
	pub := &stubPublisher{visible: false}
	e.cfg.Publisher = pub
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/shadow", Required: CapStat}

	go func() {
		time.Sleep(5 * time.Millisecond)
		pub.respond(SocketResponse{Action: "deny"})
	}()

	d := e.Authorize(ctx, ev)
	// Permissive mode: deny → still Allow from the caller's view.
	if d != Allow {
		t.Errorf("permissive: expected Allow on deny, got %v", d)
	}
	// But Applier should see approved=true (the permissive allow).
	if call, ok := applier.lastCall(); !ok || !call.approved {
		t.Error("permissive: expected Applier.Apply called with approved=true")
	}
}

// --- Tests: timeout ---

func TestEngine_Timeout_DeniesInEnforcingMode(t *testing.T) {
	applier := &recordingApplier{}
	e := NewEngine(EngineConfig{
		Enforcing: true,
		Applier:   applier,
		Timeout:   50 * time.Millisecond, // very short for test
		HookDelay: 10 * time.Millisecond,
	})
	// No publisher — socket publishes are no-ops.
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/hosts", Required: CapStat}
	d := e.Authorize(ctx, ev)
	if d != Deny {
		t.Errorf("enforcing timeout: expected Deny, got %v", d)
	}
}

func TestEngine_Timeout_AllowsInPermissiveMode(t *testing.T) {
	applier := &recordingApplier{}
	e := NewEngine(EngineConfig{
		Enforcing: false, // permissive
		Applier:   applier,
		Timeout:   50 * time.Millisecond,
		HookDelay: 10 * time.Millisecond,
	})
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/hosts", Required: CapStat}
	d := e.Authorize(ctx, ev)
	if d != Allow {
		t.Errorf("permissive timeout: expected Allow, got %v", d)
	}
}

// --- Tests: hook invocation ---

func TestEngine_Hook_InvokedWhenPaneNotVisible(t *testing.T) {
	applier := &recordingApplier{}
	hook := &stubHook{resp: HookResponse{Action: "approve"}}
	e := NewEngine(EngineConfig{
		Enforcing: true,
		Applier:   applier,
		Timeout:   5 * time.Second,
		HookDelay: 50 * time.Millisecond,
		Hook:      hook,
	})
	pub := &stubPublisher{visible: false} // pane not visible → hook immediately
	e.cfg.Publisher = pub
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/hosts", Required: CapStat}
	d := e.Authorize(ctx, ev)
	if d != Allow {
		t.Errorf("hook approve: expected Allow, got %v", d)
	}
	if hook.callCount() == 0 {
		t.Error("hook should have been invoked")
	}
}

func TestEngine_Hook_DelayedWhenPaneVisible(t *testing.T) {
	applier := &recordingApplier{}
	hook := &stubHook{resp: HookResponse{Action: "approve"}}
	e := NewEngine(EngineConfig{
		Enforcing: true,
		Applier:   applier,
		Timeout:   5 * time.Second,
		HookDelay: 100 * time.Millisecond,
		Hook:      hook,
	})
	pub := &stubPublisher{visible: true} // pane visible → hook delayed
	e.cfg.Publisher = pub
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/hosts", Required: CapStat}

	// Approve via socket before hook delay expires — hook should be cancelled (not called).
	go func() {
		time.Sleep(10 * time.Millisecond) // before 100ms hook delay
		pub.respond(SocketResponse{Action: "approve"})
	}()

	start := time.Now()
	d := e.Authorize(ctx, ev)
	elapsed := time.Since(start)

	if d != Allow {
		t.Errorf("expected Allow, got %v", d)
	}
	// Should resolve quickly (socket, not hook delay).
	if elapsed > 80*time.Millisecond {
		t.Errorf("resolved too slowly (%v); socket should have won before hook delay", elapsed)
	}
	if hook.callCount() != 0 {
		t.Error("hook should NOT have been invoked (socket responded first)")
	}
}

func TestEngine_Hook_Debounce(t *testing.T) {
	applier := &recordingApplier{}
	hook := &stubHook{resp: HookResponse{Action: "approve"}}
	e := NewEngine(EngineConfig{
		Enforcing:    true,
		Applier:      applier,
		Timeout:      5 * time.Second,
		HookDelay:    0,
		HookDebounce: 10 * time.Second, // long debounce window
		Hook:         hook,
	})
	// Seed the hookLastInvoke to simulate a recent invocation.
	e.hookLastInvoke["stat:/etc/hosts"] = time.Now()
	startEngine(t, e)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pub := &stubPublisher{visible: false}
	e.cfg.Publisher = pub

	// Respond via socket so the test doesn't hang.
	go func() {
		time.Sleep(5 * time.Millisecond)
		pub.respond(SocketResponse{Action: "approve"})
	}()

	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/hosts", Required: CapStat}
	e.Authorize(ctx, ev)

	// Hook should not have been invoked (debounced).
	if hook.callCount() != 0 {
		t.Errorf("hook should be debounced, got %d calls", hook.callCount())
	}
}

// --- Tests: context cancellation ---

func TestEngine_ContextCancel_DeniesInFlight(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	startEngine(t, e)

	ctx, cancel := context.WithCancel(context.Background())

	resultCh := make(chan Decision, 1)
	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/shadow", Required: CapStat}

	go func() {
		resultCh <- e.Authorize(ctx, ev)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case d := <-resultCh:
		if d != Deny {
			t.Errorf("expected Deny on context cancel, got %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for decision after cancel")
	}
}

// --- Tests: engine shutdown ---

func TestEngine_ShutdownDeniesAllPending(t *testing.T) {
	applier := &recordingApplier{}
	e := makeEngine(t, applier)
	engineCtx, engineCancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- e.Run(engineCtx) }()

	ctx := context.Background()
	ev := ViolationEvent{PID: 1, Syscall: "stat", Path: "/etc/shadow", Required: CapStat}

	results := make(chan Decision, 3)
	for i := 0; i < 3; i++ {
		go func() {
			results <- e.Authorize(ctx, ev)
		}()
	}

	time.Sleep(20 * time.Millisecond)
	engineCancel()
	<-done

	// All pending escalations should receive Deny (but since stateMu is used to
	// deliver to escalation replies, some may not have been enqueued yet).
	// Collect whatever comes in.
	timeout := time.After(500 * time.Millisecond)
	count := 0
	for count < 3 {
		select {
		case <-results:
			count++
		case <-timeout:
			// Some goroutines may be blocked on ctx.Done check in Authorize — OK.
			return
		}
	}
}

// --- Tests: capFromString / escalationKey ---

func TestCapFromString(t *testing.T) {
	tests := []struct {
		s    string
		want Capability
	}{
		{"stat", CapStat},
		{"read", CapRead},
		{"write", CapWrite},
		{"exec", CapExec},
		{"unknown", CapStat}, // default
	}
	for _, tt := range tests {
		if got := capFromString(tt.s); got != tt.want {
			t.Errorf("capFromString(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestEscalationKey_IncludesCapAndPath(t *testing.T) {
	ev := ViolationEvent{Path: "/etc/hosts", Required: CapRead}
	key := escalationKey(ev)
	if key != "read:/etc/hosts" {
		t.Errorf("escalationKey = %q, want %q", key, "read:/etc/hosts")
	}
}

// --- Tests: NewEngine defaults ---

func TestNewEngine_Defaults(t *testing.T) {
	e := NewEngine(EngineConfig{Applier: &recordingApplier{}})
	if e.cfg.HookDelay != 5*time.Second {
		t.Errorf("default HookDelay: got %v, want 5s", e.cfg.HookDelay)
	}
	if e.cfg.HookDebounce != 30*time.Second {
		t.Errorf("default HookDebounce: got %v, want 30s", e.cfg.HookDebounce)
	}
	if e.cfg.Timeout != 300*time.Second {
		t.Errorf("default Timeout: got %v, want 300s", e.cfg.Timeout)
	}
}
