// E2E test for the full escalation flow: session socket subscriber + hook
// subprocess + authorization engine state machine (.4.2).
//
// Mocks the rampart escalations --watch CLI as a goroutine that opens a Unix
// socket connection to a real session.Server, subscribes via API2, reads
// escalation push events, and sends back command messages. The hook is a real
// shell script invoked via SubprocessHookExecutor. This proves the engine's
// race semantics (TR75–TR91), the persist round-trip (TR85, TR71), and the
// timeout default-deny (TR90) end-to-end.

package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/session"
)

// e2eBridge implements both supervisor.SocketPublisher (for the engine) and
// session.CommandHandler (for the server). It generates monotonic escalation
// IDs, registers a response channel per Publish call, and routes commands
// arriving on the socket back to the engine via that channel.
type e2eBridge struct {
	server  *session.Server
	idCount atomic.Int64

	mu       sync.Mutex
	pending  map[int64]chan SocketResponse // id → engine's response channel
}

func newE2EBridge(srv *session.Server) *e2eBridge {
	return &e2eBridge{
		server:  srv,
		pending: make(map[int64]chan SocketResponse),
	}
}

func (b *e2eBridge) PaneVisible() bool { return b.server.PaneVisible() }

func (b *e2eBridge) Publish(ctx context.Context, ev ViolationEvent) (<-chan SocketResponse, error) {
	id := b.idCount.Add(1)
	ch := make(chan SocketResponse, 1)
	b.mu.Lock()
	b.pending[id] = ch
	b.mu.Unlock()

	b.server.PushEscalation(session.OutboundEscalationEvent{
		Type:      "escalation",
		ID:        id,
		Operation: ev.Required.String(),
		Resource:  ev.Path,
		Status:    "pending",
	})

	// Drop the registration when the engine cancels (escalation resolved).
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
	}()

	return ch, nil
}

// HandleCommand implements session.CommandHandler. Routes the action back to
// the engine's response channel for the matching escalation ID.
func (b *e2eBridge) HandleCommand(action string, escalationID int64, pattern string) string {
	b.mu.Lock()
	ch, ok := b.pending[escalationID]
	if ok {
		delete(b.pending, escalationID)
	}
	b.mu.Unlock()
	if !ok {
		return "not_found"
	}
	select {
	case ch <- SocketResponse{Action: action, Pattern: pattern}:
	default:
		return "already_resolved"
	}
	switch action {
	case "approve":
		return "approved"
	case "deny":
		return "denied"
	case "persist":
		return "persisted"
	case "defer":
		return "deferred"
	}
	return "not_found"
}

// e2eHarness wires together a session.Server, an Engine, a bridge, a hook,
// and exposes a fake subscriber over the real Unix socket.
type e2eHarness struct {
	t          *testing.T
	socketPath string
	server     *session.Server
	engine     *Engine
	bridge     *e2eBridge
	applier    *recordingApplier
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

type harnessConfig struct {
	hookCommand  string
	hookTimeout  time.Duration
	hookDelay    time.Duration
	hookDebounce time.Duration
	timeout      time.Duration
	enforcing    bool
	configPath   string
}

func startE2EHarness(t *testing.T, hc harnessConfig) *e2eHarness {
	t.Helper()

	// Use /tmp directly: t.TempDir() on darwin returns /var/folders/... paths
	// that exceed sun_path's 104-byte limit when combined with the test name.
	dir, err := os.MkdirTemp("/tmp", "rmpt")
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "s")

	applier := &recordingApplier{}
	bridge := newE2EBridge(nil)
	srv := session.NewServer(session.ServerConfig{
		SocketPath: socketPath,
		Commands:   bridge,
	})
	bridge.server = srv

	hook := NewSubprocessHookExecutor(hc.hookCommand, hc.hookTimeout, nil)

	engineCfg := EngineConfig{
		Enforcing:    hc.enforcing,
		Applier:      applier,
		Publisher:    bridge,
		Hook:         hook,
		Timeout:      hc.timeout,
		HookDelay:    hc.hookDelay,
		HookDebounce: hc.hookDebounce,
		ConfigPath:   hc.configPath,
	}
	engine := NewEngine(engineCfg)

	ctx, cancel := context.WithCancel(context.Background())
	h := &e2eHarness{
		t:          t,
		socketPath: socketPath,
		server:     srv,
		engine:     engine,
		bridge:     bridge,
		applier:    applier,
		cancel:     cancel,
	}

	// Start server first so the socket exists before subscriber connects.
	srvErr := make(chan error, 1)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		srvErr <- srv.Run(ctx)
	}()

	engineErr := make(chan error, 1)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		engineErr <- engine.Run(ctx)
	}()

	// Wait for socket to appear so subscribers can connect.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		h.wg.Wait()
	})

	return h
}

// fakeSubscriber connects to the session socket as a "tmux pane" subscriber.
// It mirrors the rampart escalations --watch wire protocol (API2).
type fakeSubscriber struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (h *e2eHarness) connectSubscriber(t *testing.T, paneVisible bool) *fakeSubscriber {
	t.Helper()
	conn, err := net.Dial("unix", h.socketPath)
	if err != nil {
		t.Fatalf("dial session socket: %v", err)
	}
	sub := &fakeSubscriber{conn: conn, reader: bufio.NewReader(conn)}

	// Subscribe to escalation pushes.
	sub.send(t, session.InboundMessage{Type: "watch"})

	// Drain the initial list response so it doesn't pollute later reads.
	if _, err := sub.reader.ReadBytes('\n'); err != nil {
		t.Fatalf("reading initial list response: %v", err)
	}

	if paneVisible {
		sub.send(t, session.InboundMessage{Type: "presence", Event: "focus-in"})
	}

	t.Cleanup(func() { conn.Close() })
	return sub
}

func (s *fakeSubscriber) send(t *testing.T, msg session.InboundMessage) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal inbound: %v", err)
	}
	data = append(data, '\n')
	if _, err := s.conn.Write(data); err != nil {
		t.Fatalf("write to socket: %v", err)
	}
}

// readEscalation reads one OutboundEscalationEvent from the socket. Skips ack
// frames so command responses don't confuse the test logic.
func (s *fakeSubscriber) readEscalation(t *testing.T, timeout time.Duration) session.OutboundEscalationEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	defer s.conn.SetReadDeadline(time.Time{})

	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read socket: %v", err)
		}
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("decode frame: %v (raw=%s)", err, string(line))
		}
		if probe.Type != "escalation" {
			continue // skip ack/response frames
		}
		var ev session.OutboundEscalationEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("decode escalation: %v", err)
		}
		return ev
	}
}

// --- helpers ---

// writeShellScript writes a shell script to a temp file and returns its path.
func writeShellScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	content := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write hook script: %v", err)
	}
	return path
}

// --- Tests ---

// TestE2E_Escalation_SubscriberApprovesBeforeHookFires verifies that when the
// rampart pane is visible, the hook is delayed (TR75); a subscriber response
// arriving before the delay expires resolves the escalation and cancels the
// hook (TR80).
func TestE2E_Escalation_SubscriberApprovesBeforeHookFires(t *testing.T) {
	// Hook script writes a sentinel file to prove it ran.
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "hook-ran")
	hookScript := writeShellScript(t, fmt.Sprintf(
		`touch %s; sleep 5; echo '{"action":"approve"}'`, sentinel))

	h := startE2EHarness(t, harnessConfig{
		hookCommand: hookScript,
		hookTimeout: 10 * time.Second,
		hookDelay:   500 * time.Millisecond, // long enough for subscriber to win
		timeout:     5 * time.Second,
		enforcing:   true,
	})
	sub := h.connectSubscriber(t, true /* paneVisible */)

	// Wait for the focus-in presence event to be processed.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && !h.server.PaneVisible() {
		time.Sleep(5 * time.Millisecond)
	}
	if !h.server.PaneVisible() {
		t.Fatal("pane never registered as visible after focus-in")
	}

	ev := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/hosts", Required: CapRead}
	resultCh := make(chan Decision, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resultCh <- h.engine.Authorize(ctx, ev)
	}()

	pushed := sub.readEscalation(t, 2*time.Second)
	if pushed.Resource != "/etc/hosts" {
		t.Errorf("escalation resource: got %q, want /etc/hosts", pushed.Resource)
	}

	// Subscriber approves before the 500ms hook delay expires.
	sub.send(t, session.InboundMessage{
		Type:         "command",
		Action:       "approve",
		EscalationID: pushed.ID,
	})

	select {
	case d := <-resultCh:
		if d != Allow {
			t.Errorf("expected Allow, got %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("engine did not resolve escalation in time")
	}

	// The hook should not have run because the engine cancelled before the
	// delay timer fired.
	if _, err := os.Stat(sentinel); err == nil {
		t.Error("hook ran but should have been cancelled before its delay elapsed")
	}
}

// TestE2E_Escalation_HookApprovesWhenPaneNotVisible verifies that when the
// pane is not visible the hook is invoked immediately (TR76) and its response
// resolves the escalation.
func TestE2E_Escalation_HookApprovesWhenPaneNotVisible(t *testing.T) {
	hookScript := writeShellScript(t, `echo '{"action":"approve"}'`)

	h := startE2EHarness(t, harnessConfig{
		hookCommand: hookScript,
		hookTimeout: 5 * time.Second,
		hookDelay:   50 * time.Millisecond,
		timeout:     5 * time.Second,
		enforcing:   true,
	})
	// No subscriber: pane is not visible.

	ev := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/hosts", Required: CapRead}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := h.engine.Authorize(ctx, ev)
	if d != Allow {
		t.Errorf("expected Allow from hook, got %v", d)
	}
}

// TestE2E_Escalation_HookDeferThenSubscriberApproves verifies that a hook
// returning "defer" does not resolve the escalation; the subscriber must still
// be able to decide.
func TestE2E_Escalation_HookDeferThenSubscriberApproves(t *testing.T) {
	hookScript := writeShellScript(t, `echo '{"action":"defer"}'`)

	h := startE2EHarness(t, harnessConfig{
		hookCommand: hookScript,
		hookTimeout: 5 * time.Second,
		hookDelay:   10 * time.Millisecond, // hook fires fast
		timeout:     5 * time.Second,
		enforcing:   true,
	})
	sub := h.connectSubscriber(t, true)

	ev := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/hosts", Required: CapRead}
	resultCh := make(chan Decision, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resultCh <- h.engine.Authorize(ctx, ev)
	}()

	pushed := sub.readEscalation(t, 2*time.Second)

	// Give the hook time to run and return defer.
	time.Sleep(150 * time.Millisecond)

	// No decision yet — verify Authorize hasn't returned.
	select {
	case d := <-resultCh:
		t.Fatalf("engine resolved before subscriber decided: %v", d)
	default:
	}

	sub.send(t, session.InboundMessage{
		Type:         "command",
		Action:       "approve",
		EscalationID: pushed.ID,
	})

	select {
	case d := <-resultCh:
		if d != Allow {
			t.Errorf("expected Allow, got %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("engine did not resolve after subscriber approve")
	}
}

// TestE2E_Escalation_TimeoutDefaultDeny verifies that when neither the
// subscriber nor the hook respond in time, the engine times out and applies
// the default-deny in enforcing mode.
func TestE2E_Escalation_TimeoutDefaultDeny(t *testing.T) {
	hookScript := writeShellScript(t, `exec sleep 30`) // never returns in time

	h := startE2EHarness(t, harnessConfig{
		hookCommand: hookScript,
		hookTimeout: 10 * time.Second,
		hookDelay:   50 * time.Millisecond,
		timeout:     200 * time.Millisecond, // short escalation timeout
		enforcing:   true,
	})
	// Subscriber connects but never responds.
	_ = h.connectSubscriber(t, true)

	ev := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/hosts", Required: CapRead}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	d := h.engine.Authorize(ctx, ev)
	elapsed := time.Since(start)

	if d != Deny {
		t.Errorf("enforcing timeout: expected Deny, got %v", d)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("timeout took too long: %v (expected ~200ms)", elapsed)
	}
	if call, ok := h.applier.lastCall(); !ok || call.approved {
		t.Error("expected Applier.Apply to be called with approved=false")
	}
}

// TestE2E_Escalation_PersistRoundTrip verifies that a "persist" command
// writes config.json and that subsequent identical violations are auto-resolved
// from the session cache without re-prompting the subscriber.
func TestE2E_Escalation_PersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	hookScript := writeShellScript(t, `echo '{"action":"defer"}'`)

	h := startE2EHarness(t, harnessConfig{
		hookCommand: hookScript,
		hookTimeout: 5 * time.Second,
		hookDelay:   500 * time.Millisecond,
		timeout:     5 * time.Second,
		enforcing:   true,
		configPath:  cfgPath,
	})
	sub := h.connectSubscriber(t, true)

	// First escalation: subscriber persists with a glob pattern.
	ev1 := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/ssh/sshd_config", Required: CapRead}
	res1 := make(chan Decision, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		res1 <- h.engine.Authorize(ctx, ev1)
	}()

	pushed := sub.readEscalation(t, 2*time.Second)
	sub.send(t, session.InboundMessage{
		Type:         "command",
		Action:       "persist",
		EscalationID: pushed.ID,
		Pattern:      "/etc/ssh/*",
	})

	select {
	case d := <-res1:
		if d != Allow {
			t.Fatalf("first escalation: expected Allow, got %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first escalation did not resolve")
	}

	// Drain the ack frame for the persist command so subsequent reads aren't
	// confused by buffered protocol traffic.
	if _, err := sub.reader.ReadBytes('\n'); err != nil {
		t.Fatalf("read persist ack: %v", err)
	}

	// config.json must exist with the persisted approval.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config.json not written: %v", err)
	}
	var cfgFile persistedConfigFile
	if err := json.Unmarshal(data, &cfgFile); err != nil {
		t.Fatalf("config.json invalid JSON: %v", err)
	}
	if len(cfgFile.Approvals) != 1 || cfgFile.Approvals[0].Pattern != "/etc/ssh/*" {
		t.Errorf("persisted approvals: %+v", cfgFile.Approvals)
	}

	// Second escalation: matches the persisted glob (single-segment *), must
	// auto-resolve without publishing to the socket. We verify by setting a
	// short read deadline and expecting no escalation push.
	ev2 := ViolationEvent{PID: 2, Syscall: "openat", Path: "/etc/ssh/ssh_config", Required: CapRead}
	res2 := make(chan Decision, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		res2 <- h.engine.Authorize(ctx, ev2)
	}()

	select {
	case d := <-res2:
		if d != Allow {
			t.Errorf("second escalation: expected Allow from cache, got %v", d)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("second escalation did not auto-resolve from cache")
	}

	// Subscriber must NOT have received a second escalation push.
	if err := sub.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := sub.reader.ReadByte(); err == nil {
		t.Error("subscriber received an escalation push for a cached approval")
	}
	sub.conn.SetReadDeadline(time.Time{})
}

// TestE2E_Escalation_SubscriberDeniesAppliedToMonitor verifies the deny path
// end-to-end: subscriber denies, applier sees approved=false, caller gets Deny.
func TestE2E_Escalation_SubscriberDeniesAppliedToMonitor(t *testing.T) {
	hookScript := writeShellScript(t, `echo '{"action":"defer"}'`)

	h := startE2EHarness(t, harnessConfig{
		hookCommand: hookScript,
		hookTimeout: 5 * time.Second,
		hookDelay:   500 * time.Millisecond,
		timeout:     5 * time.Second,
		enforcing:   true,
	})
	sub := h.connectSubscriber(t, true)

	ev := ViolationEvent{PID: 1, Syscall: "openat", Path: "/etc/shadow", Required: CapRead}
	resultCh := make(chan Decision, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resultCh <- h.engine.Authorize(ctx, ev)
	}()

	pushed := sub.readEscalation(t, 2*time.Second)
	sub.send(t, session.InboundMessage{
		Type:         "command",
		Action:       "deny",
		EscalationID: pushed.ID,
	})

	select {
	case d := <-resultCh:
		if d != Deny {
			t.Errorf("expected Deny, got %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("engine did not resolve")
	}

	if call, ok := h.applier.lastCall(); !ok || call.approved {
		t.Error("expected Applier.Apply to be called with approved=false")
	}
}
