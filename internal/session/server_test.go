package session_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/session"
)

// startServer starts a Server with a temp socket path and returns it plus
// a cancel function. The server runs in the background.
func startServer(t *testing.T, cfg session.ServerConfig) *session.Server {
	t.Helper()
	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(t.TempDir(), "test.sock")
	}
	srv := session.NewServer(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()
	// Wait for socket to appear.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		<-errCh
	})
	return srv
}

// connectClient dials the socket and returns a connection.
func connectClient(t *testing.T, socketPath string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", socketPath, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// sendJSON writes a JSON message followed by newline to conn.
func sendJSON(t *testing.T, conn net.Conn, msg any) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// connScanner wraps a net.Conn with a persistent scanner to avoid losing
// buffered lines when multiple JSON responses arrive in sequence.
type connScanner struct {
	conn    net.Conn
	scanner *bufio.Scanner
}

func newConnScanner(conn net.Conn) *connScanner {
	return &connScanner{conn: conn, scanner: bufio.NewScanner(conn)}
}

// readJSON reads one newline-delimited JSON line into v.
func (cs *connScanner) readJSON(t *testing.T, v any) {
	t.Helper()
	cs.conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	if !cs.scanner.Scan() {
		t.Fatal("expected JSON response, got EOF or error")
	}
	if err := json.Unmarshal(cs.scanner.Bytes(), v); err != nil {
		t.Fatalf("unmarshal response: %v\ndata: %s", err, cs.scanner.Bytes())
	}
}

func TestServer_SocketCreated(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	if _, err := os.Stat(sockPath); err != nil {
		t.Errorf("expected socket at %s, got: %v", sockPath, err)
	}
}

func TestServer_SocketRemovedOnShutdown(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	cfg := session.ServerConfig{SocketPath: sockPath}
	srv := session.NewServer(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// Wait for socket.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cancel context → socket should be removed.
	cancel()
	<-errCh

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Error("expected socket to be removed after shutdown")
	}
}

func TestServer_AcceptsMultipleSubscribers(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	c1 := connectClient(t, sockPath)
	c2 := connectClient(t, sockPath)
	_ = c1
	_ = c2
	// Both connections should succeed — no error returned from the dials above.
}

func TestServer_PresenceEvent_FocusIn(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	sendJSON(t, conn, map[string]string{"type": "presence", "event": "focus-in"})

	// Give the server time to process the event.
	time.Sleep(50 * time.Millisecond)

	if !srv.Presence().PaneVisible {
		t.Error("expected PaneVisible after focus-in event")
	}
}

func TestServer_PresenceEvent_FocusOut(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	srv := startServer(t, session.ServerConfig{
		SocketPath: sockPath,
		Presence:   session.PresenceState{PaneVisible: true},
	})

	conn := connectClient(t, sockPath)
	sendJSON(t, conn, map[string]string{"type": "presence", "event": "focus-out"})
	time.Sleep(50 * time.Millisecond)

	if srv.Presence().PaneVisible {
		t.Error("expected PaneVisible=false after focus-out event")
	}
}

func TestServer_QueryList_EmptyWithNoLister(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	sendJSON(t, conn, map[string]string{"type": "query", "action": "list"})

	var resp session.OutboundResponse
	cs.readJSON(t, &resp)
	if resp.Type != "response" {
		t.Errorf("type = %q, want %q", resp.Type, "response")
	}
	if len(resp.Escalations) != 0 {
		t.Errorf("escalations = %d, want 0", len(resp.Escalations))
	}
}

type stubLister struct {
	items []session.OutboundEscalation
}

func (s *stubLister) ListEscalations() []session.OutboundEscalation { return s.items }

func TestServer_QueryList_WithLister(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	lister := &stubLister{items: []session.OutboundEscalation{
		{ID: 1, Operation: "read", Resource: "/etc/ssh/sshd_config", Status: "pending"},
	}}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Lister: lister})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	sendJSON(t, conn, map[string]string{"type": "query", "action": "list"})

	var resp session.OutboundResponse
	cs.readJSON(t, &resp)
	if len(resp.Escalations) != 1 {
		t.Fatalf("escalations = %d, want 1", len(resp.Escalations))
	}
	if resp.Escalations[0].ID != 1 {
		t.Errorf("escalation ID = %d, want 1", resp.Escalations[0].ID)
	}
}

type stubCommandHandler struct {
	calls []string
}

func (h *stubCommandHandler) HandleCommand(action string, id int64, pattern string) string {
	h.calls = append(h.calls, fmt.Sprintf("%s:%d", action, id))
	return "approved"
}

func TestServer_Command_Approve(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	handler := &stubCommandHandler{}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Commands: handler})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	sendJSON(t, conn, map[string]any{
		"type":          "command",
		"action":        "approve",
		"escalation_id": 42,
	})

	var ack session.OutboundAck
	cs.readJSON(t, &ack)
	if ack.Type != "ack" {
		t.Errorf("type = %q, want ack", ack.Type)
	}
	if ack.EscalationID != 42 {
		t.Errorf("escalation_id = %d, want 42", ack.EscalationID)
	}
	if ack.Result != "approved" {
		t.Errorf("result = %q, want approved", ack.Result)
	}
}

func TestServer_Command_NoHandler_ReturnsNotFound(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	sendJSON(t, conn, map[string]any{
		"type":          "command",
		"action":        "approve",
		"escalation_id": 99,
	})

	var ack session.OutboundAck
	cs.readJSON(t, &ack)
	if ack.Result != "not_found" {
		t.Errorf("result = %q, want not_found", ack.Result)
	}
}

func TestServer_PushEscalation_ToWatchers(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	// Subscribe to escalation events.
	sendJSON(t, conn, map[string]string{"type": "watch"})
	time.Sleep(50 * time.Millisecond)

	ev := session.OutboundEscalationEvent{
		Type:      "escalation",
		ID:        7,
		Operation: "read",
		Resource:  "/etc/passwd",
		Status:    "pending",
	}
	srv.PushEscalation(ev)

	// First response is the list from subscribe; second is the push.
	var list session.OutboundResponse
	cs.readJSON(t, &list) // initial list on subscribe

	var pushed session.OutboundEscalationEvent
	cs.readJSON(t, &pushed)
	if pushed.ID != 7 {
		t.Errorf("pushed escalation ID = %d, want 7", pushed.ID)
	}
}

func TestServer_SubscriberDisconnect_NoPanic(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "rampart.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	conn.Close() // disconnect immediately
	time.Sleep(50 * time.Millisecond)

	// Push to nobody — should not panic.
	srv.PushEscalation(session.OutboundEscalationEvent{Type: "escalation", ID: 1})
}

func TestBootstrapPresence_CI(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv("TMUX", "")
	t.Setenv("SSH_CONNECTION", "")

	ps := session.BootstrapPresence()
	if !ps.Headless {
		t.Error("expected Headless=true in CI env")
	}
}

func TestBootstrapPresence_Tmux(t *testing.T) {
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")
	t.Setenv("CI", "")

	ps := session.BootstrapPresence()
	if !ps.InTmux {
		t.Error("expected InTmux=true when $TMUX set")
	}
	if !ps.PaneVisible {
		t.Error("expected PaneVisible=true when in tmux")
	}
}

func TestBootstrapPresence_SSH(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "10.0.0.1 12345 10.0.0.2 22")
	t.Setenv("TMUX", "")
	t.Setenv("CI", "")

	ps := session.BootstrapPresence()
	if !ps.OverSSH {
		t.Error("expected OverSSH=true when $SSH_CONNECTION set")
	}
}

func TestPresenceState_AvailableChannels_Headless(t *testing.T) {
	ps := session.PresenceState{Headless: true}
	ch := ps.AvailableChannels()
	// Should have CLI and Remote but not Terminal.
	for _, c := range ch {
		if c == session.ChannelTerminal {
			t.Error("headless session should not have ChannelTerminal")
		}
	}
}

func TestPresenceState_AvailableChannels_Local(t *testing.T) {
	ps := session.PresenceState{HasTTY: true}
	ch := ps.AvailableChannels()
	hasTerminal := false
	for _, c := range ch {
		if c == session.ChannelTerminal {
			hasTerminal = true
		}
	}
	if !hasTerminal {
		t.Error("local TTY session should have ChannelTerminal")
	}
}
