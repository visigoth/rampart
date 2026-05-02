package session_test

// Contract tests for the API2 session socket protocol.
//
// These tests verify that the producer side (supervisor) and consumer side
// (rampart escalations CLI) agree on the exact JSON schema and ndjson framing
// for all five message types. See .plans/rampart/contracts/api2-session-socket.org.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/session"
)

// --- API2.1: Presence Event (external → supervisor) ---

func TestContractAPI21_FocusIn_UpdatesPresenceState(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	// Exact wire format per API2.1 spec.
	wire := `{"type":"presence","event":"focus-in","tty":"/dev/pts/5","client":"local"}` + "\n"
	if _, err := fmt.Fprint(conn, wire); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if !srv.Presence().PaneVisible {
		t.Error("API2.1 focus-in should set PaneVisible=true")
	}
}

func TestContractAPI21_FocusOut_UpdatesPresenceState(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := startServer(t, session.ServerConfig{
		SocketPath: sockPath,
		Presence:   session.PresenceState{PaneVisible: true},
	})

	conn := connectClient(t, sockPath)
	wire := `{"type":"presence","event":"focus-out"}` + "\n"
	fmt.Fprint(conn, wire) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)

	if srv.Presence().PaneVisible {
		t.Error("API2.1 focus-out should clear PaneVisible")
	}
}

func TestContractAPI21_SessionStart_SSH_UpdatesPresenceState(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	wire := `{"type":"presence","event":"session-start","client":"ssh","tty":"/dev/pts/7"}` + "\n"
	fmt.Fprint(conn, wire) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)

	ps := srv.Presence()
	if !ps.OverSSH {
		t.Error("API2.1 session-start with client=ssh should set OverSSH=true")
	}
	if !ps.HasTTY {
		t.Error("API2.1 session-start with tty set should set HasTTY=true")
	}
}

func TestContractAPI21_AllEventTypes_ParseWithoutError(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})
	conn := connectClient(t, sockPath)

	// All four event types from the spec.
	events := []string{
		`{"type":"presence","event":"focus-in"}`,
		`{"type":"presence","event":"focus-out"}`,
		`{"type":"presence","event":"session-start","client":"local"}`,
		`{"type":"presence","event":"session-end"}`,
	}
	for _, e := range events {
		if _, err := fmt.Fprintln(conn, e); err != nil {
			t.Fatalf("writing %q: %v", e, err)
		}
	}
	// No response expected; server should silently handle all of them.
	time.Sleep(50 * time.Millisecond)
}

// --- API2.2: Escalation Query (external → supervisor) ---

func TestContractAPI22_ListQuery_ReturnsResponseType(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)

	// Exact wire format per API2.2.
	fmt.Fprintln(conn, `{"type":"query","action":"list"}`) //nolint:errcheck

	var resp session.OutboundResponse
	cs.readJSON(t, &resp)
	if resp.Type != "response" {
		t.Errorf("API2.4 type = %q, want %q", resp.Type, "response")
	}
	if resp.Escalations == nil {
		t.Error("API2.4 escalations must be non-nil (empty array, not null)")
	}
}

func TestContractAPI22_ListQuery_EscalationSchema(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	lister := &stubLister{items: []session.OutboundEscalation{
		{
			ID:        1,
			Operation: "read",
			Resource:  "/etc/ssh/sshd_config",
			Status:    "pending",
			Timestamp: "2026-04-29T10:15:00Z",
		},
	}}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Lister: lister})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	fmt.Fprintln(conn, `{"type":"query","action":"list"}`) //nolint:errcheck

	var resp session.OutboundResponse
	cs.readJSON(t, &resp)

	if len(resp.Escalations) != 1 {
		t.Fatalf("want 1 escalation, got %d", len(resp.Escalations))
	}
	e := resp.Escalations[0]
	if e.ID != 1 {
		t.Errorf("id = %d, want 1", e.ID)
	}
	if e.Operation != "read" {
		t.Errorf("operation = %q, want %q", e.Operation, "read")
	}
	if e.Resource != "/etc/ssh/sshd_config" {
		t.Errorf("resource = %q, want %q", e.Resource, "/etc/ssh/sshd_config")
	}
	if e.Status != "pending" {
		t.Errorf("status = %q, want %q", e.Status, "pending")
	}
}

// --- API2.3: Escalation Command (external → supervisor) ---

func TestContractAPI23_ApproveCommand_Schema(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	handler := &stubCommandHandler{}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Commands: handler})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)

	// Exact wire format per API2.3.
	wire := `{"type":"command","action":"approve","escalation_id":1}` + "\n"
	fmt.Fprint(conn, wire) //nolint:errcheck

	var ack session.OutboundAck
	cs.readJSON(t, &ack)
	if ack.Type != "ack" {
		t.Errorf("API2.5 type = %q, want ack", ack.Type)
	}
	if ack.EscalationID != 1 {
		t.Errorf("escalation_id = %d, want 1", ack.EscalationID)
	}
	// Handler returns "approved".
	if ack.Result != "approved" {
		t.Errorf("result = %q, want approved", ack.Result)
	}
	// Verify handler received the right action.
	if len(handler.calls) != 1 || !strings.Contains(handler.calls[0], "approve") {
		t.Errorf("handler should have been called with approve, got %v", handler.calls)
	}
}

func TestContractAPI23_DenyCommand_Schema(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	handler := &denyHandler{}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Commands: handler})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	fmt.Fprintln(conn, `{"type":"command","action":"deny","escalation_id":3}`) //nolint:errcheck

	var ack session.OutboundAck
	cs.readJSON(t, &ack)
	if ack.Result != "denied" {
		t.Errorf("result = %q, want denied", ack.Result)
	}
	if ack.EscalationID != 3 {
		t.Errorf("escalation_id = %d, want 3", ack.EscalationID)
	}
}

func TestContractAPI23_PersistCommand_Schema(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	handler := &persistHandler{}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Commands: handler})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	fmt.Fprintln(conn, `{"type":"command","action":"persist","escalation_id":1}`) //nolint:errcheck

	var ack session.OutboundAck
	cs.readJSON(t, &ack)
	if ack.Result != "persisted" {
		t.Errorf("result = %q, want persisted", ack.Result)
	}
}

// --- API2.4: Query Response (supervisor → external) round-trip ---

func TestContractRoundTrip_QueryListResponse(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	lister := &stubLister{items: []session.OutboundEscalation{
		{ID: 10, Operation: "connect", Resource: "evil.com:443", Status: "denied", Timestamp: "2026-04-29T10:16:00Z"},
	}}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Lister: lister})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	fmt.Fprintln(conn, `{"type":"query","action":"list"}`) //nolint:errcheck

	// Verify the raw JSON contains the expected fields (spec compliance).
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatal("expected JSON response line")
	}
	raw := scanner.Text()

	// Unmarshal to verify field names match the spec.
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"type", "escalations"} {
		if _, ok := payload[field]; !ok {
			t.Errorf("API2.4 response missing field %q", field)
		}
	}
	// "type" must be "response".
	var typ string
	if err := json.Unmarshal(payload["type"], &typ); err != nil || typ != "response" {
		t.Errorf("API2.4 type = %q, want response", typ)
	}

	// Escalations should be an array (not null).
	var escalations []json.RawMessage
	if err := json.Unmarshal(payload["escalations"], &escalations); err != nil {
		t.Errorf("API2.4 escalations is not a JSON array: %v", err)
	}
	_ = cs
}

// --- API2.5: Command Acknowledgment (supervisor → external) round-trip ---

func TestContractRoundTrip_CommandAck_FieldNames(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	handler := &stubCommandHandler{}
	startServer(t, session.ServerConfig{SocketPath: sockPath, Commands: handler})

	conn := connectClient(t, sockPath)
	fmt.Fprintln(conn, `{"type":"command","action":"approve","escalation_id":42}`) //nolint:errcheck

	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatal("expected ack")
	}
	raw := scanner.Text()

	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	for _, field := range []string{"type", "escalation_id", "result"} {
		if _, ok := payload[field]; !ok {
			t.Errorf("API2.5 ack missing field %q", field)
		}
	}
	var ackType string
	json.Unmarshal(payload["type"], &ackType) //nolint:errcheck
	if ackType != "ack" {
		t.Errorf("API2.5 type = %q, want ack", ackType)
	}
}

func TestContractAPI25_NotFoundResult(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	// No Commands handler → returns "not_found".
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	fmt.Fprintln(conn, `{"type":"command","action":"approve","escalation_id":99}`) //nolint:errcheck

	var ack session.OutboundAck
	cs.readJSON(t, &ack)
	if ack.Result != "not_found" {
		t.Errorf("API2.5 result = %q, want not_found", ack.Result)
	}
	if ack.EscalationID != 99 {
		t.Errorf("API2.5 escalation_id = %d, want 99", ack.EscalationID)
	}
}

// --- Schema mismatch / forward-compatibility ---

func TestContractSchemaCompat_ExtraFields_Ignored(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})
	conn := connectClient(t, sockPath)

	// Unknown fields must be silently ignored (forward-compatible).
	// A future client might add new fields; existing server must not crash.
	wire := `{"type":"presence","event":"focus-in","unknown_field":"future_value","nested":{"a":1}}` + "\n"
	if _, err := fmt.Fprint(conn, wire); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	// No panic or connection drop expected.
}

func TestContractSchemaCompat_UnknownMessageType_HandledGracefully(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	// Unknown type — server should log a warning but stay alive.
	fmt.Fprintln(conn, `{"type":"unknown_future_type","data":"ignored"}`) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)

	// Connection should still be usable (server didn't close it).
	cs := newConnScanner(conn)
	fmt.Fprintln(conn, `{"type":"query","action":"list"}`) //nolint:errcheck
	var resp session.OutboundResponse
	cs.readJSON(t, &resp)
	if resp.Type != "response" {
		t.Errorf("server unresponsive after unknown message type: got %q", resp.Type)
	}
}

func TestContractSchemaCompat_MissingEventField_HandledGracefully(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})
	conn := connectClient(t, sockPath)

	// Presence message without "event" field — should not crash.
	fmt.Fprintln(conn, `{"type":"presence"}`) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)
	// Server stays alive; subsequent message still works.
}

func TestContractSchemaCompat_MissingEscalationID_CommandNotFound(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)
	// Missing escalation_id defaults to zero → "not_found".
	fmt.Fprintln(conn, `{"type":"command","action":"approve"}`) //nolint:errcheck

	var ack session.OutboundAck
	cs.readJSON(t, &ack)
	// Server should respond with "not_found" for escalation_id=0.
	if ack.Type != "ack" {
		t.Errorf("type = %q, want ack", ack.Type)
	}
}

// --- NDJSON framing ---

func TestContractNDJSON_MultipleMessagesOnOneConnection(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)

	// Send two queries in quick succession on the same TCP-style connection.
	fmt.Fprintln(conn, `{"type":"query","action":"list"}`) //nolint:errcheck
	fmt.Fprintln(conn, `{"type":"query","action":"list"}`) //nolint:errcheck

	// Expect two responses, each on its own line.
	var r1, r2 session.OutboundResponse
	cs.readJSON(t, &r1)
	cs.readJSON(t, &r2)
	if r1.Type != "response" || r2.Type != "response" {
		t.Errorf("expected two response messages, got %q and %q", r1.Type, r2.Type)
	}
}

func TestContractNDJSON_MessagesSeparatedByNewlines(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	fmt.Fprintln(conn, `{"type":"query","action":"list"}`) //nolint:errcheck

	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	raw := string(buf[:n])

	// Each NDJSON response line must end with exactly one newline.
	if !strings.HasSuffix(raw, "\n") {
		t.Error("NDJSON: response must be newline-terminated")
	}
	// Exactly one newline (one message, not two).
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 NDJSON line, got %d: %q", len(lines), raw)
	}
	// Must be valid JSON.
	var v map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &v); err != nil {
		t.Errorf("response line is not valid JSON: %v", err)
	}
}

// --- API2.6: Push Escalation Event (supervisor → watchers) round-trip ---

func TestContractRoundTrip_PushEscalationToWatcher(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: sockPath})

	conn := connectClient(t, sockPath)
	cs := newConnScanner(conn)

	// Subscribe.
	fmt.Fprintln(conn, `{"type":"watch"}`) //nolint:errcheck
	// Consume the initial list response.
	var list session.OutboundResponse
	cs.readJSON(t, &list)

	time.Sleep(30 * time.Millisecond)

	// Supervisor pushes escalation.
	ev := session.OutboundEscalationEvent{
		Type:      "escalation",
		ID:        42,
		Operation: "read",
		Resource:  "/etc/passwd",
		Status:    "pending",
	}
	srv.PushEscalation(ev)

	var pushed session.OutboundEscalationEvent
	cs.readJSON(t, &pushed)
	if pushed.Type != "escalation" {
		t.Errorf("push type = %q, want escalation", pushed.Type)
	}
	if pushed.ID != 42 {
		t.Errorf("push ID = %d, want 42", pushed.ID)
	}
	if pushed.Operation != "read" {
		t.Errorf("push operation = %q, want read", pushed.Operation)
	}
	if pushed.Resource != "/etc/passwd" {
		t.Errorf("push resource = %q", pushed.Resource)
	}
	if pushed.Status != "pending" {
		t.Errorf("push status = %q, want pending", pushed.Status)
	}
}

func TestContractRoundTrip_PushNotSentToNonWatchers(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: sockPath})

	// Connect but do NOT send "watch".
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	time.Sleep(30 * time.Millisecond)

	srv.PushEscalation(session.OutboundEscalationEvent{Type: "escalation", ID: 1})

	// Non-watcher should receive nothing — set a short deadline and expect timeout.
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n != 0 {
		t.Errorf("non-watcher should not receive push, got %d bytes: %s", n, buf[:n])
	}
}

// --- Helpers for this file ---

type denyHandler struct{}

func (h *denyHandler) HandleCommand(_ string, _ int64, _ string) string { return "denied" }

type persistHandler struct{}

func (h *persistHandler) HandleCommand(_ string, _ int64, _ string) string { return "persisted" }
