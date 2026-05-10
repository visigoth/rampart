package session_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/session"
)

// fakeListerWithItems returns a fixed escalation list.
type fakeListerWithItems struct {
	items []session.OutboundEscalation
}

func (f *fakeListerWithItems) ListEscalations() []session.OutboundEscalation {
	return f.items
}

// fakeCommandsRecording records the calls and returns the configured result.
type fakeCommandsRecording struct {
	result string
	calls  []struct {
		action  string
		id      int64
		pattern string
	}
}

func (f *fakeCommandsRecording) HandleCommand(action string, id int64, pattern string) string {
	f.calls = append(f.calls, struct {
		action  string
		id      int64
		pattern string
	}{action, id, pattern})
	return f.result
}

func TestClient_List_Roundtrip(t *testing.T) {
	lister := &fakeListerWithItems{
		items: []session.OutboundEscalation{
			{ID: 1, Operation: "read", Resource: "/etc/master.passwd", Status: "pending", Timestamp: "2026-05-10T00:00:00Z"},
			{ID: 2, Operation: "exec", Resource: "/usr/local/bin/foo", Status: "pending", Timestamp: "2026-05-10T00:00:01Z"},
		},
	}
	srv := startServer(t, session.ServerConfig{Lister: lister})
	_ = srv

	// Find the socket path the server is using by re-deriving it from cfg.
	// startServer's tmpSock helper writes to /tmp/rmpt*/s; ListActiveSockets
	// is path-aware so we use Dial directly.
	sockPath := socketOf(t, srv)
	c, err := session.Dial(sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	resp, err := c.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Escalations) != 2 {
		t.Fatalf("expected 2 escalations, got %d", len(resp.Escalations))
	}
	if resp.Escalations[0].ID != 1 || resp.Escalations[1].ID != 2 {
		t.Errorf("IDs: got %v, want [1, 2]", []int64{resp.Escalations[0].ID, resp.Escalations[1].ID})
	}
}

func TestClient_Command_Approve(t *testing.T) {
	cmds := &fakeCommandsRecording{result: "approved"}
	srv := startServer(t, session.ServerConfig{Commands: cmds})

	c, err := session.Dial(socketOf(t, srv))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	ack, err := c.Command("approve", 42, "")
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	if ack.Result != "approved" {
		t.Errorf("Result = %q, want %q", ack.Result, "approved")
	}
	if ack.EscalationID != 42 {
		t.Errorf("EscalationID = %d, want 42", ack.EscalationID)
	}
	if len(cmds.calls) != 1 || cmds.calls[0].action != "approve" || cmds.calls[0].id != 42 {
		t.Errorf("server didn't see expected call: %+v", cmds.calls)
	}
}

func TestClient_Command_Deny_NotFound(t *testing.T) {
	cmds := &fakeCommandsRecording{result: "not_found"}
	srv := startServer(t, session.ServerConfig{Commands: cmds})

	c, err := session.Dial(socketOf(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ack, err := c.Command("deny", 999, "")
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	if ack.Result != "not_found" {
		t.Errorf("Result = %q, want %q", ack.Result, "not_found")
	}
}

func TestClient_Watch_ReceivesInitialListAndPushedEvent(t *testing.T) {
	lister := &fakeListerWithItems{
		items: []session.OutboundEscalation{
			{ID: 7, Operation: "read", Resource: "/secret", Status: "pending", Timestamp: "t0"},
		},
	}
	srv := startServer(t, session.ServerConfig{Lister: lister})

	c, err := session.Dial(socketOf(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type capture struct {
		responses []*session.OutboundResponse
		events    []*session.OutboundEscalationEvent
	}
	cap := &capture{}
	done := make(chan error, 1)

	go func() {
		done <- c.Watch(ctx, func(msg map[string]any) error {
			if r, ok := session.DecodeAsResponse(msg); ok {
				cap.responses = append(cap.responses, r)
				return nil
			}
			if e, ok := session.DecodeAsEvent(msg); ok {
				cap.events = append(cap.events, e)
				if len(cap.events) >= 1 {
					return errStopWatch // stops the loop cleanly
				}
			}
			return nil
		})
	}()

	// Wait for the initial response, then push an event.
	deadline := time.After(1 * time.Second)
	for {
		if len(cap.responses) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("never received initial response")
		case <-time.After(20 * time.Millisecond):
		}
	}
	srv.PushEscalation(session.OutboundEscalationEvent{
		Type:      "escalation",
		ID:        99,
		Operation: "exec",
		Resource:  "/bin/badbin",
		Status:    "pending",
	})

	err = <-done
	if err != errStopWatch && err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		t.Fatalf("Watch ended unexpectedly: %v", err)
	}

	if len(cap.responses) == 0 || len(cap.responses[0].Escalations) != 1 || cap.responses[0].Escalations[0].ID != 7 {
		t.Errorf("initial response missing or wrong: %+v", cap.responses)
	}
	if len(cap.events) == 0 || cap.events[0].ID != 99 {
		t.Errorf("pushed event not received: %+v", cap.events)
	}
}

var errStopWatch = errStopWatchT{}

type errStopWatchT struct{}

func (errStopWatchT) Error() string { return "stop watch" }

func TestListActiveSockets_FiltersStaleEntries(t *testing.T) {
	// Redirect HOME to a temp dir so SocketsDir() points at our fixture.
	// macOS sun_path is 104 bytes; t.TempDir under /var/folders/... is too
	// long, so use /tmp.
	tmpHome, err := os.MkdirTemp("/tmp", "rmpt-home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpHome) })
	t.Setenv("HOME", tmpHome)

	sessionsDir := filepath.Join(tmpHome, ".rampart", "sessions")
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Real listener at conventional/<pid>.sock for this test's lifetime.
	live := filepath.Join(sessionsDir, "12345.sock")
	srv := startServer(t, session.ServerConfig{SocketPath: live})
	_ = srv

	// Plant a stale socket file (regular file, no listener).
	stale := filepath.Join(sessionsDir, "99999.sock")
	if err := os.WriteFile(stale, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := session.ListActiveSockets()
	if err != nil {
		t.Fatalf("ListActiveSockets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d sockets, want 1 (stale filtered): %v", len(got), got)
	}
	if got[0] != live {
		t.Errorf("got %q, want %q", got[0], live)
	}
}

// socketOf returns the socket path the server is listening on. We rely on the
// test helper convention that ServerConfig.SocketPath was set by startServer
// (or, when unset there, it computed the default).
func socketOf(t *testing.T, _ *session.Server) string {
	// startServer assigns a tmpSock when cfg.SocketPath is empty. Since
	// startServer doesn't expose that path, mirror its logic here to keep
	// the tests independent: read it back from the server's state.
	// As a workable hack: tests above pass cfg.SocketPath explicitly when
	// they need it; this helper is used after startServer with no
	// explicit path. We re-derive by listing the latest /tmp/rmpt*/s.
	t.Helper()
	matches, err := filepath.Glob("/tmp/rmpt*/s")
	if err != nil || len(matches) == 0 {
		t.Fatalf("could not find tmp socket; matches=%v err=%v", matches, err)
	}
	// Newest by mtime.
	var newest string
	var newestMod time.Time
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if fi.ModTime().After(newestMod) {
			newestMod = fi.ModTime()
			newest = m
		}
	}
	if newest == "" {
		t.Fatal("no live tmp socket found")
	}
	return newest
}
