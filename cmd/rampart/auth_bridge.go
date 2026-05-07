package main

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/visigoth/rampart/internal/session"
	"github.com/visigoth/rampart/internal/supervisor"
)

// sessionBridge wires the authorization engine's SocketPublisher interface to
// the session.Server, and routes commands arriving on the socket back to the
// engine via per-escalation response channels.
//
// One bridge per supervisor session: it owns the monotonic ID counter and the
// in-flight escalation map. The engine publishes via Publish (allocating an
// ID and pushing an OutboundEscalationEvent); subscribers (e.g. `rampart
// escalations --watch`) reply with InboundMessage{Type:"command", ...} which
// the server hands to HandleCommand.
type sessionBridge struct {
	server  *session.Server
	idCount atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan supervisor.SocketResponse
}

func newSessionBridge() *sessionBridge {
	return &sessionBridge{
		pending: make(map[int64]chan supervisor.SocketResponse),
	}
}

// attachServer associates the bridge with its session.Server. Must be called
// before any Publish or PaneVisible call. Allows breaking the construction
// cycle: the bridge is registered as ServerConfig.Commands, and the freshly
// created Server is then handed back to the bridge here.
func (b *sessionBridge) attachServer(srv *session.Server) { b.server = srv }

// PaneVisible implements supervisor.SocketPublisher.
func (b *sessionBridge) PaneVisible() bool { return b.server.PaneVisible() }

// Publish implements supervisor.SocketPublisher.
func (b *sessionBridge) Publish(ctx context.Context, ev supervisor.ViolationEvent) (<-chan supervisor.SocketResponse, error) {
	id := b.idCount.Add(1)
	ch := make(chan supervisor.SocketResponse, 1)

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
func (b *sessionBridge) HandleCommand(action string, escalationID int64, pattern string) string {
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
	case ch <- supervisor.SocketResponse{Action: action, Pattern: pattern}:
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

var (
	_ supervisor.SocketPublisher = (*sessionBridge)(nil)
	_ session.CommandHandler     = (*sessionBridge)(nil)
)
