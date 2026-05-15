package main

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

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
// the server hands to HandleCommand. The bridge also implements
// session.EscalationLister, so `rampart escalations` (no flags) and the
// auto-list a fresh `--watch` subscriber gets on connect see the same
// pending set the engine is currently waiting on.
type sessionBridge struct {
	server  *session.Server
	idCount atomic.Int64

	mu      sync.Mutex
	pending map[int64]*pendingEscalation
}

// pendingEscalation is the bridge's view of an in-flight escalation:
// what to send when the subscriber answers (resp), plus enough info to
// render a list entry to a late-joining subscriber.
type pendingEscalation struct {
	resp      chan supervisor.SocketResponse
	operation string
	resource  string
	createdAt time.Time
}

func newSessionBridge() *sessionBridge {
	return &sessionBridge{
		pending: make(map[int64]*pendingEscalation),
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

	operation := ev.Required.String()
	resource := ev.Path
	createdAt := time.Now()

	b.mu.Lock()
	b.pending[id] = &pendingEscalation{
		resp:      ch,
		operation: operation,
		resource:  resource,
		createdAt: createdAt,
	}
	b.mu.Unlock()

	b.server.PushEscalation(session.OutboundEscalationEvent{
		Type:      "escalation",
		ID:        id,
		Operation: operation,
		Resource:  resource,
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
	p, ok := b.pending[escalationID]
	if ok {
		delete(b.pending, escalationID)
	}
	b.mu.Unlock()
	if !ok {
		return "not_found"
	}
	select {
	case p.resp <- supervisor.SocketResponse{Action: action, Pattern: pattern}:
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

// ListEscalations implements session.EscalationLister. Returns a
// snapshot of every in-flight escalation sorted by ID (which is the
// monotonic creation order, since idCount only increases).
//
// Without this, `rampart escalations` (the list subcommand) and the
// auto-list a fresh `--watch` subscriber gets on subscribe both
// returned an empty list — the server's Lister was nil, so even when
// the engine was actively waiting on a decision, list queries
// reported "no pending escalations". That made the CLI feel broken
// even though pushes via PushEscalation (which doesn't go through
// the lister) were arriving correctly.
func (b *sessionBridge) ListEscalations() []session.OutboundEscalation {
	b.mu.Lock()
	out := make([]session.OutboundEscalation, 0, len(b.pending))
	for id, p := range b.pending {
		out = append(out, session.OutboundEscalation{
			ID:        id,
			Operation: p.operation,
			Resource:  p.resource,
			Status:    "pending",
			Timestamp: p.createdAt.UTC().Format(time.RFC3339),
		})
	}
	b.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

var (
	_ supervisor.SocketPublisher = (*sessionBridge)(nil)
	_ session.CommandHandler     = (*sessionBridge)(nil)
	_ session.EscalationLister   = (*sessionBridge)(nil)
)
