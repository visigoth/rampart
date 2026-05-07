package main

import (
	"context"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/session"
	"github.com/visigoth/rampart/internal/supervisor"
)

// TestSessionBridge_PublishAllocatesUniqueIDs verifies that two consecutive
// Publish calls allocate distinct, monotonic escalation IDs. Routing back via
// HandleCommand uses these IDs, so collisions would cross-wire decisions.
func TestSessionBridge_PublishAllocatesUniqueIDs(t *testing.T) {
	srv := session.NewServer(session.ServerConfig{})
	b := newSessionBridge()
	b.attachServer(srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ev := supervisor.ViolationEvent{Path: "/etc/hosts", Required: supervisor.CapRead}
	_, err1 := b.Publish(ctx, ev)
	if err1 != nil {
		t.Fatalf("Publish 1: %v", err1)
	}
	_, err2 := b.Publish(ctx, ev)
	if err2 != nil {
		t.Fatalf("Publish 2: %v", err2)
	}

	if b.idCount.Load() != 2 {
		t.Errorf("idCount: got %d, want 2", b.idCount.Load())
	}
}

// TestSessionBridge_HandleCommandRoutesToWaitingChannel verifies that a command
// arriving on the socket is routed to the engine's per-escalation response
// channel registered by Publish.
func TestSessionBridge_HandleCommandRoutesToWaitingChannel(t *testing.T) {
	srv := session.NewServer(session.ServerConfig{})
	b := newSessionBridge()
	b.attachServer(srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := b.Publish(ctx, supervisor.ViolationEvent{Path: "/etc/hosts", Required: supervisor.CapRead})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	id := b.idCount.Load() // most recent allocated id
	result := b.HandleCommand("approve", id, "")
	if result != "approved" {
		t.Errorf("HandleCommand result: got %q, want %q", result, "approved")
	}

	select {
	case resp := <-ch:
		if resp.Action != "approve" {
			t.Errorf("response action: got %q, want %q", resp.Action, "approve")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("response not delivered to channel")
	}
}

// TestSessionBridge_HandleCommandUnknownIDIsNotFound verifies that a command
// for an escalation that was never published (or already resolved) returns
// "not_found" rather than panicking on the missing map entry.
func TestSessionBridge_HandleCommandUnknownIDIsNotFound(t *testing.T) {
	srv := session.NewServer(session.ServerConfig{})
	b := newSessionBridge()
	b.attachServer(srv)

	if got := b.HandleCommand("approve", 9999, ""); got != "not_found" {
		t.Errorf("unknown id: got %q, want %q", got, "not_found")
	}
}

// TestSessionBridge_PaneVisibleDelegatesToServer verifies the publisher
// forwards pane visibility to the underlying session.Server.
func TestSessionBridge_PaneVisibleDelegatesToServer(t *testing.T) {
	srv := session.NewServer(session.ServerConfig{})
	b := newSessionBridge()
	b.attachServer(srv)

	if b.PaneVisible() {
		t.Error("PaneVisible: expected false on a fresh server")
	}
}
