package session

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// CommandHandler is called by the server when a command message arrives from a
// subscriber. Returns the result string for the ack ("approved", "denied",
// "persisted", "not_found", "already_resolved").
type CommandHandler interface {
	HandleCommand(action string, escalationID int64, pattern string) string
}

// EscalationLister returns the current pending escalations for list queries.
type EscalationLister interface {
	ListEscalations() []OutboundEscalation
}

// ServerConfig holds the server's injectable dependencies.
type ServerConfig struct {
	// SocketPath is the Unix socket path. If empty, defaults to
	// ~/.rampart/sessions/<pid>.sock.
	SocketPath string

	// Presence is the initial PresenceState; updated by push events.
	Presence PresenceState

	// Commands handles approve/deny/persist commands from subscribers.
	// If nil, commands return "not_found".
	Commands CommandHandler

	// Lister provides the escalation list for query responses.
	// If nil, list responses return an empty slice.
	Lister EscalationLister

	// Logger is the diagnostic sink. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

func (c *ServerConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// DefaultSocketPath returns ~/.rampart/sessions/<pid>.sock.
func DefaultSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	dir := filepath.Join(home, ".rampart", "sessions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating session dir: %w", err)
	}
	return filepath.Join(dir, fmt.Sprintf("%d.sock", os.Getpid())), nil
}

// Server is a Subsystem that listens on the session Unix socket, accepts
// NDJSON message streams from subscribers, and handles presence events,
// escalation queries, and escalation commands per API2.
type Server struct {
	cfg         ServerConfig
	mu          sync.RWMutex
	presence    PresenceState
	subscribers []*subscriber
}

// NewServer creates a new session Server from the given config.
func NewServer(cfg ServerConfig) *Server {
	return &Server{
		cfg:      cfg,
		presence: cfg.Presence,
	}
}

// Name implements Subsystem.
func (s *Server) Name() string { return "session-socket" }

// Run implements Subsystem. It listens on the configured socket path, accepts
// connections, and processes messages until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	log := s.cfg.logger()

	socketPath := s.cfg.SocketPath
	if socketPath == "" {
		var err error
		socketPath, err = DefaultSocketPath()
		if err != nil {
			return fmt.Errorf("session socket path: %w", err)
		}
	}

	// Remove stale socket file if it belongs to a dead process (or just clean up).
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("session socket listen %s: %w", socketPath, err)
	}
	// Restrict to owner only (TR97-style security).
	_ = os.Chmod(socketPath, 0600)

	defer func() {
		ln.Close()
		_ = os.Remove(socketPath)
		log.Info("session socket closed", "path", socketPath)
	}()

	log.Info("session socket listening", "path", socketPath)

	// acceptLoop: accept connections until ctx is cancelled.
	connCh := make(chan net.Conn, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // ln.Close() called by defer
			}
			connCh <- conn
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case conn := <-connCh:
			sub := &subscriber{conn: conn}
			s.addSubscriber(sub)
			go s.handleConn(ctx, sub)
		}
	}
}

// Presence returns the current PresenceState (thread-safe).
func (s *Server) Presence() PresenceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.presence
}

// PushEscalation pushes an escalation event to all --watch subscribers.
func (s *Server) PushEscalation(ev OutboundEscalationEvent) {
	s.mu.RLock()
	subs := make([]*subscriber, len(s.subscribers))
	copy(subs, s.subscribers)
	s.mu.RUnlock()

	data, _ := json.Marshal(ev)
	data = append(data, '\n')
	for _, sub := range subs {
		if sub.watching {
			_, _ = sub.conn.Write(data)
		}
	}
}

func (s *Server) addSubscriber(sub *subscriber) {
	s.mu.Lock()
	s.subscribers = append(s.subscribers, sub)
	s.mu.Unlock()
}

func (s *Server) removeSubscriber(sub *subscriber) {
	s.mu.Lock()
	for i, ss := range s.subscribers {
		if ss == sub {
			s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

func (s *Server) handleConn(ctx context.Context, sub *subscriber) {
	log := s.cfg.logger()
	defer func() {
		sub.conn.Close()
		s.removeSubscriber(sub)
	}()

	scanner := bufio.NewScanner(sub.conn)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := scanner.Bytes()
		var msg InboundMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Warn("session socket: invalid JSON", "err", err)
			continue
		}
		s.dispatch(sub, msg)
	}
}

func (s *Server) dispatch(sub *subscriber, msg InboundMessage) {
	log := s.cfg.logger()
	switch msg.Type {
	case "presence":
		s.handlePresence(msg)
	case "query":
		s.handleQuery(sub, msg)
	case "command":
		s.handleCommand(sub, msg)
	case "watch":
		sub.watching = true
		log.Info("session socket: subscriber watching escalations")
		// Send current pending escalations on subscribe.
		s.sendList(sub)
	default:
		log.Warn("session socket: unknown message type", "type", msg.Type)
	}
}

func (s *Server) handlePresence(msg InboundMessage) {
	log := s.cfg.logger()
	s.mu.Lock()
	switch msg.Event {
	case "focus-in":
		s.presence.PaneVisible = true
	case "focus-out":
		s.presence.PaneVisible = false
	case "session-start":
		if msg.Client == "ssh" {
			s.presence.OverSSH = true
		}
		if msg.TTY != "" {
			s.presence.HasTTY = true
		}
	case "session-end":
		// session-end doesn't necessarily mean TTY gone; just log it.
	default:
		log.Warn("session socket: unknown presence event", "event", msg.Event)
	}
	s.mu.Unlock()
	log.Info("session socket: presence updated", "event", msg.Event)
}

func (s *Server) handleQuery(sub *subscriber, msg InboundMessage) {
	if msg.Action == "list" {
		s.sendList(sub)
	}
}

func (s *Server) sendList(sub *subscriber) {
	var escalations []OutboundEscalation
	if s.cfg.Lister != nil {
		escalations = s.cfg.Lister.ListEscalations()
	}
	if escalations == nil {
		escalations = []OutboundEscalation{}
	}
	resp := OutboundResponse{Type: "response", Escalations: escalations}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = sub.conn.Write(data)
}

func (s *Server) handleCommand(sub *subscriber, msg InboundMessage) {
	result := "not_found"
	if s.cfg.Commands != nil {
		result = s.cfg.Commands.HandleCommand(msg.Action, msg.EscalationID, msg.Pattern)
	}
	ack := OutboundAck{
		Type:         "ack",
		EscalationID: msg.EscalationID,
		Result:       result,
	}
	data, _ := json.Marshal(ack)
	data = append(data, '\n')
	_, _ = sub.conn.Write(data)
}

// subscriber tracks one connected client.
type subscriber struct {
	conn    net.Conn
	watching bool // true if subscribed to escalation pushes
}

// PaneVisible implements supervisor.SocketPublisher.PaneVisible for wiring
// into the authorization engine.
func (s *Server) PaneVisible() bool {
	return s.Presence().PaneVisible
}
