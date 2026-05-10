package session

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SocketsDir returns ~/.rampart/sessions, the conventional directory holding
// one Unix socket per active rampart supervisor (named <pid>.sock).
func SocketsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	return filepath.Join(home, ".rampart", "sessions"), nil
}

// ListActiveSockets returns every "<pid>.sock" file under ~/.rampart/sessions/
// whose Unix socket can be connected to. Stale entries from crashed
// supervisors are silently filtered; callers can clean them up separately.
// The returned slice is sorted by socket path so output is stable.
func ListActiveSockets() ([]string, error) {
	dir, err := SocketsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".sock" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if !canDial(path) {
			continue
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

// canDial attempts a short-timeout connect to verify the socket is alive.
func canDial(path string) bool {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Client is a thin NDJSON wrapper over the API2 Unix-socket protocol. One
// Client maps to one connection; callers create a new Client per operation.
type Client struct {
	conn net.Conn
	rd   *bufio.Reader
}

// Dial opens a connection to the given session socket path.
func Dial(path string) (*Client, error) {
	conn, err := net.DialTimeout("unix", path, 1*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", path, err)
	}
	return &Client{conn: conn, rd: bufio.NewReader(conn)}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// send writes one NDJSON message terminated by \n.
func (c *Client) send(msg InboundMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')
	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// readLine reads one NDJSON line from the server.
func (c *Client) readLine() ([]byte, error) {
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	// Trim the trailing newline; payload may also end without \n at EOF.
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	return line, nil
}

// List sends a query/list request and returns the server's response. The
// server echoes its current pending escalations in a single message.
func (c *Client) List() (*OutboundResponse, error) {
	if err := c.send(InboundMessage{Type: "query", Action: "list"}); err != nil {
		return nil, err
	}
	line, err := c.readLine()
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var resp OutboundResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w (raw: %s)", err, string(line))
	}
	return &resp, nil
}

// Command sends a command (approve/deny/persist) and returns the server's
// ack. action is "approve" | "deny" | "persist". For "persist", pattern is
// the path/glob to persist; ignored for approve/deny.
func (c *Client) Command(action string, escalationID int64, pattern string) (*OutboundAck, error) {
	msg := InboundMessage{
		Type:         "command",
		Action:       action,
		EscalationID: escalationID,
		Pattern:      pattern,
	}
	if err := c.send(msg); err != nil {
		return nil, err
	}
	line, err := c.readLine()
	if err != nil {
		return nil, fmt.Errorf("read ack: %w", err)
	}
	var ack OutboundAck
	if err := json.Unmarshal(line, &ack); err != nil {
		return nil, fmt.Errorf("unmarshal ack: %w (raw: %s)", err, string(line))
	}
	return &ack, nil
}

// Watch subscribes to escalation pushes. The server immediately sends the
// current pending list as the first message (an OutboundResponse), then
// streams OutboundEscalationEvent messages as new violations arrive.
//
// Each decoded message is delivered to the consumer via onMessage. Messages
// arrive as map[string]any so the consumer can dispatch on the "type" field;
// helpers DecodeAsResponse / DecodeAsEvent re-marshal to typed structs.
//
// Watch returns when ctx is cancelled, the connection closes, or onMessage
// returns a non-nil error.
func (c *Client) Watch(ctx context.Context, onMessage func(map[string]any) error) error {
	if err := c.send(InboundMessage{Type: "watch"}); err != nil {
		return err
	}

	// Run the read loop in a goroutine so ctx cancellation can interrupt
	// blocked reads via Close on the connection.
	type lineOrErr struct {
		line []byte
		err  error
	}
	ch := make(chan lineOrErr, 1)
	go func() {
		for {
			line, err := c.readLine()
			ch <- lineOrErr{line: line, err: err}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = c.Close()
			return ctx.Err()
		case le := <-ch:
			if le.err != nil {
				return le.err
			}
			var msg map[string]any
			if err := json.Unmarshal(le.line, &msg); err != nil {
				continue // skip malformed lines, keep reading
			}
			if err := onMessage(msg); err != nil {
				_ = c.Close()
				return err
			}
		}
	}
}

// DecodeAsResponse re-marshals a generic message map as an OutboundResponse.
// Returns ok=false if the message's type is not "response".
func DecodeAsResponse(msg map[string]any) (*OutboundResponse, bool) {
	if t, _ := msg["type"].(string); t != "response" {
		return nil, false
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, false
	}
	var r OutboundResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, false
	}
	return &r, true
}

// DecodeAsEvent re-marshals a generic message map as an OutboundEscalationEvent.
// Returns ok=false if the message's type is not "escalation".
func DecodeAsEvent(msg map[string]any) (*OutboundEscalationEvent, bool) {
	if t, _ := msg["type"].(string); t != "escalation" {
		return nil, false
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, false
	}
	var e OutboundEscalationEvent
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, false
	}
	return &e, true
}
