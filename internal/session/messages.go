package session

// msg types for API2 ndjson protocol.
//
// All messages have a "type" discriminator field. Inbound messages arrive from
// external CLI tools; outbound messages are sent to subscribers.

// InboundMessage is a discriminated union of all messages the server accepts.
type InboundMessage struct {
	Type   string `json:"type"`   // "presence" | "query" | "command"
	Event  string `json:"event"`  // presence event type (API2.1)
	TTY    string `json:"tty"`    // optional tty path
	Client string `json:"client"` // "local" | "ssh"
	Action string `json:"action"` // query action or command action (API2.2 / API2.3)

	// Command fields (API2.3)
	EscalationID int64 `json:"escalation_id"`

	// Query/command
	Pattern string `json:"pattern,omitempty"` // for persist action
}

// OutboundEscalation is one item in a list-response payload (API2.4).
type OutboundEscalation struct {
	ID        int64  `json:"id"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// OutboundResponse is an API2.4 query response.
type OutboundResponse struct {
	Type        string               `json:"type"` // "response"
	Escalations []OutboundEscalation `json:"escalations"`
}

// OutboundAck is an API2.5 command acknowledgment.
type OutboundAck struct {
	Type          string `json:"type"`           // "ack"
	EscalationID  int64  `json:"escalation_id"`
	Result        string `json:"result"`         // "approved" | "denied" | "persisted" | "not_found" | "already_resolved"
}

// OutboundEscalationEvent is a push notification to --watch subscribers (API2.6).
type OutboundEscalationEvent struct {
	Type      string `json:"type"`      // "escalation"
	ID        int64  `json:"id"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Status    string `json:"status"`
}
