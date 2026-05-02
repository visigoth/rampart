// Escalation hook executor — runs a user-provided script for escalation notifications
// and decisions (API3, FR47-FR51). The hook receives JSON context on stdin and writes
// a JSON decision to stdout.
package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"sync/atomic"
	"time"
)

// PresenceState describes the user's interaction context at hook invocation time (ENT10).
// Injected into HookInput so hooks can decide whether to send a push notification.
type PresenceState struct {
	TmuxPane       bool `json:"tmux_pane"`       // rampart pane is visible
	PaneFocused    bool `json:"pane_focused"`    // pane is the active pane
	HasTTY         bool `json:"has_tty"`         // stdin is a TTY
	InTmux         bool `json:"in_tmux"`         // running inside a tmux session
	SSHSession     bool `json:"ssh_session"`     // connecting via SSH
	HookConfigured bool `json:"hook_configured"` // always true when hook runs
	Headless       bool `json:"headless"`        // no interactive channels attached
}

// PresenceProvider supplies the current PresenceState at hook invocation time.
// Implement this interface to inject live presence data into the hook input.
type PresenceProvider interface {
	PresenceState() PresenceState
}

// HookInput is the JSON payload sent to the escalation hook on stdin (ENT10, API3.1).
type HookInput struct {
	ID        int64         `json:"id"`
	Operation string        `json:"operation"`
	Resource  string        `json:"resource"`
	Agent     string        `json:"agent,omitempty"`
	Profile   string        `json:"profile,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Presence  PresenceState `json:"presence"`
}

// SubprocessHookExecutor implements HookExecutor by launching a user-provided
// script via os/exec and exchanging JSON over stdin/stdout (FR48).
//
// Validated at construction time (FR50.1): if the binary cannot be found,
// a warning is logged once and all subsequent invocations silently defer.
type SubprocessHookExecutor struct {
	// Command is the path to the hook script or binary.
	Command string
	// Timeout is the maximum time to wait for a hook response (FR49). Default: 60s.
	Timeout time.Duration
	// Agent and Profile are injected into every HookInput for context.
	Agent   string
	Profile string
	// Presence provides the current presence state. May be nil.
	Presence PresenceProvider

	logger     *slog.Logger
	idCounter  atomic.Int64
	startupErr error
}

// NewSubprocessHookExecutor creates an executor and validates the command path
// at startup (FR50.1). Logs a one-time warning if the binary cannot be found.
func NewSubprocessHookExecutor(cmd string, timeout time.Duration, logger *slog.Logger) *SubprocessHookExecutor {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	e := &SubprocessHookExecutor{
		Command: cmd,
		Timeout: timeout,
		logger:  logger,
	}
	if _, err := exec.LookPath(cmd); err != nil {
		e.startupErr = fmt.Errorf("hook command %q not found: %w", cmd, err)
		logger.Warn("hook command not found; all escalations will defer",
			"command", cmd, "err", err)
	}
	return e
}

// Invoke runs the hook subprocess, sends HookInput JSON on stdin, and parses the
// HookResponse JSON from stdout (FR48). Safe for concurrent calls.
//
// Fallback rules (API3.3):
//   - No/invalid JSON on stdout + exit 0 → defer
//   - Non-zero exit code → log + defer (TR95)
//   - Timeout → log + defer (FR49.1)
//   - Startup error (binary missing) → silent defer (TR94)
func (h *SubprocessHookExecutor) Invoke(ctx context.Context, evs []ViolationEvent) (HookResponse, error) {
	if h.startupErr != nil {
		return HookResponse{Action: "defer"}, nil
	}
	if len(evs) == 0 {
		return HookResponse{Action: "defer"}, nil
	}

	ev := evs[0]

	var ps PresenceState
	if h.Presence != nil {
		ps = h.Presence.PresenceState()
	}
	ps.HookConfigured = true

	input := HookInput{
		ID:        h.idCounter.Add(1),
		Operation: ev.Required.String(),
		Resource:  ev.Path,
		Agent:     h.Agent,
		Profile:   h.Profile,
		Timestamp: time.Now().UTC(),
		Presence:  ps,
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return HookResponse{Action: "defer"}, fmt.Errorf("marshaling hook input: %w", err)
	}

	hCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := exec.CommandContext(hCtx, h.Command)
	cmd.Stdin = bytes.NewReader(inputJSON)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()

	if stderrBuf.Len() > 0 {
		h.logger.Debug("hook stderr", "stderr", stderrBuf.String())
	}

	if runErr != nil {
		if hCtx.Err() != nil {
			h.logger.Warn("hook timed out; treating as defer", "timeout", h.Timeout, "command", h.Command)
		} else {
			h.logger.Warn("hook failed; treating as defer", "err", runErr, "command", h.Command)
		}
		return HookResponse{Action: "defer"}, nil
	}

	// Parse stdout JSON (API3.2). Invalid/empty JSON with exit 0 → defer (API3.3).
	var resp HookResponse
	if err := json.NewDecoder(&stdoutBuf).Decode(&resp); err != nil {
		return HookResponse{Action: "defer"}, nil
	}

	switch resp.Action {
	case "approve", "deny", "persist", "defer":
		return resp, nil
	default:
		return HookResponse{Action: "defer"}, nil
	}
}
