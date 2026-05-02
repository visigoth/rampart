// Authorization engine reactor (COMP2, FT12).
//
// Engine is the central reactor for escalations. It receives ViolationEvents
// from platform monitors (Linux seccomp supervisor, macOS monitor), looks them
// up against the session cache and persisted approvals, fans out to the user
// via the session socket and escalation hook, and applies the final decision
// back to the platform monitor.
//
// Design: single reactor goroutine for state, per-escalation waiter goroutines
// for I/O (socket responses, hook subprocess, timeout). See TDD TR68-TR98.
package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EscalationState is the state machine state for an in-flight escalation (TR69).
type EscalationState int

const (
	StatePending       EscalationState = iota
	StateCheckingCache                 // looking up against session cache and persisted approvals
	StateAutoResolved                  // cache hit — auto-allowed without prompting
	StatePrompting                     // published to socket, waiting for user response
	StateApproved                      // allow once
	StatePersisted                     // allow + saved to config.json
	StateDenied                        // explicitly denied
	StateTimedOut                      // no response within timeout
)

// EscalationRecord is a persisted approval stored in config.json (ENT9).
type EscalationRecord struct {
	Operation   string    `json:"operation"`              // "stat", "read", "write", "exec"
	Pattern     string    `json:"pattern"`                // exact path or glob
	CreatedAt   time.Time `json:"created_at"`
	AgentName   string    `json:"agent_name,omitempty"`   // FR37.1
	ProfileName string    `json:"profile_name,omitempty"` // FR37.1
}

// resolutionAction is the outcome of an in-flight escalation.
type resolutionAction int

const (
	actionApprove resolutionAction = iota
	actionPersist
	actionDeny
	actionTimeout
	actionDefer // hook or socket asked to defer; not a final outcome
)

func actionFromString(s string) resolutionAction {
	switch s {
	case "approve":
		return actionApprove
	case "persist":
		return actionPersist
	case "deny":
		return actionDeny
	case "defer":
		return actionDefer
	default:
		return actionDeny
	}
}

// DecisionApplier applies a resolved decision to the platform monitor.
// On Linux this calls NotifRespond; on macOS this logs and updates cache.
type DecisionApplier interface {
	Apply(ev ViolationEvent, approved bool) error
}

// SocketPublisher publishes escalation events to all connected session socket
// watchers (TR74). PaneVisible reports whether the rampart tmux pane is
// currently visible (TR77).
type SocketPublisher interface {
	Publish(ctx context.Context, ev ViolationEvent) (<-chan SocketResponse, error)
	PaneVisible() bool
}

// SocketResponse is a response received from a session socket watcher.
type SocketResponse struct {
	Action  string // "approve", "deny", "persist", "defer"
	Pattern string // for "persist" — the approved glob pattern
}

// HookResponse is the JSON response from an escalation hook subprocess (API3).
type HookResponse struct {
	Action  string `json:"action"`            // "approve", "deny", "persist", "defer"
	Pattern string `json:"pattern,omitempty"` // for "persist"
}

// HookExecutor invokes the user's escalation hook subprocess (TR75-TR80).
type HookExecutor interface {
	Invoke(ctx context.Context, evs []ViolationEvent) (HookResponse, error)
}

// EngineConfig holds configuration and injectable dependencies for Engine.
type EngineConfig struct {
	// Enforcing: true = EPERM on deny; false = allow+log (permissive mode, TR83).
	Enforcing bool
	// HookDelay: time to wait before invoking hook when pane is visible (TR75).
	// Default: 5s.
	HookDelay time.Duration
	// HookDebounce: minimum interval between hook invocations for same pattern (TR88).
	// Default: 30s.
	HookDebounce time.Duration
	// Timeout: overall escalation timeout before auto-deny or auto-allow (TR90).
	// Default: 300s.
	Timeout time.Duration
	// Applier applies the final decision to the platform monitor. Required.
	Applier DecisionApplier
	// Publisher publishes escalations to session socket subscribers. May be nil.
	Publisher SocketPublisher
	// Hook is the escalation hook executor. May be nil if no hook configured.
	Hook HookExecutor
	// ConfigPath is the path to config.json for persisted approvals.
	// If empty, persistence is disabled.
	ConfigPath string
	// Logger is the diagnostic sink.
	Logger *slog.Logger
}

// cacheEntry is a session-scoped cached approval.
type cacheEntry struct {
	cap     Capability
	pattern string
}

// escalation is an in-flight authorization request.
type escalation struct {
	id      string // escalationKey(ev)
	ev      ViolationEvent
	state   EscalationState
	replies []chan<- Decision // all Authorize callers waiting on this escalation
}

// violationReq is the internal message sent from Authorize to the reactor.
type violationReq struct {
	ev    ViolationEvent
	reply chan<- Decision
}

// resolution is the internal message sent from a waiter goroutine to the reactor.
type resolution struct {
	id      string
	action  resolutionAction
	pattern string // for actionPersist — the approved glob pattern
}

// hookResult is returned by invokeHook via a channel.
type hookResult struct {
	action  resolutionAction
	pattern string
}

// persistedConfigFile is the JSON schema for config.json.
type persistedConfigFile struct {
	Approvals []EscalationRecord `json:"approvals"`
}

// Engine is the central authorization reactor for escalations (TR91).
// Call NewEngine to create, then Run(ctx) to start the reactor goroutine.
// Use Authorize to submit ViolationEvents; it blocks until a decision is made.
type Engine struct {
	cfg EngineConfig

	// violationsCh receives violation requests from Authorize.
	violationsCh chan violationReq
	// resCh receives resolutions from waiter goroutines.
	resCh chan resolution

	// escalations: in-flight state map. Protected by stateMu.
	stateMu     sync.RWMutex
	escalations map[string]*escalation

	// sessionCache: session-scoped approved capability+pattern pairs.
	// Protected by cacheMu (TR93).
	cacheMu      sync.RWMutex
	sessionCache []cacheEntry

	// persistedRecs: loaded from config.json at startup; read-only after Run.
	persistedRecs []EscalationRecord

	// hookLastInvoke: debounce tracking. Key: "cap:path". Protected by hookMu.
	hookMu         sync.Mutex
	hookLastInvoke map[string]time.Time
}

// NewEngine creates an Engine with the given config.
// Call Run(ctx) to start the reactor goroutine.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.HookDelay == 0 {
		cfg.HookDelay = 5 * time.Second
	}
	if cfg.HookDebounce == 0 {
		cfg.HookDebounce = 30 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 300 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Engine{
		cfg:            cfg,
		violationsCh:   make(chan violationReq),
		resCh:          make(chan resolution, 16),
		escalations:    make(map[string]*escalation),
		hookLastInvoke: make(map[string]time.Time),
	}
}

// Authorize submits a violation event and blocks until a decision is reached (TR69).
// Implements AuthEngine. Safe for concurrent calls from multiple goroutines.
func (e *Engine) Authorize(ctx context.Context, ev ViolationEvent) Decision {
	reply := make(chan Decision, 1)
	select {
	case e.violationsCh <- violationReq{ev: ev, reply: reply}:
	case <-ctx.Done():
		return Deny
	}
	select {
	case d := <-reply:
		return d
	case <-ctx.Done():
		return Deny
	}
}

// Run starts the reactor goroutine. Blocks until ctx is cancelled.
// Loads persisted approvals from config.json at startup; returns an error if
// config.json exists but cannot be parsed (corrupt file refuses startup).
func (e *Engine) Run(ctx context.Context) error {
	if err := e.loadPersistedRecs(); err != nil {
		return fmt.Errorf("startup: %w", err)
	}
	for {
		select {
		case req := <-e.violationsCh:
			e.handleIncoming(ctx, req)
		case res := <-e.resCh:
			e.handleResolution(res)
		case <-ctx.Done():
			e.denyPending()
			return nil
		}
	}
}

// handleIncoming processes a new violation request in the reactor goroutine.
func (e *Engine) handleIncoming(ctx context.Context, req violationReq) {
	key := escalationKey(req.ev)

	// Deduplication: if identical escalation is already PROMPTING, attach this
	// reply to the existing escalation (TR86).
	e.stateMu.Lock()
	if existing, ok := e.escalations[key]; ok && existing.state == StatePrompting {
		existing.replies = append(existing.replies, req.reply)
		e.stateMu.Unlock()
		return
	}
	e.stateMu.Unlock()

	// CHECKING_CACHE: look up session cache + persisted approvals.
	if d, ok := e.checkCache(req.ev); ok {
		req.reply <- d
		return
	}

	// PROMPTING: create escalation, spawn per-escalation waiter goroutine.
	esc := &escalation{
		id:      key,
		ev:      req.ev,
		state:   StatePrompting,
		replies: []chan<- Decision{req.reply},
	}
	e.stateMu.Lock()
	e.escalations[key] = esc
	e.stateMu.Unlock()

	go e.runWaiter(ctx, esc)
}

// handleResolution processes a resolution from a waiter goroutine in the reactor.
func (e *Engine) handleResolution(res resolution) {
	e.stateMu.Lock()
	esc, ok := e.escalations[res.id]
	if !ok {
		e.stateMu.Unlock()
		return
	}
	delete(e.escalations, res.id)
	e.stateMu.Unlock()

	approved := res.action == actionApprove || res.action == actionPersist

	switch res.action {
	case actionApprove:
		esc.state = StateApproved
	case actionPersist:
		esc.state = StatePersisted
		pattern := res.pattern
		if pattern == "" {
			pattern = esc.ev.Path
		}
		if err := e.persistApproval(esc.ev.Required, pattern); err != nil {
			e.cfg.Logger.Warn("failed to persist approval", "err", err, "path", esc.ev.Path)
		}
		// Populate session cache (TR73).
		e.cacheMu.Lock()
		e.sessionCache = append(e.sessionCache, cacheEntry{cap: esc.ev.Required, pattern: pattern})
		e.cacheMu.Unlock()
	case actionDeny:
		esc.state = StateDenied
	case actionTimeout:
		esc.state = StateTimedOut
	}

	// In permissive mode, denied/timed-out requests are still allowed + logged (TR83).
	finalApproved := approved
	if !approved && !e.cfg.Enforcing {
		finalApproved = true
		e.cfg.Logger.Info("permissive: allowing denied request",
			"path", esc.ev.Path, "cap", esc.ev.Required, "syscall", esc.ev.Syscall)
	}

	if err := e.cfg.Applier.Apply(esc.ev, finalApproved); err != nil {
		e.cfg.Logger.Warn("failed to apply decision", "err", err, "path", esc.ev.Path)
	}

	d := Deny
	if finalApproved {
		d = Allow
	}
	for _, ch := range esc.replies {
		ch <- d
	}
}

// denyPending sends Deny to all in-flight escalations when the engine shuts down.
func (e *Engine) denyPending() {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	for _, esc := range e.escalations {
		for _, ch := range esc.replies {
			ch <- Deny
		}
	}
}

// checkCache looks up the event against session cache then persisted records,
// respecting the capability hierarchy (TR71, TR71.1).
func (e *Engine) checkCache(ev ViolationEvent) (Decision, bool) {
	// Session cache check (TR71, step 1 & 2).
	e.cacheMu.RLock()
	for _, entry := range e.sessionCache {
		if satisfies(entry.cap, ev.Required) && (entry.pattern == ev.Path || matchGlob(entry.pattern, ev.Path)) {
			e.cacheMu.RUnlock()
			return Allow, true
		}
	}
	e.cacheMu.RUnlock()

	// Persisted records check (TR71, step 3 & 4). persistedRecs is read-only.
	for _, rec := range e.persistedRecs {
		cap := capFromString(rec.Operation)
		if satisfies(cap, ev.Required) && (rec.Pattern == ev.Path || matchGlob(rec.Pattern, ev.Path)) {
			// Populate session cache for fast future lookups (TR73).
			e.cacheMu.Lock()
			e.sessionCache = append(e.sessionCache, cacheEntry{cap: cap, pattern: rec.Pattern})
			e.cacheMu.Unlock()
			return Allow, true
		}
	}

	return Deny, false
}

// runWaiter is the per-escalation goroutine that handles socket publishing,
// hook invocation, and timeout (TR91). Sends a resolution to e.resCh when done.
func (e *Engine) runWaiter(ctx context.Context, esc *escalation) {
	wCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()

	// Always publish to session socket (TR74).
	var socketRespCh <-chan SocketResponse
	if e.cfg.Publisher != nil {
		if ch, err := e.cfg.Publisher.Publish(wCtx, esc.ev); err == nil {
			socketRespCh = ch
		} else {
			e.cfg.Logger.Warn("socket publish failed", "err", err, "path", esc.ev.Path)
		}
	}

	// Determine hook timing (TR75, TR76).
	paneVisible := e.cfg.Publisher != nil && e.cfg.Publisher.PaneVisible()
	var hookTimerCh <-chan time.Time
	if paneVisible {
		t := time.NewTimer(e.cfg.HookDelay)
		defer t.Stop()
		hookTimerCh = t.C
	} else {
		// Invoke hook immediately.
		ready := make(chan time.Time, 1)
		ready <- time.Now()
		hookTimerCh = ready
	}

	hookInvoked := false
	var hookRespCh <-chan hookResult

	for {
		select {
		case <-hookTimerCh:
			hookTimerCh = nil // don't re-trigger
			if !hookInvoked && e.cfg.Hook != nil {
				hookInvoked = true
				hookRespCh = e.invokeHook(wCtx, esc.ev)
			}

		case resp, ok := <-socketRespCh:
			if !ok {
				socketRespCh = nil
				continue
			}
			action := actionFromString(resp.Action)
			if action == actionDefer {
				continue
			}
			cancel() // cancel pending hook (TR80)
			e.resCh <- resolution{id: esc.id, action: action, pattern: resp.Pattern}
			return

		case hr, ok := <-hookRespCh:
			if !ok {
				hookRespCh = nil
				continue
			}
			if hr.action == actionDefer {
				hookRespCh = nil
				continue
			}
			cancel()
			e.resCh <- resolution{id: esc.id, action: hr.action, pattern: hr.pattern}
			return

		case <-wCtx.Done():
			if ctx.Err() != nil {
				// Parent context cancelled (engine shutting down) — deny.
				e.resCh <- resolution{id: esc.id, action: actionDeny}
			} else {
				// Per-escalation timeout (TR90).
				e.resCh <- resolution{id: esc.id, action: actionTimeout}
			}
			return
		}
	}
}

// invokeHook starts the hook subprocess in a goroutine and returns a channel
// that will receive exactly one hookResult (or be closed on error/defer).
// Respects the debounce window (TR88).
func (e *Engine) invokeHook(ctx context.Context, ev ViolationEvent) <-chan hookResult {
	ch := make(chan hookResult, 1)

	// Debounce check (TR88): suppress repeated invocations for the same pattern.
	key := ev.Required.String() + ":" + ev.Path
	e.hookMu.Lock()
	if last, ok := e.hookLastInvoke[key]; ok && time.Since(last) < e.cfg.HookDebounce {
		e.hookMu.Unlock()
		close(ch) // debounced — closed channel reads as (zero, false), treated as defer
		return ch
	}
	e.hookLastInvoke[key] = time.Now()
	e.hookMu.Unlock()

	go func() {
		defer close(ch)
		resp, err := e.cfg.Hook.Invoke(ctx, []ViolationEvent{ev})
		if err != nil {
			e.cfg.Logger.Warn("hook invocation failed", "err", err, "path", ev.Path)
			return // closed without sending = defer
		}
		action := actionFromString(resp.Action)
		if action == actionDefer {
			return
		}
		ch <- hookResult{action: action, pattern: resp.Pattern}
	}()

	return ch
}

// loadPersistedRecs reads EscalationRecords from config.json (TR71).
func (e *Engine) loadPersistedRecs() error {
	if e.cfg.ConfigPath == "" {
		return nil
	}
	data, err := os.ReadFile(e.cfg.ConfigPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	var cfg persistedConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}
	e.persistedRecs = cfg.Approvals
	return nil
}

// persistApproval appends a new EscalationRecord to config.json (TR85).
// Uses an atomic rename to avoid partial writes.
func (e *Engine) persistApproval(cap Capability, pattern string) error {
	if e.cfg.ConfigPath == "" {
		return nil
	}

	var cfg persistedConfigFile
	data, err := os.ReadFile(e.cfg.ConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading config: %w", err)
	}
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parsing config: %w", err)
		}
	}

	cfg.Approvals = append(cfg.Approvals, EscalationRecord{
		Operation: cap.String(),
		Pattern:   pattern,
		CreatedAt: time.Now(),
	})

	if err := os.MkdirAll(filepath.Dir(e.cfg.ConfigPath), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	tmpPath := e.cfg.ConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.Rename(tmpPath, e.cfg.ConfigPath); err != nil {
		return fmt.Errorf("renaming config: %w", err)
	}

	// Refresh in-memory slice.
	e.persistedRecs = cfg.Approvals
	return nil
}

// escalationKey builds the deduplication key for an escalation (TR86).
// Uses exact path (not a pattern) since deduplication is on exact resources.
func escalationKey(ev ViolationEvent) string {
	return ev.Required.String() + ":" + ev.Path
}
