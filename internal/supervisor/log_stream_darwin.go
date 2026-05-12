//go:build darwin

package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"syscall"
)

// LogStreamer is a live source of sandbox-violation events for a child PID.
// Stream returns a channel that emits one event per parsed unified-log entry
// produced by `log stream` and remains open until ctx is cancelled or the
// subprocess exits, at which point the channel is closed.
type LogStreamer interface {
	Stream(ctx context.Context, pid int) (<-chan ViolationEvent, error)
}

// LogStreamCmd defaults to "/usr/bin/log". Tests may override to point at a
// fake binary that scripts ndjson lines on stdout.
var LogStreamCmd = []string{"/usr/bin/log"}

// realLogStreamer spawns `log stream --style ndjson --info --predicate
// 'subsystem == "com.apple.sandbox.reporting"'`, parses ndjson lines, and
// emits a ViolationEvent for every sandbox-reporting entry whose processID
// matches the supervised child.
//
// One subprocess per Stream call. The subprocess is bound to ctx via
// CommandContext so ctx cancellation kills the live tail without leaking.
type realLogStreamer struct {
	// Logger is the diagnostic sink. Defaults to slog.Default() when nil.
	Logger *slog.Logger
	// Cmd overrides the executable+args used for the subprocess (testing).
	// When nil, LogStreamCmd is used. The PID-specific predicate is appended
	// at Stream time.
	Cmd []string
}

// NewLogStreamer returns the production live-tail source.
func NewLogStreamer(logger *slog.Logger) LogStreamer {
	return &realLogStreamer{Logger: logger}
}

func (s *realLogStreamer) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *realLogStreamer) cmd() []string {
	if len(s.Cmd) > 0 {
		return s.Cmd
	}
	return LogStreamCmd
}

// streamRecord is the subset of `log stream --style ndjson` we read.
// The full schema is broader; we only need what feeds parseSandboxLogLine.
type streamRecord struct {
	EventMessage string `json:"eventMessage"`
	ProcessID    int    `json:"processID"`
	Subsystem    string `json:"subsystem"`
	EventType    string `json:"eventType"`
}

// Stream implements LogStreamer.
func (s *realLogStreamer) Stream(ctx context.Context, pid int) (<-chan ViolationEvent, error) {
	base := s.cmd()
	// The predicate must match BOTH paths the kernel takes for sandbox
	// denies:
	//   - subsystem == "com.apple.sandbox.reporting" — sandboxd-emitted
	//     entries (some macOS releases route certain denies through the
	//     sandbox daemon for telemetry).
	//   - eventMessage starting with "Sandbox: " — kernel-direct denies,
	//     where the log entry has processID == 0 (kernel) and an empty
	//     subsystem field but the eventMessage text contains both the
	//     violator's process name + PID and the operation + path. Modern
	//     macOS (Sequoia and later) emits most `deny default` events
	//     via this path.
	args := []string{
		"stream",
		"--style", "ndjson",
		"--info",
		"--predicate",
		`subsystem == "com.apple.sandbox.reporting" OR eventMessage BEGINSWITH "Sandbox: "`,
	}
	full := append([]string(nil), base[1:]...)
	full = append(full, args...)

	cmd := exec.CommandContext(ctx, base[0], full...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("log-stream stdout pipe: %w", err)
	}
	// Drain stderr — `log` writes the "Filtering the log data..." banner there
	// and may also emit warnings; discarding keeps the process from blocking
	// on a full stderr pipe buffer.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("log-stream start: %w", err)
	}

	// Look up the process group of the sandboxed child once at start. The
	// child and every descendant it spawns share this pgrp (Go's exec.Cmd
	// default inherits parent's pgid; the kernel preserves pgid across
	// fork/exec). Filtering on pgid instead of an exact PID match lets us
	// pick up sandbox denies from descendants — e.g. claude → bash →
	// python3 → xcrun, where the deny is emitted against python3's PID.
	// If the lookup fails (already-dead child / racy ctx cancel / test
	// fixture with synthetic PID) we record pgid=0 and the filter below
	// falls back to strict exact-PID matching. Note: macOS Getpgid
	// returns (-1, ESRCH) on miss, not (0, err) — must zero on error.
	pgid := 0
	if g, err := syscall.Getpgid(pid); err == nil {
		pgid = g
	}

	out := make(chan ViolationEvent, 16)
	go s.scanLoop(ctx, cmd, stdout, pid, pgid, out)
	return out, nil
}

// scanLoop reads ndjson from stdout, decodes streamRecord values, filters
// by pid, parses event messages, and forwards ViolationEvents. It closes
// `out` and reaps the subprocess on exit.
func (s *realLogStreamer) scanLoop(ctx context.Context, cmd *exec.Cmd, stdout io.ReadCloser, pid, pgid int, out chan<- ViolationEvent) {
	log := s.logger()

	defer func() {
		close(out)
		// CommandContext kills on ctx-done; Wait reaps the process.
		_ = cmd.Wait()
	}()

	sc := bufio.NewScanner(stdout)
	// `log stream` ndjson lines can be large (backtrace frames, image lists);
	// raise the line cap so we don't drop entries with bufio.ErrTooLong.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue // banner / non-json
		}
		var rec streamRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			// Malformed line — skip but keep streaming.
			continue
		}
		if rec.EventMessage == "" {
			continue
		}
		// Parse the violator PID + op + path out of the message text.
		// We can't trust rec.ProcessID — kernel-direct sandbox denies
		// (which is most of them on modern macOS) come tagged with
		// processID = 0 (kernel), and only the eventMessage carries
		// the real violator PID like "Sandbox: cat(34104) deny(1) ...".
		violatorPID, op, path, ok := parseSandboxLogLineFull(rec.EventMessage)
		if !ok {
			continue
		}
		// Filter: accept events from the sandboxed child or any
		// process in its process group. Descendants like
		// claude → bash → python3 → xcrun share pgid via the
		// kernel's fork-preserves-pgid rule.
		//
		// IMPORTANT race-handling: by the time we see a deny log
		// entry for a short-lived process (e.g. `cat`), the process
		// has typically already exited. syscall.Getpgid then returns
		// ESRCH. We must NOT treat ESRCH as "wrong process tree" —
		// that would silently drop every deny from a fast-exiting
		// command. Lookup failure → accept (the streamer's macOS
		// log predicate is already scoped to sandbox events, so the
		// false-positive surface is small).
		eventPID := violatorPID
		if eventPID == 0 {
			eventPID = rec.ProcessID
		}
		if eventPID != pid {
			if pgid == 0 {
				// We never established our supervised pgid (lookup
				// at startup failed — typical in tests with synthetic
				// PIDs). Fall back to strict exact-PID filtering so
				// stray events for unrelated processes don't leak.
				continue
			}
			// We DO know our pgid. Look up the violator's; if the
			// lookup succeeds and matches, accept (descendant). If
			// the lookup fails (ESRCH — short-lived violator that
			// already exited, which is the common case for things
			// like `cat /etc/foo` denied by Seatbelt) we accept too,
			// since we can't prove the event is unrelated and the
			// streamer's predicate has already narrowed to sandbox
			// events. Only confirmed mismatch drops.
			rpgid, err := syscall.Getpgid(eventPID)
			if err == nil && rpgid != pgid {
				continue
			}
		}
		ev := ViolationEvent{
			PID:      uint32(eventPID),
			Syscall:  op,
			Path:     path,
			Required: capFromOperation(op),
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
	if err := sc.Err(); err != nil && !strings.Contains(err.Error(), "file already closed") {
		log.Debug("log-stream scanner ended with error", "err", err)
	}
}
