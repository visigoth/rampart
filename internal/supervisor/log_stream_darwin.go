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
	args := []string{
		"stream",
		"--style", "ndjson",
		"--info",
		"--predicate", `subsystem == "com.apple.sandbox.reporting"`,
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

	out := make(chan ViolationEvent, 16)
	go s.scanLoop(ctx, cmd, stdout, pid, out)
	return out, nil
}

// scanLoop reads ndjson from stdout, decodes streamRecord values, filters
// by pid, parses event messages, and forwards ViolationEvents. It closes
// `out` and reaps the subprocess on exit.
func (s *realLogStreamer) scanLoop(ctx context.Context, cmd *exec.Cmd, stdout io.ReadCloser, pid int, out chan<- ViolationEvent) {
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
		if rec.ProcessID != pid {
			continue
		}
		if rec.Subsystem != "" && rec.Subsystem != "com.apple.sandbox.reporting" {
			continue
		}
		if rec.EventMessage == "" {
			continue
		}
		op, path, ok := parseSandboxLogLine(rec.EventMessage)
		if !ok {
			continue
		}
		ev := ViolationEvent{
			PID:      uint32(pid),
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
