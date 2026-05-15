package main

import (
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// configureSlog routes rampart's diagnostic log lines (slog.Default()) away
// from the controlling TTY when an interactive agent owns it.
//
// When an interactive TUI like claude is rendering, rampart's INFO log
// lines to stderr would otherwise overwrite the agent's screen on every
// proxy CONNECT, session-socket event, etc. Routing those lines to a
// rotating per-PID file under ~/.rampart/logs/ keeps the TTY clean for
// the agent while preserving full diagnostics.
//
// Modes:
//   - Headless (CI, non-TTY, --headless): write to stderr only — there's
//     no TUI to clobber, and the user/CI expects to see logs there.
//   - Interactive (TTY, with or without tmux): write to file only; the
//     agent owns the TTY. --verbose ALSO mirrors to stderr.
//   - --dry-run / utility subcommands (escalations, list, etc.): do not
//     route. The default slog→stderr is fine; they don't share the TTY
//     with a long-running TUI.
//
// Returns the path of the log file (empty when no file was opened) and
// a close func the caller should defer.
func configureSlog(flags *runFlags) (logPath string, cleanup func()) {
	cleanup = func() {}

	mode := DetectMode(flags)
	if mode == ModeHeadless {
		// Default slog → stderr is already fine. Nothing to do.
		return "", cleanup
	}

	// Interactive mode: route to a per-PID file under ~/.rampart/logs/.
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to stderr; the agent will see some noise but at least
		// the log doesn't disappear.
		return "", cleanup
	}
	logDir := filepath.Join(home, ".rampart", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return "", cleanup
	}
	logPath = filepath.Join(logDir, fmt.Sprintf("%d-%s.log", os.Getpid(), time.Now().Format("20060102T150405")))
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return "", cleanup
	}

	var sink io.Writer = f
	if flags.verbose {
		// Mirror to stderr too; user explicitly opted in.
		sink = io.MultiWriter(f, os.Stderr)
	}

	handler := slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))

	// Also redirect Go's standard-library log package. Several libraries
	// rampart depends on bypass slog and write to log.Default() directly
	// — most visibly goproxy (`2026/05/12 23:08:10 [161] WARN: Error
	// copying to client: ...`), but also crypto/tls, net/http error
	// paths, etc. Without this redirect those lines land on stderr and
	// clobber the interactive agent's TUI hours after rampart started.
	// Save the previous output so cleanup can restore it; this matters
	// in tests that share the process with other code.
	prevLogOut := stdlog.Default().Writer()
	stdlog.SetOutput(sink)

	cleanup = func() {
		stdlog.SetOutput(prevLogOut)
		_ = f.Close()
	}
	return logPath, cleanup
}

// pruneOldLogs keeps the ~/.rampart/logs/ directory bounded. Best-effort:
// drops files older than 7 days; failures are silently ignored.
func pruneOldLogs() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	logDir := filepath.Join(home, ".rampart", "logs")
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(logDir, e.Name()))
		}
	}
}
