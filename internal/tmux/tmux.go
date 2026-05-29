// Package tmux manages the rampart UI pane lifecycle (FT10).
//
// When the user is in tmux, rampart splits the current window to add a small
// escalation pane at the bottom. When not in tmux, rampart creates a new
// session with two panes and attaches to it.
//
// Design refs: .plans/rampart/features/local-channels.org FR44-FR47,
//              .plans/rampart/contracts/api6-tmux-control.org.
package tmux

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// PaneConfig holds the parameters for pane creation.
type PaneConfig struct {
	// PaneCommand is the command to run in the rampart UI pane (e.g.
	// "rampart escalations --watch").
	PaneCommand string

	// IdleLines is the number of lines for the idle rampart pane (default 3).
	IdleLines int

	// ActiveLines is the number of lines when the pane is expanded for a
	// prompt (default 6).
	ActiveLines int

	// NewSession forces creation of a new session even if already in tmux.
	NewSession bool

	// NewWindow creates a new window in the current session instead of
	// splitting the current window.
	NewWindow bool

	// Logger is the diagnostic sink. Defaults to slog.Default() if nil.
	Logger *slog.Logger

	// RunnerOverride is injectable for tests; defaults to realRunner when nil.
	RunnerOverride Runner
}

func (c *PaneConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *PaneConfig) idleLines() int {
	if c.IdleLines > 0 {
		return c.IdleLines
	}
	return 3
}

func (c *PaneConfig) activeLines() int {
	if c.ActiveLines > 0 {
		return c.ActiveLines
	}
	return 6
}

func (c *PaneConfig) getRunner() Runner {
	if c.RunnerOverride != nil {
		return c.RunnerOverride
	}
	return realRunner{}
}

// Pane represents a managed rampart escalation pane.
type Pane struct {
	// PaneID is the tmux pane identifier (e.g. "%5").
	PaneID string

	// SessionName is non-empty when rampart created the session (cleanup needed).
	SessionName string

	cfg PaneConfig
}

// Runner abstracts tmux subprocess invocation for testing.
type Runner interface {
	// Run executes args[0] with the rest as arguments and returns combined output.
	Run(args ...string) (string, error)
	// LookPath checks if tmux is installed.
	LookPath(name string) (string, error)
}

// realRunner executes real subprocess calls.
type realRunner struct{}

func (realRunner) Run(args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no command given")
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return strings.TrimRight(string(out), "\n"), err
}

func (realRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// Setup creates the rampart UI pane and returns a Pane handle.
// If tmux is not installed, returns ErrTmuxNotFound; callers should fall back
// to interactive-direct mode (TR117).
func Setup(cfg PaneConfig) (*Pane, error) {
	log := cfg.logger()
	r := cfg.getRunner()

	// Check tmux is installed (TR117).
	tmuxBin, err := r.LookPath("tmux")
	if err != nil {
		return nil, ErrTmuxNotFound
	}
	_ = tmuxBin

	inTmux := os.Getenv("TMUX") != ""

	paneCmd := cfg.PaneCommand
	if paneCmd == "" {
		paneCmd = "rampart escalations --watch"
	}

	idleLines := cfg.idleLines()
	sessionName := ""
	var paneID string

	if inTmux && !cfg.NewSession {
		if cfg.NewWindow {
			// Create a new window and split it. -d on the new-window means
			// "don't make it active"; tmux split-window -d below keeps focus
			// on the agent pane so the user's keystrokes drive claude, not
			// the watch pane.
			out, err := r.Run("tmux", "new-window", "-P", "-F", "#{pane_id}")
			if err != nil {
				return nil, fmt.Errorf("tmux new-window: %w", err)
			}
			mainPaneID := strings.TrimSpace(out)

			out, err = r.Run("tmux", "split-window", "-v", "-d",
				"-l", strconv.Itoa(idleLines),
				"-t", mainPaneID,
				"-P", "-F", "#{pane_id}",
				paneCmd)
			if err != nil {
				return nil, fmt.Errorf("tmux split-window (new-window): %w", err)
			}
			paneID = strings.TrimSpace(out)
		} else {
			// Split current window horizontally (bottom pane). -d keeps the
			// agent pane focused (without it, tmux would focus the watch
			// pane and user keystrokes would not reach claude).
			//
			// -t targets the pane we're running in via $TMUX_PANE. Without
			// it, tmux split-window defaults to the server's currently
			// active client, which can be a different session entirely
			// when the tmux server is shared across multiple sessions —
			// the split lands in the wrong window and never appears for
			// the user. $TMUX_PANE is set automatically by tmux for every
			// process running inside a pane.
			splitArgs := []string{"tmux", "split-window", "-v", "-d",
				"-l", strconv.Itoa(idleLines),
				"-P", "-F", "#{pane_id}"}
			if pane := os.Getenv("TMUX_PANE"); pane != "" {
				splitArgs = append(splitArgs, "-t", pane)
			}
			splitArgs = append(splitArgs, paneCmd)
			out, err := r.Run(splitArgs...)
			if err != nil {
				return nil, fmt.Errorf("tmux split-window: %w", err)
			}
			paneID = strings.TrimSpace(out)
		}
		log.Info("tmux: split current window", "pane_id", paneID)
	} else {
		// Create a new session.
		pid := os.Getpid()
		sessionName = fmt.Sprintf("rampart-%d", pid)

		// Get terminal dimensions for the new session.
		cols, lines := terminalSize(r)

		_, err := r.Run("tmux", "new-session", "-d",
			"-s", sessionName,
			"-x", strconv.Itoa(cols),
			"-y", strconv.Itoa(lines))
		if err != nil {
			return nil, fmt.Errorf("tmux new-session: %w", err)
		}

		// Split the session to add the rampart pane.
		out, err := r.Run("tmux", "split-window", "-v",
			"-l", strconv.Itoa(idleLines),
			"-t", sessionName,
			"-P", "-F", "#{pane_id}",
			paneCmd)
		if err != nil {
			// Clean up the session we just created.
			_, _ = r.Run("tmux", "kill-session", "-t", sessionName)
			return nil, fmt.Errorf("tmux split-window (new-session): %w", err)
		}
		paneID = strings.TrimSpace(out)

		// Select the main (top) pane so the agent sees it.
		_, _ = r.Run("tmux", "select-pane", "-t", sessionName+":0.0")

		log.Info("tmux: created new session", "session", sessionName, "pane_id", paneID)
	}

	return &Pane{
		PaneID:      paneID,
		SessionName: sessionName,
		cfg:         cfg,
	}, nil
}

// Expand resizes the pane to the active height for an escalation prompt (API6.2).
func (p *Pane) Expand() error {
	_, err := p.cfg.getRunner().Run("tmux", "resize-pane",
		"-t", p.PaneID,
		"-y", strconv.Itoa(p.cfg.activeLines()))
	if err != nil {
		return fmt.Errorf("tmux resize-pane expand: %w", err)
	}
	return nil
}

// Shrink resizes the pane back to idle height (API6.2).
func (p *Pane) Shrink() error {
	_, err := p.cfg.getRunner().Run("tmux", "resize-pane",
		"-t", p.PaneID,
		"-y", strconv.Itoa(p.cfg.idleLines()))
	if err != nil {
		return fmt.Errorf("tmux resize-pane shrink: %w", err)
	}
	return nil
}

// Close kills the pane and, if rampart created the session, kills the session
// too (TR122 / TR123).
func (p *Pane) Close() error {
	r := p.cfg.getRunner()
	if p.SessionName != "" {
		// Rampart created the session: kill the whole session (TR122).
		_, err := r.Run("tmux", "kill-session", "-t", p.SessionName)
		if err != nil {
			return fmt.Errorf("tmux kill-session: %w", err)
		}
		p.cfg.logger().Info("tmux: killed session", "session", p.SessionName)
	} else {
		// Rampart joined an existing session: only kill our pane (TR123).
		_, err := r.Run("tmux", "kill-pane", "-t", p.PaneID)
		if err != nil {
			return fmt.Errorf("tmux kill-pane: %w", err)
		}
		p.cfg.logger().Info("tmux: killed pane", "pane_id", p.PaneID)
	}
	return nil
}

// AttachSession runs tmux attach-session for a new-session setup. This replaces
// the current process image with the tmux client (like exec).
func (p *Pane) AttachSession() error {
	if p.SessionName == "" {
		return fmt.Errorf("no session to attach — pane joined existing session")
	}
	tmux, err := exec.LookPath("tmux")
	if err != nil {
		return fmt.Errorf("tmux not found: %w", err)
	}
	return syscallExec(tmux, []string{"tmux", "attach-session", "-t", p.SessionName})
}

// ErrTmuxNotFound is returned by Setup when tmux is not installed (TR117).
var ErrTmuxNotFound = fmt.Errorf("tmux not found — falling back to interactive-direct mode")

// terminalSize returns the current terminal dimensions, falling back to 220x50.
func terminalSize(r Runner) (cols, lines int) {
	out, err := r.Run("tput", "cols")
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil && n > 0 {
			cols = n
		}
	}
	out, err = r.Run("tput", "lines")
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil && n > 0 {
			lines = n
		}
	}
	if cols <= 0 {
		cols = 220
	}
	if lines <= 0 {
		lines = 50
	}
	return
}
