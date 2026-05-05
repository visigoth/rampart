// E2E (UX) test for the rampart tmux pane lifecycle (.2.3).
//
// Spins up a real tmux server on a dedicated socket (via tmux -L) so the test
// does not interfere with any tmux session the user has running. Uses the real
// tmux.Setup → Expand → Shrink → Close flow and asserts on the live tmux
// state (pane count, pane geometry) rather than mock invocations.
//
// Skips when the tmux binary is not on PATH so dev machines without tmux do
// not see false failures. The mocked tests in tmux_test.go cover argument
// shape; this test covers actual server interaction and FR44.1, FR44.4-FR44.6.

package tmux_test

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/tmux"
)

// tmuxServer manages a dedicated tmux server reachable via a -L socket name.
// All commands run against this socket so the test cannot disturb the user's
// tmux state.
type tmuxServer struct {
	t          *testing.T
	socketName string
}

func newTmuxServer(t *testing.T) *tmuxServer {
	t.Helper()
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skipf("tmux not installed: %v", err)
	}
	// Unique per-test name; tmux maps -L to a socket under /tmp/tmux-<uid>/.
	name := fmt.Sprintf("rampart-ux-%d", time.Now().UnixNano())
	srv := &tmuxServer{t: t, socketName: name}
	t.Cleanup(srv.killServer)
	return srv
}

// run executes a tmux command against the dedicated server.
func (s *tmuxServer) run(args ...string) (string, error) {
	full := append([]string{"-L", s.socketName}, args...)
	out, err := exec.Command("tmux", full...).CombinedOutput()
	return strings.TrimRight(string(out), "\n"), err
}

func (s *tmuxServer) mustRun(args ...string) string {
	s.t.Helper()
	out, err := s.run(args...)
	if err != nil {
		s.t.Fatalf("tmux %s failed: %v\noutput: %s", strings.Join(args, " "), err, out)
	}
	return out
}

// killServer tears down the tmux server even if some panes remain.
func (s *tmuxServer) killServer() {
	_, _ = s.run("kill-server")
}

// startSession creates a detached session inside the dedicated server and
// returns the session-name and the initial pane-id.
func (s *tmuxServer) startSession() (sessionName, paneID string) {
	s.t.Helper()
	sessionName = fmt.Sprintf("agent-%d", time.Now().UnixNano())
	s.mustRun("new-session", "-d", "-s", sessionName, "-x", "200", "-y", "50")
	paneID = s.mustRun("display-message", "-p", "-t", sessionName, "#{pane_id}")
	return sessionName, paneID
}

// listPanes returns the (paneID, height) pairs in the given session.
func (s *tmuxServer) listPanes(sessionName string) []paneInfo {
	s.t.Helper()
	out := s.mustRun("list-panes", "-t", sessionName, "-F", "#{pane_id}\t#{pane_height}")
	var panes []paneInfo
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			s.t.Fatalf("unexpected list-panes line: %q", line)
		}
		h, err := strconv.Atoi(parts[1])
		if err != nil {
			s.t.Fatalf("parse pane height %q: %v", parts[1], err)
		}
		panes = append(panes, paneInfo{id: parts[0], height: h})
	}
	return panes
}

type paneInfo struct {
	id     string
	height int
}

// runnerForServer wraps tmux invocations so they target the dedicated server
// (-L <socket-name>). It satisfies tmux.Runner so tmux.Setup talks to our
// isolated server rather than the user's default tmux.
type runnerForServer struct {
	srv *tmuxServer
}

func (r *runnerForServer) Run(args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no command given")
	}
	if args[0] == "tmux" {
		return r.srv.run(args[1:]...)
	}
	// tput and others run normally.
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return strings.TrimRight(string(out), "\n"), err
}

func (r *runnerForServer) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// TestUX_PaneLifecycle_RealTmux verifies pane creation, idle geometry, expand
// for an active prompt, shrink on resolution, and clean close — all against a
// real tmux server.
func TestUX_PaneLifecycle_RealTmux(t *testing.T) {
	srv := newTmuxServer(t)
	sessionName, agentPaneID := srv.startSession()

	// Sanity: brand-new session has exactly one pane (the "agent" pane).
	panes := srv.listPanes(sessionName)
	if len(panes) != 1 {
		t.Fatalf("expected 1 pane in fresh session, got %d", len(panes))
	}
	if panes[0].id != agentPaneID {
		t.Fatalf("first pane id = %q, want %q", panes[0].id, agentPaneID)
	}

	runner := &runnerForServer{srv: srv}
	// Simulate "we are inside tmux, talking to this session" so Setup takes the
	// split-current-window path.
	t.Setenv("TMUX", filepath.Join("/tmp", "fake-tmux-env"))

	// Set the active client target by selecting the agent pane so split-window
	// (which has no -t) lands inside this session.
	srv.mustRun("select-pane", "-t", agentPaneID)

	const idle = 4
	const active = 8
	pane, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand:    "cat", // long-lived no-op pane content
		IdleLines:      idle,
		ActiveLines:    active,
		RunnerOverride: runner,
	})
	if err != nil {
		t.Fatalf("tmux.Setup: %v", err)
	}
	if pane.PaneID == "" {
		t.Fatal("Setup returned empty PaneID")
	}
	if pane.SessionName != "" {
		t.Errorf("SessionName should be empty when joining existing session, got %q", pane.SessionName)
	}

	// AC: tmux pane created with expected layout (horizontal split).
	panes = srv.listPanes(sessionName)
	if len(panes) != 2 {
		t.Fatalf("expected 2 panes after Setup, got %d (%v)", len(panes), panes)
	}
	rampartPane := findPane(panes, pane.PaneID)
	if rampartPane == nil {
		t.Fatalf("rampart pane %q not found in %v", pane.PaneID, panes)
	}

	// AC: Pane resizes for prompt visibility (FR44.5).
	if err := pane.Expand(); err != nil {
		t.Fatalf("Expand: %v", err)
	}
	panes = srv.listPanes(sessionName)
	rampartPane = findPane(panes, pane.PaneID)
	if rampartPane == nil || rampartPane.height != active {
		t.Errorf("after Expand: pane height = %d, want %d", paneHeight(rampartPane), active)
	}

	// AC: pane shrinks back to idle after resolution (FR44.6).
	if err := pane.Shrink(); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	panes = srv.listPanes(sessionName)
	rampartPane = findPane(panes, pane.PaneID)
	if rampartPane == nil || rampartPane.height != idle {
		t.Errorf("after Shrink: pane height = %d, want %d", paneHeight(rampartPane), idle)
	}

	// AC: clean close — only the rampart pane goes away (TR123).
	if err := pane.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	panes = srv.listPanes(sessionName)
	if len(panes) != 1 {
		t.Errorf("after Close: expected 1 pane (agent), got %d (%v)", len(panes), panes)
	}
	if findPane(panes, pane.PaneID) != nil {
		t.Errorf("rampart pane %q still present after Close", pane.PaneID)
	}
	if findPane(panes, agentPaneID) == nil {
		t.Errorf("agent pane %q must still be present after Close", agentPaneID)
	}
}

// TestUX_PaneCreatedSession_KillsSessionOnClose verifies that when rampart
// creates the tmux session itself (TR122), Close kills the entire session so
// no detached server keeps running.
func TestUX_PaneCreatedSession_KillsSessionOnClose(t *testing.T) {
	srv := newTmuxServer(t)

	// No existing session — clear TMUX so Setup takes the new-session path.
	t.Setenv("TMUX", "")

	runner := &runnerForServer{srv: srv}
	pane, err := tmux.Setup(tmux.PaneConfig{
		PaneCommand:    "cat",
		IdleLines:      3,
		RunnerOverride: runner,
	})
	if err != nil {
		t.Fatalf("tmux.Setup: %v", err)
	}
	if pane.SessionName == "" {
		t.Fatal("expected SessionName to be set when rampart creates the session")
	}

	// Verify the session exists.
	if _, err := srv.run("has-session", "-t", pane.SessionName); err != nil {
		t.Fatalf("session %q should exist after Setup: %v", pane.SessionName, err)
	}

	if err := pane.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// has-session returns non-zero when the session is gone; that is success.
	if _, err := srv.run("has-session", "-t", pane.SessionName); err == nil {
		t.Errorf("session %q should be gone after Close (TR122)", pane.SessionName)
	}
}

func findPane(panes []paneInfo, id string) *paneInfo {
	for i := range panes {
		if panes[i].id == id {
			return &panes[i]
		}
	}
	return nil
}

func paneHeight(p *paneInfo) int {
	if p == nil {
		return -1
	}
	return p.height
}
