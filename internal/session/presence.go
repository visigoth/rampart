// Package session implements the per-rampart-session presence state and
// the session socket server (API2). It exposes a Subsystem that supervisors
// plug into their errgroup; external CLI tools connect to the socket to push
// presence events and issue escalation commands.
//
// Design refs: .plans/rampart/features/presence-detection.org FR39-FR45,
//              .plans/rampart/contracts/api2-session-socket.org.
package session

import (
	"os"
	"strings"
)

// PresenceState is ENT7: captures which authorization channels are reachable
// for the current rampart session. Updated by push events on the session socket
// and by the initial bootstrap from the process environment.
type PresenceState struct {
	// HasTTY is true when stdin is attached to a terminal (isatty check).
	HasTTY bool

	// InTmux is true when the session launched inside tmux ($TMUX set).
	InTmux bool

	// OverSSH is true when the session arrived via SSH ($SSH_CONNECTION set).
	OverSSH bool

	// Headless is true for CI/cron environments (no TTY, no tmux, no SSH, $CI set).
	Headless bool

	// PaneVisible is true when the rampart tmux pane is currently visible.
	// Updated by focus-in / focus-out presence events.
	PaneVisible bool
}

// ChannelKind describes the kind of channel available for escalation delivery.
type ChannelKind int

const (
	ChannelTerminal ChannelKind = iota // interactive terminal prompt
	ChannelRemote                      // Apprise / Slack / remote
	ChannelCLI                         // rampart escalations CLI
)

// AvailableChannels returns the channels this session can use for escalation
// delivery, based on current presence state.
func (ps PresenceState) AvailableChannels() []ChannelKind {
	ch := []ChannelKind{ChannelCLI, ChannelRemote} // always available
	if ps.HasTTY || ps.InTmux || ps.OverSSH {
		ch = append(ch, ChannelTerminal)
	}
	return ch
}

// BootstrapPresence determines the initial PresenceState from the process
// environment (FR39). It reads env vars and performs an isatty check.
func BootstrapPresence() PresenceState {
	var ps PresenceState

	// FR39.1: isatty(stdin)
	ps.HasTTY = isTerminal(os.Stdin)

	// FR39.2: $TMUX is set → inside tmux
	ps.InTmux = os.Getenv("TMUX") != ""

	// FR39.3: $SSH_CONNECTION is set → SSH session
	ps.OverSSH = os.Getenv("SSH_CONNECTION") != ""

	// FR39.4: CI environment → headless
	ps.Headless = isCI()

	// If running in tmux, the pane is initially considered visible.
	if ps.InTmux {
		ps.PaneVisible = true
	}

	return ps
}

// isCI returns true if well-known CI env vars are set (FR39.4).
func isCI() bool {
	for _, v := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "BUILDKITE", "JENKINS_URL"} {
		if val := os.Getenv(v); val != "" && strings.ToLower(val) != "false" && val != "0" {
			return true
		}
	}
	return false
}
