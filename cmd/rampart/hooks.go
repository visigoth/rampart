package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Marker strings used to identify managed hook sections in config files.
// Installing hooks twice is idempotent: the section is replaced, not duplicated.
const (
	tmuxHookBegin  = "# BEGIN rampart tmux hooks"
	tmuxHookEnd    = "# END rampart tmux hooks"
	shellHookBegin = "# BEGIN rampart shell hooks"
	shellHookEnd   = "# END rampart shell hooks"
)

// tmuxHookSnippet returns the snippet to append to ~/.tmux.conf.
// The hooks push focus-in/focus-out presence events to $RAMPART_SESSION_SOCK
// when a tmux client attaches or detaches. Best-effort: silently ignored if
// $RAMPART_SESSION_SOCK is unset or the socket doesn't exist.
func tmuxHookSnippet() string {
	return tmuxHookBegin + `
# rampart presence hooks — push focus events to the active session socket.
# RAMPART_SESSION_SOCK is exported by rampart into the sandboxed environment.
set-hook -ga client-attached 'run-shell -b "rampart presence-push focus-in 2>/dev/null || true"'
set-hook -ga client-detached 'run-shell -b "rampart presence-push focus-out 2>/dev/null || true"'
` + tmuxHookEnd + "\n"
}

// shellLoginHookSnippet returns the snippet to append to ~/.bashrc or ~/.zshrc.
// When the shell starts inside a rampart session ($RAMPART_SESSION_SOCK set),
// it pushes a session-start presence event so the authorization engine knows
// a user shell is active (FR43).
func shellLoginHookSnippet() string {
	return shellHookBegin + `
# rampart shell hooks — push session-start when inside a rampart session.
if [ -n "${RAMPART_SESSION_SOCK:-}" ]; then
  rampart presence-push session-start 2>/dev/null || true
fi
` + shellHookEnd + "\n"
}

// installHooksToFile appends or replaces a managed hook section in the file
// at path. If path does not exist, it is created. The section is delimited by
// beginMarker and endMarker lines; subsequent calls replace the existing section
// rather than appending a duplicate (idempotent).
func installHooksToFile(path, snippet, beginMarker, endMarker string) error {
	var existing []byte
	var err error

	existing, err = os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	content := string(existing)
	begin := strings.Index(content, beginMarker)
	end := strings.Index(content, endMarker)

	var result string
	if begin >= 0 && end > begin {
		// Replace the existing managed section.
		result = content[:begin] + snippet + content[end+len(endMarker):]
		// Trim trailing newline from the part before our section and re-add one.
		after := strings.TrimLeft(result[begin+len(snippet):], "\n")
		result = result[:begin] + snippet
		if after != "" {
			result += "\n" + after
		}
	} else {
		// No existing section: append.
		if len(content) > 0 && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		result = content + "\n" + snippet
	}

	if err := atomicWriteFile(path, []byte(result), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// atomicWriteFile writes data to path via a temp file + rename.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".rampart.tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// installTmuxHooks appends (or replaces) the rampart tmux hook section in
// tmuxConfPath. Creates the file if it does not exist.
func installTmuxHooks(tmuxConfPath string) error {
	return installHooksToFile(tmuxConfPath, tmuxHookSnippet(), tmuxHookBegin, tmuxHookEnd)
}

// installShellHooks appends (or replaces) the rampart shell hook section in
// rcPath (e.g. ~/.bashrc or ~/.zshrc). Creates the file if it does not exist.
func installShellHooks(rcPath string) error {
	return installHooksToFile(rcPath, shellLoginHookSnippet(), shellHookBegin, shellHookEnd)
}

// defaultShellRCPath returns the user's preferred shell RC file path.
// Checks $SHELL to pick zsh vs. bash; falls back to ~/.bashrc.
func defaultShellRCPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	shell := filepath.Base(os.Getenv("SHELL"))
	if shell == "zsh" {
		return filepath.Join(home, ".zshrc"), nil
	}
	return filepath.Join(home, ".bashrc"), nil
}

// defaultTmuxConfPath returns ~/.tmux.conf.
func defaultTmuxConfPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	return filepath.Join(home, ".tmux.conf"), nil
}

// pushPresenceEvent writes a presence event to the Unix socket at sockPath.
// It is a best-effort write: errors are silently discarded.
func pushPresenceEvent(sockPath, event string) error {
	if sockPath == "" {
		return nil
	}
	// Check that the socket file exists before dialing.
	if fi, err := os.Stat(sockPath); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		return nil // best-effort
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	msg, _ := json.Marshal(map[string]string{"type": "presence", "event": event})
	msg = append(msg, '\n')
	_, _ = conn.Write(msg)
	return nil
}
