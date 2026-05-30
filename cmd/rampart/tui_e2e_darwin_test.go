//go:build darwin

// TUI end-to-end test: launch a full-screen TUI app under rampart, verify it
// painted its initial screen, then quit it cleanly.
//
// Drives a real rampart binary inside a pty (via virtui) rather than calling
// runLaunch in-process — TUI apps need a real PTY for their ioctl(2)
// queries and SIGWINCH handling. Skips when virtui or htop aren't on disk
// so the test is opt-in: present on a developer's mac, absent on Linux CI
// and bare-bones builders.
//
// What it asserts:
//
//   - htop's initial screen renders inside the sandbox (we look for two
//     distinctive markers — the "Load average:" header line and the "F10"
//     quit hint in the function-key footer).
//   - `q` cleanly exits htop and rampart returns the session to the parent.
//   - No EPERMs leaked to stderr (a smoke test that the bundled policy
//     grants the htop binary and its supporting reads).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// htopCandidates lists the absolute paths where htop is plausibly installed
// on macOS. We grant ALL of them in the test profile (paths that don't
// exist on this machine are inert in the policy) and skip the test if
// none of them resolve.
var htopCandidates = []string{
	"/opt/homebrew/bin/htop",
	"/usr/local/bin/htop",
}

func TestE2E_TUI_RendersUnderRampart(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only: requires /usr/bin/sandbox-exec")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}

	virtuiBin, err := exec.LookPath("virtui")
	if err != nil {
		t.Skipf("virtui not found on PATH (install via `brew install virtui` or skip): %v", err)
	}
	htopBin := firstExistingPath(htopCandidates)
	if htopBin == "" {
		t.Skipf("htop not found at any of %v (install via `brew install htop` or skip)", htopCandidates)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain required to build rampart for the test: %v", err)
	}

	// Build the rampart binary under test into a tmpdir so we exercise the
	// actual exec path the user installs from, not in-process runLaunch.
	rampartBin := buildRampartForE2E(t)

	// Self-contained .rampart/ that grants htop and the standard shell
	// surface. Lives in its own gitdir so FindGitRoot anchors here and
	// doesn't accidentally pick up the user's real .rampart/.
	gitDir := scaffoldTUIRampartConfig(t, htopBin)

	// Isolated HOME so the session socket and log dir don't collide with
	// the developer's normal rampart usage.
	homeDir := mustTempDir(t, "ramp-tui-home")
	t.Setenv("HOME", homeDir)

	// Per-test virtui socket so the test daemon doesn't fight with any
	// long-running virtui daemon the developer has up.
	socketPath := filepath.Join(mustTempDir(t, "ramp-tui-virtui"), "daemon.sock")
	t.Setenv("VIRTUI_SOCKET", socketPath)

	startVirtuiDaemon(t, virtuiBin, socketPath)

	// Spawn rampart wrapping htop under virtui's pty. --no-tmux forces
	// interactive-direct so the test doesn't need to negotiate a tmux
	// server (covered by a separate test).
	sessionID := virtuiRun(t, virtuiBin, virtuiRunOpts{
		dir:  gitDir,
		cols: 120,
		rows: 30,
		argv: []string{
			rampartBin,
			"--agent", "tui-test",
			"--profile", "tui-test/default",
			"--no-tls-mitm",
			"--no-tmux",
			"--mode", "enforcing",
			"--", htopBin,
		},
	})

	// Poll the screen until htop's distinctive layout markers appear, or
	// time out. 15s is generous — htop typically renders within 2s; the
	// extra headroom is for cold-cache exec under Seatbelt.
	waitForScreen(t, virtuiBin, sessionID, 15*time.Second, []string{
		"Load average",
		"F10",
	})

	// Quit htop with `q`. virtui's `press` resolves the keysym and sends
	// the corresponding byte sequence to the pty.
	if out, err := exec.Command(virtuiBin, "press", sessionID, "q").CombinedOutput(); err != nil {
		t.Fatalf("virtui press q: %v\n%s", err, out)
	}

	// Verify the session terminates cleanly within a few seconds. After
	// htop exits, rampart's supervisor tears down subsystems and the
	// session ends. virtui's `sessions show` reports `exited(N)` once
	// the child wait reaps the process.
	waitForSessionExit(t, virtuiBin, sessionID, 10*time.Second)
}

// TestE2E_TUI_TmuxWatchPaneTargeting drives the same TUI scenario but with
// rampart running inside a tmux session, so the supervisor takes the
// ModeInteractiveTmux path: it splits the current window to add a watch
// pane running `rampart escalations --watch`.
//
// The non-trivial behaviour being asserted is the fix in tmux.go that
// targets the split at `-t $TMUX_PANE`. Without that target, the split
// lands at the server's currently active client, which on a shared
// tmux socket can be a completely different session — so the watch
// pane silently never appears next to the agent. This test runs an
// isolated tmux server via `-L <socket>` so we can `list-panes -a`
// against it and assert:
//
//   - The agent pane is running rampart (wrapping htop).
//   - A second pane in the same window is running rampart's escalations
//     watcher.
//   - Nothing leaked into any OTHER session/window on the test server.
//
// Resolution of the bug surfaced by the virtui repro on 2026-05-28
// (commit cf80c86).
func TestE2E_TUI_TmuxWatchPaneTargeting(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only: requires /usr/bin/sandbox-exec")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}

	virtuiBin, err := exec.LookPath("virtui")
	if err != nil {
		t.Skipf("virtui not found on PATH: %v", err)
	}
	tmuxBin, err := exec.LookPath("tmux")
	if err != nil {
		t.Skipf("tmux not found on PATH: %v", err)
	}
	htopBin := firstExistingPath(htopCandidates)
	if htopBin == "" {
		t.Skipf("htop not found at any of %v", htopCandidates)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain required: %v", err)
	}

	rampartBin := buildRampartForE2E(t)
	gitDir := scaffoldTUIRampartConfig(t, htopBin)

	homeDir := mustTempDir(t, "ramp-tui-tmux-home")
	t.Setenv("HOME", homeDir)

	socketPath := filepath.Join(mustTempDir(t, "ramp-tui-tmux-virtui"), "daemon.sock")
	t.Setenv("VIRTUI_SOCKET", socketPath)
	startVirtuiDaemon(t, virtuiBin, socketPath)

	// Isolated tmux server. -L picks a socket name relative to
	// /tmp/tmux-<uid>/ which keeps this server entirely separate from
	// the developer's default server — `tmux list-panes -a` against
	// the test socket sees only what this test created.
	tmuxSocket := fmt.Sprintf("rampart-tui-test-%d", os.Getpid())
	t.Cleanup(func() {
		_ = exec.Command(tmuxBin, "-L", tmuxSocket, "kill-server").Run()
	})

	sessionName := "rampart-tui"
	// virtui spawns tmux as the session's shell. -A means "attach if
	// exists, create if not" — on a fresh isolated server the create
	// branch wins.
	sessionID := virtuiRun(t, virtuiBin, virtuiRunOpts{
		dir:  gitDir,
		cols: 140,
		rows: 40,
		argv: []string{tmuxBin, "-L", tmuxSocket, "new-session", "-A", "-s", sessionName},
	})

	// Wait for the tmux server to fully bring up the session and for the
	// pane's shell to be ready to accept input. We poll the server
	// directly via `list-panes` rather than scraping the screen — the
	// user's tmux.conf may render the status bar differently (or hide
	// it entirely), so screen content isn't a reliable signal.
	waitForTmuxPaneCount(t, tmuxBin, tmuxSocket, 1, 5*time.Second)
	// Brief pause for the shell to print its first prompt; without it
	// the virtui exec lands during shell init and is dropped.
	time.Sleep(500 * time.Millisecond)

	// Type the rampart launch into the tmux pane's shell. Note the
	// absence of --no-tmux: the supervisor will detect $TMUX and take
	// the ModeInteractiveTmux path, triggering tmux.Setup.
	cmd := fmt.Sprintf("%s --agent tui-test --profile tui-test/default --no-tls-mitm --mode enforcing --verbose -- %s\n",
		rampartBin, htopBin)
	if out, err := exec.Command(virtuiBin, "exec", sessionID, cmd).CombinedOutput(); err != nil {
		t.Fatalf("virtui exec rampart command: %v\n%s", err, out)
	}

	// Wait for htop to render inside the agent pane.
	waitForScreen(t, virtuiBin, sessionID, 20*time.Second, []string{
		"Load average",
		"F10",
	})

	// Inspect tmux's pane topology on the test socket. We expect the
	// agent pane (rampart wrapping htop) AND the watch pane (rampart
	// escalations --watch) BOTH in the same window, no other panes
	// anywhere on this server. The split happens during supervisor
	// startup, before htop's first frame, but tmux's bookkeeping can
	// lag by a few hundred ms; poll briefly before failing.
	defer func() {
		if t.Failed() {
			t.Logf("agent pane screen at failure:\n%s", captureScreen(virtuiBin, sessionID))
			// On failure, surface rampart's own log so we can see what
			// it actually decided. HOME is the per-test tmpdir, so the
			// log lives at <homeDir>/.rampart/logs/<pid>-*.log.
			logsDir := filepath.Join(homeDir, ".rampart", "logs")
			if entries, _ := os.ReadDir(logsDir); len(entries) > 0 {
				for _, e := range entries {
					data, err := os.ReadFile(filepath.Join(logsDir, e.Name()))
					if err != nil {
						continue
					}
					t.Logf("rampart log %s:\n%s", e.Name(), data)
				}
			} else {
				t.Logf("no rampart log directory found at %s", logsDir)
			}
		}
	}()
	waitForTmuxPaneCount(t, tmuxBin, tmuxSocket, 2, 5*time.Second)
	panes := listTmuxPanes(t, tmuxBin, tmuxSocket)

	var agentPane, watchPane *tmuxPane
	for i := range panes {
		p := &panes[i]
		switch {
		case strings.Contains(p.command, "rampart") && p.sessionName == sessionName:
			// Could be either pane — both are running rampart binaries.
			// Disambiguate by which one was the original (active when we
			// typed the command) vs the new split (was added later).
			if agentPane == nil {
				agentPane = p
			} else {
				watchPane = p
			}
		}
	}

	// Both panes must be in the same session+window. The bug we're
	// guarding against was the watch pane landing in some OTHER
	// session on the shared tmux server.
	if agentPane == nil || watchPane == nil {
		t.Fatalf("could not identify both panes:\n%s", formatPanes(panes))
	}
	if agentPane.sessionName != watchPane.sessionName {
		t.Errorf("watch pane is in session %q but agent pane is in session %q (split-window mistargeted)",
			watchPane.sessionName, agentPane.sessionName)
	}
	if agentPane.windowIndex != watchPane.windowIndex {
		t.Errorf("watch pane is in window %d but agent pane is in window %d (split landed in different window)",
			watchPane.windowIndex, agentPane.windowIndex)
	}

	// Quit htop. The watch pane will tear down with rampart's supervisor
	// shortly after htop's SIGCHLD; we observe this via tmux reporting
	// only one pane left (the original shell prompt).
	if out, err := exec.Command(virtuiBin, "press", sessionID, "q").CombinedOutput(); err != nil {
		t.Fatalf("virtui press q: %v\n%s", err, out)
	}

	// Wait for the watch pane to clean up. After rampart's supervisor
	// returns, the watch pane subsystem closes and tmux kills its pane.
	waitForTmuxPaneCount(t, tmuxBin, tmuxSocket, 1, 10*time.Second)
}

// --- tmux helpers ---

type tmuxPane struct {
	id          string
	sessionName string
	windowIndex int
	paneIndex   int
	command     string
}

func formatPanes(panes []tmuxPane) string {
	var sb strings.Builder
	for _, p := range panes {
		fmt.Fprintf(&sb, "  %s %s:%d.%d %s\n", p.id, p.sessionName, p.windowIndex, p.paneIndex, p.command)
	}
	return sb.String()
}

// listTmuxPanes runs `tmux -L <socket> list-panes -a` and parses the
// output. Returns nil on error so callers can retry; for fatal failures
// they should bail by checking len(result) directly.
func listTmuxPanes(t *testing.T, tmuxBin, socket string) []tmuxPane {
	t.Helper()
	out, err := exec.Command(tmuxBin, "-L", socket, "list-panes", "-a",
		"-F", "#{pane_id}|#{session_name}|#{window_index}|#{pane_index}|#{pane_current_command}",
	).Output()
	if err != nil {
		return nil
	}
	var panes []tmuxPane
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Split(line, "|")
		if len(parts) != 5 {
			continue
		}
		p := tmuxPane{
			id:          parts[0],
			sessionName: parts[1],
			command:     parts[4],
		}
		fmt.Sscanf(parts[2], "%d", &p.windowIndex)
		fmt.Sscanf(parts[3], "%d", &p.paneIndex)
		panes = append(panes, p)
	}
	return panes
}

// waitForTmuxPaneCount polls until the test tmux server reports exactly
// `want` panes, or the timeout elapses. Used after sending the quit
// keystroke to assert the watch pane was torn down.
func waitForTmuxPaneCount(t *testing.T, tmuxBin, socket string, want int, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()

	var last []tmuxPane
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("expected %d panes, still see %d after %v:\n%s",
				want, len(last), timeout, formatPanes(last))
		case <-tick.C:
			last = listTmuxPanes(t, tmuxBin, socket)
			if len(last) == want {
				return
			}
		}
	}
}

// --- helpers ---

// firstExistingPath returns the first path in `paths` that exists, or "".
func firstExistingPath(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// buildRampartForE2E builds the rampart binary at the current module head
// into a temp directory. Uses the same -ldflags that `just _test-rampart`
// applies (Info.plist sectcreate) so the resulting binary's auth-bridge
// path lines up with what the production install gets.
func buildRampartForE2E(t *testing.T) string {
	t.Helper()
	outDir := mustTempDir(t, "ramp-tui-bin")
	binPath := filepath.Join(outDir, "rampart")

	// Locate this package's directory (cmd/rampart) — go test cd's into
	// it, so PWD is already correct.
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	plistPath := filepath.Join(pwd, "Info.plist")
	ldflags := fmt.Sprintf(
		"-linkmode external -extldflags=-Wl,-sectcreate,__TEXT,__info_plist,%s",
		plistPath)

	cmd := exec.Command("go", "build", "-o", binPath, "-ldflags", ldflags, ".")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build rampart: %v\n%s", err, out)
	}
	return binPath
}

// scaffoldTUIRampartConfig writes a self-contained .rampart/ with an agent
// that explicitly grants the htop binary and the shell read surface htop
// needs to bootstrap (PATH dirs, /proc-equivalent system info paths on
// darwin live behind syscalls, not files).
//
// The agent uses the new schema (no `filesystem`/`network_mode` attrs —
// modes inferred from declarations). Returns the gitdir path.
func scaffoldTUIRampartConfig(t *testing.T, htopBin string) string {
	t.Helper()
	// Short tmp path: /tmp keeps the session socket sun_path under the
	// 104-byte darwin limit. /var/folders TempDir paths often exceed it.
	gitDir, err := os.MkdirTemp("/tmp", "ramp-tui")
	if err != nil {
		t.Fatalf("mkdir gitDir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(gitDir) })

	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	rampDir := filepath.Join(gitDir, ".rampart")
	if err := os.MkdirAll(filepath.Join(rampDir, "profiles", "tui-test"), 0o755); err != nil {
		t.Fatalf("mkdir .rampart: %v", err)
	}

	defaults := `defaults {
  default_agent   = "tui-test"
  default_profile = "tui-test/default"
}
`
	mustWrite(t, filepath.Join(rampDir, "defaults.hcl"), defaults)

	// Agent declares exec on htop + a broad read so the kernel can fetch
	// htop's binary, its dynamic libs, and PATH-scan dirs. Inferred mode
	// becomes read-write (because `exec` is present); proxy stays off
	// (no domains declared → network_mode = "none").
	agent := fmt.Sprintf(`agent "tui-test" {
  description = "Full-screen TUI under rampart"
  read        = ["/"]
  exec        = [%q]
  env         = ["PATH", "HOME", "USER", "TERM", "LANG", "SHELL", "TMPDIR", "LC_*"]
}
`, htopBin)
	mustWrite(t, filepath.Join(rampDir, "agents.hcl"), agent)

	// Profile mirrors the agent's request (intersection logic produces
	// the resolved grant). All htop candidate paths are listed so the
	// same scaffold works on Intel + Apple Silicon and on Linux brews.
	candidateExecs := make([]string, 0, len(htopCandidates))
	for _, c := range htopCandidates {
		candidateExecs = append(candidateExecs, fmt.Sprintf("    %q", c))
	}
	profile := fmt.Sprintf(`profile "default" {
  workdir = "."
  read    = ["/"]
  exec = [
%s,
    # Shell + linker + PATH probes htop's libc and dyld stub do at startup.
    "/usr/bin",
    "/bin",
    "/usr/lib",
    "/System/Library",
    "/private/etc",
  ]
  env = ["PATH", "HOME", "USER", "TERM", "LANG", "SHELL", "TMPDIR", "LC_*"]
}
`, strings.Join(candidateExecs, ",\n"))
	mustWrite(t, filepath.Join(rampDir, "profiles", "tui-test", "default.hcl"), profile)

	return gitDir
}

// startVirtuiDaemon starts a virtui daemon on the given socket path. The
// daemon is process-isolated from any developer-run daemon by the
// VIRTUI_SOCKET env var. Cleanup stops it after the test.
func startVirtuiDaemon(t *testing.T, virtuiBin, socketPath string) {
	t.Helper()
	cmd := exec.Command(virtuiBin, "daemon", "start", "--socket", socketPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("virtui daemon start: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		// Best-effort stop; the test framework will inevitably outlive
		// us if the daemon is wedged, and we don't want a stop failure
		// to mask the real test failure.
		_ = exec.Command(virtuiBin, "daemon", "stop", "--socket", socketPath).Run()
	})

	// Brief wait for the daemon to start accepting connections — start
	// reports synchronously on systems with fast fork, but on slow disks
	// the listen() can lag a few hundred ms.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command(virtuiBin, "daemon", "status", "--socket", socketPath).Run(); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("virtui daemon never became reachable at %s", socketPath)
}

type virtuiRunOpts struct {
	dir  string
	cols int
	rows int
	argv []string
}

// virtuiRun spawns a virtui session via `virtui run -j` and returns the
// allocated session ID. Registers a cleanup that kills the session on test
// exit so partial test failures don't leak processes.
func virtuiRun(t *testing.T, virtuiBin string, opts virtuiRunOpts) string {
	t.Helper()
	args := []string{
		"run", "-j",
		"--cols", fmt.Sprintf("%d", opts.cols),
		"--rows", fmt.Sprintf("%d", opts.rows),
	}
	if opts.dir != "" {
		args = append(args, "--dir", opts.dir)
	}
	args = append(args, opts.argv...)

	out, err := exec.Command(virtuiBin, args...).Output()
	if err != nil {
		t.Fatalf("virtui run: %v", err)
	}
	var resp struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode virtui run response: %v: %s", err, out)
	}
	if resp.SessionID == "" {
		t.Fatalf("virtui run returned empty session_id: %s", out)
	}
	t.Cleanup(func() {
		_ = exec.Command(virtuiBin, "kill", resp.SessionID).Run()
	})
	return resp.SessionID
}

// waitForScreen polls the session's rendered screen at 250ms intervals
// until every marker in `want` is present, or until the timeout elapses.
// On timeout, dumps the final screen for diagnostic context.
func waitForScreen(t *testing.T, virtuiBin, sessionID string, timeout time.Duration, want []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()

	var last string
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("screen never showed all of %v within %v\nlast screen:\n%s",
				want, timeout, last)
		case <-tick.C:
			last = captureScreen(virtuiBin, sessionID)
			allFound := true
			for _, m := range want {
				if !strings.Contains(last, m) {
					allFound = false
					break
				}
			}
			if allFound {
				return
			}
		}
	}
}

// captureScreen returns the current screen text of the virtui session.
// Errors are silently treated as empty strings; waitForScreen will retry.
func captureScreen(virtuiBin, sessionID string) string {
	out, err := exec.Command(virtuiBin, "screenshot", "-j", sessionID).Output()
	if err != nil {
		return ""
	}
	var resp struct {
		ScreenText string `json:"screen_text"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return ""
	}
	return resp.ScreenText
}

// waitForSessionExit polls `virtui sessions show -j` until the session
// reports `running: false`, or the timeout elapses. A failure here
// usually means rampart's supervisor didn't tear down after the child's
// SIGCHLD — or the child never received the quit byte and is still
// drawing. On timeout, includes the resolved exit code (if any) and the
// last screen state for diagnosis.
func waitForSessionExit(t *testing.T, virtuiBin, sessionID string, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			last := captureScreen(virtuiBin, sessionID)
			t.Fatalf("session %s did not exit within %v\nlast screen:\n%s",
				sessionID, timeout, last)
		case <-tick.C:
			out, err := exec.Command(virtuiBin, "sessions", "show", "-j", sessionID).Output()
			if err != nil {
				// `sessions show` returns non-zero once the daemon has
				// reaped and forgotten the session — treat as success.
				return
			}
			var resp struct {
				Sessions []struct {
					Running  bool `json:"running"`
					ExitCode int  `json:"exit_code"`
				} `json:"sessions"`
			}
			if err := json.Unmarshal(out, &resp); err != nil {
				continue
			}
			if len(resp.Sessions) == 0 {
				return // already removed
			}
			s := resp.Sessions[0]
			if !s.Running {
				if s.ExitCode != 0 {
					t.Errorf("session exited with code %d (expected 0)", s.ExitCode)
				}
				return
			}
		}
	}
}

// --- tiny conveniences ---

func mustTempDir(t *testing.T, pattern string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", pattern)
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
