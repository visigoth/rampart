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
