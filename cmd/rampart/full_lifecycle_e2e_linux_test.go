//go:build linux

// E2E test for : Linux parallel of .1.5's full session
// lifecycle from `rampart -- <agent>` through clean shutdown. Exercises the
// entire wiring chain in-process under bubblewrap:
//
//	loadPolicy → buildSandboxedCmd (real bwrap)
//	→ supervisor.Run with proxy/session-socket subsystems
//	→ child exits cleanly → all subsystems shut down → exit code 0.
//
// Linux Auth Engine note: auth_other.go currently returns nil for the
// engine and post-start hook on linux (the seccomp_unotify supervisor wiring
// is FT6 and lands separately). The lifecycle assertions still hold —
// proxy + session-socket are cross-platform and the supervisor's signal
// + cleanup paths run regardless of platform-specific subsystems.
//
// Runs in the .forgejo/workflows/rampart-test.yml CI container which
// provides bwrap + CAP_SYS_ADMIN. Skips cleanly on dev machines that lack
// unprivileged user namespaces or bwrap.

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// linuxUserNamespacesAvailable reports whether unprivileged user namespaces
// are usable. bwrap's --unshare-all needs them unless bwrap is setuid or the
// process has CAP_SYS_ADMIN (which the CI container provides).
func linuxUserNamespacesAvailable() bool {
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		return strings.TrimSpace(string(b)) == "1"
	}
	// File missing on modern kernels (e.g., Debian bookworm) means the sysctl
	// was removed and unprivileged userns is unconditionally allowed.
	return true
}

// linuxSandboxAvailable bundles every platform precondition the lifecycle
// test depends on. Tests call this and Skip cleanly when something is
// missing rather than producing flaky environment-dependent failures.
func linuxSandboxAvailable(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux-only: requires bwrap")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skipf("bwrap not on PATH (install bubblewrap): %v", err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain required to compile stub agent: %v", err)
	}
	if !linuxUserNamespacesAvailable() {
		t.Skip("unprivileged user namespaces disabled on this host")
	}
}

// TestE2E_FullSessionLifecycle_HappyPath_Linux is the linux mirror of the
// darwin happy-path test: rampart launches a stub agent under bwrap, the
// agent performs in-policy filesystem ops and exits 0, rampart returns
// exit code 0, and the session socket is unlinked on shutdown. Load-bearing
// wiring test — exercises loadPolicy → buildSandboxedCmd → supervisor.Run
// with the real proxy/session subsystems composed together.
func TestE2E_FullSessionLifecycle_HappyPath_Linux(t *testing.T) {
	linuxSandboxAvailable(t)

	resolvedWorkdir := makeE2ELifecycleEnv(t)
	stubBin := buildE2EStubAgent(t, resolvedWorkdir)

	sessionsDir := filepath.Join(os.Getenv("HOME"), ".rampart", "sessions")

	// The stub reads STUB_WORKDIR to know where to write its marker. Pass it
	// through rampart's --env so it propagates to the sandboxed child.
	flags := &runFlags{
		mode:     "enforcing",
		envVars:  []string{"STUB_WORKDIR=" + resolvedWorkdir},
		noTmux:   true,
		headless: true,
	}

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exitCode, err := runLaunch(ctx, flags, []string{stubBin}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runLaunch: %v\nstderr: %s", err, stderr.String())
	}
	if exitCode != 0 {
		t.Fatalf("exit code: got %d, want 0\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
	}

	// Stub agent must have run: marker file exists with expected content.
	marker := filepath.Join(resolvedWorkdir, "stub.touched")
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("stub-agent did not write marker (in-policy write failed?): %v\nstderr: %s",
			err, stderr.String())
	}
	if string(data) != "ok\n" {
		t.Errorf("marker content: got %q, want %q", string(data), "ok\n")
	}

	// Stub agent's stdout reached us via the supervisor's pipe.
	if !strings.Contains(stdout.String(), "stub-agent: wrote+read") {
		t.Errorf("stub-agent stdout not propagated: %q", stdout.String())
	}

	// TR97/TR98: session socket file must be unlinked after shutdown.
	if entries, err := os.ReadDir(sessionsDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".sock") {
				t.Errorf("session socket leaked after shutdown: %s", e.Name())
			}
		}
	}
}

// TestE2E_FullSessionLifecycle_SIGINTGracefulShutdown_Linux verifies that
// cancelling the supervisor context during a long-running child produces a
// graceful shutdown: the child is signalled, supervisor.Run returns, and the
// session socket is cleaned up. Asserts the supervisor's signal-handling
// path (TR48-TR51) works end-to-end with the bwrap-based wiring.
func TestE2E_FullSessionLifecycle_SIGINTGracefulShutdown_Linux(t *testing.T) {
	linuxSandboxAvailable(t)

	resolvedWorkdir := makeE2ELifecycleEnv(t)

	// /usr/bin/sleep is bound read-only by bwrap defaults via --ro-bind-try
	// /usr/lib (and the binary path itself isn't in the policy, so we need
	// to resolve and bind it). Build a stub that just sleeps — guarantees
	// the binary is in workdir which is bound read-write.
	sleepStubSrc := `package main

import "time"

func main() { time.Sleep(30 * time.Second) }
`
	srcDir := filepath.Join(resolvedWorkdir, "_sleep_src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir sleep src: %v", err)
	}
	srcPath := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(sleepStubSrc), 0o644); err != nil {
		t.Fatalf("write sleep src: %v", err)
	}
	sleepBin := filepath.Join(resolvedWorkdir, "sleep-stub")
	if out, err := exec.Command("go", "build", "-o", sleepBin, srcPath).CombinedOutput(); err != nil {
		t.Fatalf("go build sleep-stub: %v\n%s", err, out)
	}

	flags := &runFlags{
		mode:     "enforcing",
		noTmux:   true,
		headless: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		code int
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		var out, errOut bytes.Buffer
		code, runErr := runLaunch(ctx, flags, []string{sleepBin}, nil, &out, &errOut)
		resCh <- result{code: code, err: runErr}
	}()

	// Give the child time to start before signalling.
	time.Sleep(500 * time.Millisecond)

	cancel()

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("runLaunch returned err: %v", r.err)
		}
		_ = r.code
	case <-time.After(15 * time.Second):
		_ = exec.Command("pkill", "-f", "sleep-stub").Run()
		t.Fatal("runLaunch did not return after context cancel within 15s")
	}

	sessionsDir := filepath.Join(os.Getenv("HOME"), ".rampart", "sessions")
	if entries, err := os.ReadDir(sessionsDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".sock") {
				t.Errorf("session socket leaked after SIGINT: %s", e.Name())
			}
		}
	}
}

// TestE2E_FullSessionLifecycle_BinaryViaExec_Linux covers the same flow as
// HappyPath_Linux but invokes the real rampart binary as a subprocess (rather
// than runLaunch in-process). This proves the cobra → main → runLaunch path
// is wired correctly end-to-end on linux and that exitWithCode propagates
// the supervisor's exit code to the OS.
func TestE2E_FullSessionLifecycle_BinaryViaExec_Linux(t *testing.T) {
	linuxSandboxAvailable(t)

	binDir, err := os.MkdirTemp("/tmp", "ramp-bin")
	if err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(binDir) })
	rampartBin := filepath.Join(binDir, "rampart")

	build := exec.Command("go", "build", "-o", rampartBin, "github.com/visigoth/rampart/cmd/rampart")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build rampart: %v\n%s", err, out)
	}

	resolvedWorkdir := makeE2ELifecycleEnv(t)
	stubBin := buildE2EStubAgent(t, resolvedWorkdir)

	cmd := exec.Command(rampartBin, "--no-tmux", "--headless",
		"--env", "STUB_WORKDIR="+resolvedWorkdir,
		"--", stubBin)
	cmd.Dir = resolvedWorkdir
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"))

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rampart binary exited with error: %v\nstdout: %s\nstderr: %s",
				err, out.String(), errOut.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Signal(syscall.SIGKILL)
		t.Fatal("rampart binary did not exit within 30s")
	}

	if !strings.Contains(out.String(), "stub-agent: wrote+read") {
		t.Errorf("stub-agent stdout not propagated through binary:\nstdout: %s\nstderr: %s",
			out.String(), errOut.String())
	}

	marker := filepath.Join(resolvedWorkdir, "stub.touched")
	if _, err := os.ReadFile(marker); err != nil {
		t.Errorf("stub-agent marker missing: %v", err)
	}
}
