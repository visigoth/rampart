//go:build darwin

// E2E tests for the macOS Seatbelt backend (.1.2).
//
// These tests build a ResolvedPolicy, compile it to SBPL via CompileSBPL,
// then re-exec the test binary itself under /usr/bin/sandbox-exec with the
// generated profile. The re-exec helper (init below) performs file/network
// operations and exits, so the parent test process can observe enforcement
// behaviour from sandbox-exec's exit status.

package macos

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/policy"
)

const (
	e2eOpEnv     = "RAMPART_SBPL_E2E_OP"
	e2eTargetEnv = "RAMPART_SBPL_E2E_TARGET"
)

func init() {
	op := os.Getenv(e2eOpEnv)
	if op == "" {
		return
	}
	runE2EHelper(op, os.Getenv(e2eTargetEnv))
	// unreachable
}

// runE2EHelper performs the requested operation and exits the process.
// Exit codes: 0 = success, 2 = operation failed (EPERM, refused, etc.).
func runE2EHelper(op, target string) {
	switch op {
	case "noop":
		os.Exit(0)
	case "read":
		if _, err := os.ReadFile(target); err != nil {
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	case "write":
		if err := os.WriteFile(target, []byte("ok"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	case "dial":
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial: %v\n", err)
			os.Exit(2)
		}
		_ = c.Close()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown op: %s\n", op)
		os.Exit(2)
	}
}

type sandboxResult struct {
	exitCode int
	signal   syscall.Signal // 0 if not signaled
	stderr   string
}

// signaled reports whether the child was killed by a signal (rather than
// exiting normally). When true, exitCode is undefined.
func (r sandboxResult) signaled() bool { return r.signal != 0 }

// runSandboxedHelper sandbox-exec's the test binary itself, instructing it
// (via env vars) to perform op against target. Returns the WaitStatus.
func runSandboxedHelper(t *testing.T, sbpl, op, target string, params map[string]string) sandboxResult {
	t.Helper()

	exe := testBinaryPath(t)
	args := []string{"-p", sbpl}
	for k, v := range params {
		args = append(args, "-D", k+"="+v)
	}
	args = append(args, exe)

	cmd := exec.Command("/usr/bin/sandbox-exec", args...)
	// Inherit env then layer the helper instructions on top.
	cmd.Env = append(os.Environ(), e2eOpEnv+"="+op, e2eTargetEnv+"="+target)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	cmd.Stdout = io.Discard

	err := cmd.Run()
	res := sandboxResult{stderr: errBuf.String()}
	if err == nil {
		return res
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("run sandbox-exec: %v\nstderr: %s", err, errBuf.String())
	}
	ws := ee.Sys().(syscall.WaitStatus)
	if ws.Signaled() {
		res.signal = ws.Signal()
		res.exitCode = -1
		return res
	}
	res.exitCode = ws.ExitStatus()
	return res
}

func testBinaryPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", exe, err)
	}
	return resolved
}

// sandboxParams returns the -D parameter map for sandbox-exec covering all
// (param ...) references in the base template. CLAUDE_BIN_DIR points at the
// test binary's directory so the helper itself is process-exec'able.
func sandboxParams(t *testing.T, workdir string) map[string]string {
	t.Helper()
	exe := testBinaryPath(t)
	binDir := filepath.Dir(exe)

	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	tmp := os.Getenv("TMPDIR")
	if tmp == "" {
		tmp = "/tmp"
	}
	// Strip trailing slashes; sandbox subpath rules are precise.
	tmp = strings.TrimRight(tmp, "/")
	if t, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = t
	}
	if h, err := filepath.EvalSymlinks(home); err == nil {
		home = h
	}
	if w, err := filepath.EvalSymlinks(workdir); err == nil {
		workdir = w
	}
	return map[string]string{
		"HOME":           home,
		"WORKDIR":        workdir,
		"TMPDIR":         tmp,
		"CLAUDE_BIN_DIR": binDir,
	}
}

func compileOrFail(t *testing.T, rp *policy.ResolvedPolicy, testMode bool) string {
	t.Helper()
	s, err := CompileSBPL(rp, testMode)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	return s
}

// TestE2E_Smoke verifies that the generated SBPL produces a runnable sandbox:
// the helper starts, performs a noop, and exits 0. This proves SBPL parses
// and the base allowlist is sufficient for Go runtime startup.
func TestE2E_Smoke(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	wd := t.TempDir()
	rp := &policy.ResolvedPolicy{NetworkMode: "none"}
	sbpl := compileOrFail(t, rp, false)

	res := runSandboxedHelper(t, sbpl, "noop", "", sandboxParams(t, wd))
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("noop helper failed: signal=%v exit=%d stderr=%s\nSBPL:\n%s",
			res.signal, res.exitCode, res.stderr, sbpl)
	}
}

// TestE2E_NetworkFullAllowsDial verifies NetworkMode=full lets the helper
// dial an arbitrary local listener.
func TestE2E_NetworkFullAllowsDial(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	addr := startLocalListener(t)
	wd := t.TempDir()
	rp := &policy.ResolvedPolicy{NetworkMode: "full"}
	sbpl := compileOrFail(t, rp, false)

	res := runSandboxedHelper(t, sbpl, "dial", addr, sandboxParams(t, wd))
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("dial under network=full should succeed: signal=%v exit=%d stderr=%s",
			res.signal, res.exitCode, res.stderr)
	}
}

// TestE2E_NetworkNoneRefusesDial verifies that a dial to a disallowed
// destination under NetworkMode=none returns EPERM (manifested as a
// non-zero, non-signalled exit from the helper). SIGKILL on violation is
// enforced at the supervisor layer (FT7), not in SBPL itself.
func TestE2E_NetworkNoneRefusesDial(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	addr := startLocalListener(t)
	wd := t.TempDir()
	rp := &policy.ResolvedPolicy{NetworkMode: "none"}
	sbpl := compileOrFail(t, rp, false)

	res := runSandboxedHelper(t, sbpl, "dial", addr, sandboxParams(t, wd))
	if res.signaled() {
		t.Fatalf("dial should fail with EPERM, not be signaled: signal=%v stderr=%s",
			res.signal, res.stderr)
	}
	if res.exitCode == 0 {
		t.Fatalf("dial under network=none should fail with non-zero exit, got 0; stderr=%s",
			res.stderr)
	}
	if !strings.Contains(res.stderr, "dial:") {
		t.Errorf("expected helper to report dial error, stderr=%s", res.stderr)
	}
}

// TestE2E_DisallowedReadReturnsEPERM verifies that reading a path outside
// the base allowlist + policy grants returns EPERM rather than succeeding.
// We use /Library/Frameworks which exists on every macOS host but is not in
// rampart's base SBPL allowlist (only /Library/Apple is permitted).
func TestE2E_DisallowedReadReturnsEPERM(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	const denied = "/Library/Frameworks"
	if _, err := os.Stat(denied); err != nil {
		t.Skipf("%s not present on this host: %v", denied, err)
	}
	wd := t.TempDir()
	rp := &policy.ResolvedPolicy{NetworkMode: "none"}
	sbpl := compileOrFail(t, rp, false)

	res := runSandboxedHelper(t, sbpl, "read", denied, sandboxParams(t, wd))
	if res.signaled() {
		t.Fatalf("read should return EPERM, not signal: signal=%v stderr=%s",
			res.signal, res.stderr)
	}
	if res.exitCode == 0 {
		t.Fatalf("read of %s should be denied; helper exited 0; stderr=%s", denied, res.stderr)
	}
	if !strings.Contains(res.stderr, "read:") {
		t.Errorf("expected helper to report read error, stderr=%s", res.stderr)
	}
}

// TestE2E_TestModeBootsNormally verifies that test-mode SBPL still produces
// a runnable sandbox. Test mode is a placeholder for future divergence in
// enforcement strategy; today it produces the same SBPL as normal mode.
func TestE2E_TestModeBootsNormally(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	wd := t.TempDir()
	rp := &policy.ResolvedPolicy{NetworkMode: "none"}
	sbpl := compileOrFail(t, rp, true)

	res := runSandboxedHelper(t, sbpl, "noop", "", sandboxParams(t, wd))
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("test-mode noop helper failed: signal=%v exit=%d stderr=%s",
			res.signal, res.exitCode, res.stderr)
	}
}

// TestE2E_WorkdirReadWriteAllowed verifies the workdir param grants the
// helper read+write inside the working directory.
func TestE2E_WorkdirReadWriteAllowed(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	wd := t.TempDir()
	resolvedWd, err := filepath.EvalSymlinks(wd)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", wd, err)
	}
	target := filepath.Join(resolvedWd, "out.txt")
	rp := &policy.ResolvedPolicy{NetworkMode: "none"}
	sbpl := compileOrFail(t, rp, false)

	res := runSandboxedHelper(t, sbpl, "write", target, sandboxParams(t, wd))
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("write to workdir should succeed: signal=%v exit=%d stderr=%s",
			res.signal, res.exitCode, res.stderr)
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "ok" {
		t.Fatalf("workdir file readback: %q err=%v", b, err)
	}
}

// startLocalListener starts a TCP listener bound to 127.0.0.1:0 and returns
// its address. The listener is closed on test cleanup. The listener accepts
// and immediately closes connections so the helper's Dial returns promptly.
func startLocalListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}
