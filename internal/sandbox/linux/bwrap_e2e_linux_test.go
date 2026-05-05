//go:build linux

// E2E tests for the Linux bubblewrap sandbox backend (.2.4).
//
// These tests build a ResolvedPolicy, compile it to bwrap flags via
// CompileBwrapFlags, then re-exec the test binary itself under bubblewrap.
// The re-exec helper (init below) performs file/network operations and
// exits, so the parent test process can observe enforcement behaviour from
// bwrap's exit status.
//
// Requires on the host:
//   - bwrap (bubblewrap) on PATH
//   - either unprivileged user namespaces enabled OR setuid bwrap OR
//     CAP_SYS_ADMIN (the rampart CI container provides the latter via
//     --cap-add=SYS_ADMIN — see .forgejo/workflows/rampart-test.yml).
//
// Tests skip cleanly when the host lacks user namespace support so dev
// machines with locked-down kernels don't see false failures.

package linux

import (
	"errors"
	"fmt"
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
	e2eOpEnv     = "RAMPART_BWRAP_E2E_OP"
	e2eTargetEnv = "RAMPART_BWRAP_E2E_TARGET"
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
// Exit codes: 0 = success, 2 = operation failed (EPERM, ENOENT, etc.).
func runE2EHelper(op, target string) {
	switch op {
	case "noop":
		os.Exit(0)
	case "pid":
		fmt.Printf("pid=%d\n", os.Getpid())
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

type bwrapResult struct {
	exitCode int
	signal   syscall.Signal // 0 if not signaled
	stdout   string
	stderr   string
}

func (r bwrapResult) signaled() bool { return r.signal != 0 }

// runBwrap exec's bwrap with the supplied policy-derived flags plus the
// test binary bound in as /test-helper, then runs that helper as the
// sandboxed target. Returns the WaitStatus.
func runBwrap(t *testing.T, bwrapFlags []string, op, target string) bwrapResult {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skipf("bwrap not available on PATH: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	resolvedExe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", exe, err)
	}

	args := append([]string{}, bwrapFlags...)
	// Make the test binary visible inside the sandbox at a stable path.
	args = append(args, "--ro-bind", resolvedExe, "/test-helper")
	args = append(args, "--", "/test-helper")

	cmd := exec.Command("bwrap", args...)
	cmd.Env = append(os.Environ(), e2eOpEnv+"="+op, e2eTargetEnv+"="+target)
	var errBuf, outBuf strings.Builder
	cmd.Stderr = &errBuf
	cmd.Stdout = &outBuf

	err = cmd.Run()
	res := bwrapResult{stdout: outBuf.String(), stderr: errBuf.String()}
	if err == nil {
		return res
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("run bwrap: %v\nstderr: %s", err, errBuf.String())
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

// userNamespacesAvailable reports whether unprivileged user namespaces are
// allowed on this host. bwrap's --unshare-all needs them unless bwrap is
// setuid or the process has CAP_SYS_ADMIN.
func userNamespacesAvailable() bool {
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		return strings.TrimSpace(string(b)) == "1"
	}
	// File missing on modern kernels (e.g., Debian bookworm) means the
	// sysctl was removed and unprivileged userns is unconditionally allowed.
	return true
}

// TestE2E_BwrapSmoke verifies bwrap can launch the test binary with the
// generated flags and the helper exits 0. Foundational E2E proving the flag
// sequence is well-formed end-to-end.
func TestE2E_BwrapSmoke(t *testing.T) {
	if !userNamespacesAvailable() {
		t.Skip("unprivileged user namespaces disabled on this host")
	}
	rp := &policy.ResolvedPolicy{Mode: "enforcing", NetworkMode: "none"}
	flags := CompileBwrapFlags(rp)

	res := runBwrap(t, flags, "noop", "")
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("noop helper failed: signal=%v exit=%d stderr=%s",
			res.signal, res.exitCode, res.stderr)
	}
}

// TestE2E_PIDNamespaceIsolation verifies that --unshare-all gives the child
// a fresh PID namespace where it sees itself as PID 1.
func TestE2E_PIDNamespaceIsolation(t *testing.T) {
	if !userNamespacesAvailable() {
		t.Skip("unprivileged user namespaces disabled on this host")
	}
	rp := &policy.ResolvedPolicy{Mode: "enforcing", NetworkMode: "none"}
	flags := CompileBwrapFlags(rp)

	res := runBwrap(t, flags, "pid", "")
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("pid helper failed: signal=%v exit=%d stdout=%s stderr=%s",
			res.signal, res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "pid=1\n") {
		t.Errorf("expected child to see pid=1 (PID namespace), got: %q", res.stdout)
	}
}

// TestE2E_NetworkNamespaceBlocksOutbound verifies that --unshare-all gives
// the child a fresh network namespace with only loopback. A dial to a
// remote address must fail because the sandbox has no outbound interface.
func TestE2E_NetworkNamespaceBlocksOutbound(t *testing.T) {
	if !userNamespacesAvailable() {
		t.Skip("unprivileged user namespaces disabled on this host")
	}
	rp := &policy.ResolvedPolicy{Mode: "enforcing", NetworkMode: "none"}
	flags := CompileBwrapFlags(rp)

	res := runBwrap(t, flags, "dial", "8.8.8.8:53")
	if res.signaled() {
		t.Fatalf("dial should fail with EHOSTUNREACH/ENETUNREACH, not signal: %v\nstderr=%s",
			res.signal, res.stderr)
	}
	if res.exitCode == 0 {
		t.Fatalf("dial to 8.8.8.8:53 from netns-isolated sandbox must fail; exit=0 stderr=%s",
			res.stderr)
	}
	if !strings.Contains(res.stderr, "dial:") {
		t.Errorf("expected helper to report dial error, stderr=%s", res.stderr)
	}
}

// TestE2E_ReadOnlyBindAllowsRead verifies that --ro-bind for a path in
// policy.Read makes that path readable inside the sandbox.
func TestE2E_ReadOnlyBindAllowsRead(t *testing.T) {
	if !userNamespacesAvailable() {
		t.Skip("unprivileged user namespaces disabled on this host")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		NetworkMode: "none",
		Read:        []string{src},
	}
	flags := CompileBwrapFlags(rp)

	res := runBwrap(t, flags, "read", src)
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("read of bound path should succeed: signal=%v exit=%d stderr=%s",
			res.signal, res.exitCode, res.stderr)
	}
}

// TestE2E_OutOfPolicyReadFails verifies that a path NOT in policy.Read is
// not bound into the sandbox mount namespace and is therefore inaccessible
// to the sandboxed process.
func TestE2E_OutOfPolicyReadFails(t *testing.T) {
	if !userNamespacesAvailable() {
		t.Skip("unprivileged user namespaces disabled on this host")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("private"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// Policy intentionally omits dir from Read.
	rp := &policy.ResolvedPolicy{Mode: "enforcing", NetworkMode: "none"}
	flags := CompileBwrapFlags(rp)

	res := runBwrap(t, flags, "read", src)
	if res.signaled() {
		t.Fatalf("read should fail with ENOENT, not signal: %v\nstderr=%s",
			res.signal, res.stderr)
	}
	if res.exitCode == 0 {
		t.Fatalf("read of unbound path must fail; exit=0 stderr=%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "read:") {
		t.Errorf("expected helper to report read error, stderr=%s", res.stderr)
	}
}

// TestE2E_WritableBindAllowsWrite verifies that --bind for a path in
// policy.Write makes that path read-write inside the sandbox.
func TestE2E_WritableBindAllowsWrite(t *testing.T) {
	if !userNamespacesAvailable() {
		t.Skip("unprivileged user namespaces disabled on this host")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")

	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		NetworkMode: "none",
		Write:       []string{dir},
	}
	flags := CompileBwrapFlags(rp)

	res := runBwrap(t, flags, "write", target)
	if res.signaled() || res.exitCode != 0 {
		t.Fatalf("write to bound dir should succeed: signal=%v exit=%d stderr=%s",
			res.signal, res.exitCode, res.stderr)
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "ok" {
		t.Fatalf("readback: %q err=%v", b, err)
	}
}
