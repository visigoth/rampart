//go:build linux

// Package linux provides the Linux bubblewrap sandbox backend (FT5).
// It compiles a ResolvedPolicy into bwrap command-line flags.
package linux

import (
	"github.com/visigoth/rampart/internal/policy"
)

// defaultROBinds are paths always bound read-only for a functioning userspace.
var defaultROBinds = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/usr/share",
	"/etc/ssl",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/passwd",
	"/etc/group",
	"/etc/nsswitch.conf",
	"/etc/localtime",
}

// CompileBwrapFlags converts a ResolvedPolicy into a slice of bwrap argument
// strings. The returned slice does NOT include the target command — callers
// append " -- <cmd> [args...]" themselves.
//
// Baseline (FR25):
//   - --unshare-all        isolates mount, network, PID, user, IPC, UTS, cgroup
//   - --die-with-parent    child dies if supervisor exits
//   - --proc /proc         live /proc inside sandbox
//   - --dev /dev           minimal device nodes via bubblewrap
//   - --tmpfs /tmp         writable scratch space
//
// Policy-driven binds (FR25):
//   - --ro-bind src dst    for each path in policy.Read (exclusive of Write/Exec)
//   - --bind src dst       for each path in policy.Write or policy.Exec
//
// Environment (FR2.6):
//   - --setenv HTTP_PROXY  if network mode allows a proxy
//   - --setenv RAMPART_POLICY_MODE  enforcing | permissive
func CompileBwrapFlags(rp *policy.ResolvedPolicy) []string {
	var args []string

	// --- Namespace isolation baseline ---
	args = append(args,
		"--unshare-all",
		"--die-with-parent",
	)

	// --- Essential pseudo-filesystems (FR25.1) ---
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	)

	// --- Workdir (bind writable if set) ---
	if rp.Workdir != "" {
		args = append(args, "--bind", rp.Workdir, rp.Workdir)
	}

	// Build write-path and exec-path sets for fast lookup so we don't
	// double-bind paths that appear in both Read and Write.
	writeSet := make(map[string]bool, len(rp.Write)+len(rp.Exec))
	for _, p := range rp.Write {
		writeSet[p] = true
	}
	for _, p := range rp.Exec {
		writeSet[p] = true
	}

	// --- Read-only binds for read paths not in write set ---
	for _, p := range rp.Read {
		if !writeSet[p] {
			args = append(args, "--ro-bind", p, p)
		}
	}

	// --- Read-write binds for write paths ---
	// Dedup: exec paths may overlap with write paths.
	bindAdded := make(map[string]bool, len(rp.Write)+len(rp.Exec))
	for _, p := range rp.Write {
		if !bindAdded[p] {
			args = append(args, "--bind", p, p)
			bindAdded[p] = true
		}
	}
	// Exec paths: bind read-write (process execution needs read+exec bits, and
	// the containing directory is often needed writable for dynamic linkers).
	for _, p := range rp.Exec {
		if !bindAdded[p] {
			args = append(args, "--bind", p, p)
			bindAdded[p] = true
		}
	}

	// --- Default read-only userspace paths for a functional container ---
	for _, p := range defaultROBinds {
		args = append(args, "--ro-bind-try", p, p)
	}

	// --- Policy environment variables ---
	args = append(args,
		"--setenv", "RAMPART_POLICY_MODE", rp.Mode,
		"--setenv", "RAMPART_PROFILE", rp.ProfileName,
	)

	if rp.NetworkMode == "none" {
		// Inject a hard deny signal so the agent process knows why connections fail.
		args = append(args, "--setenv", "RAMPART_NET", "blocked")
	} else {
		args = append(args, "--setenv", "RAMPART_NET", rp.NetworkMode)
	}

	return args
}
