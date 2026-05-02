//go:build linux && (amd64 || arm64)

// This file implements CompileSeccomp (API1.5): build a seccomp BPF filter
// from a ResolvedPolicy (TR168). It uses libseccomp-golang (CGo) for portable
// BPF generation across x86_64 and aarch64 (TR169).
//
// Filter design (per TDD TR152-TR177):
//
//   - Default action: ALLOW (unfiltered syscalls pass through, NG12).
//   - Filtered syscalls: path-taking filesystem + exec syscalls → ActNotify
//     (USER_NOTIF). The supervisor decides per-path in userspace (TR158).
//   - Always-fatal syscalls: privilege-escalation-class → ActKillProcess (TR159).
//   - Test REPL mode: swaps ActKillProcess for ActErrno(EPERM) (TR160).
//
// Network syscalls are NOT filtered; isolation is handled by bwrap's network
// namespace + iptables + proxy (TR157).
package linux

import (
	"fmt"
	"os"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// SeccompOptions configures filter compilation.
type SeccompOptions struct {
	// TestREPLMode replaces ActKillProcess with ActErrno(EPERM) for
	// always-fatal syscalls. Use in test REPL mode (FT17, TR160).
	TestREPLMode bool
}

// filteredSyscalls are the path-taking filesystem and exec syscalls that the
// supervisor must approve per TR153-TR156. Action: ActNotify (USER_NOTIF).
// Named by their string identifiers so lookup is portable across architectures.
var filteredSyscalls = []string{
	// Stat category (TR153)
	"fstatat", "newfstatat", "statx", "stat", "lstat",
	// Access category (TR153)
	"faccessat", "faccessat2", "access",
	// Symlink read (TR153)
	"readlinkat", "readlink",
	// Open-family: read or write depending on flags (TR153)
	"openat", "openat2", "open", "creat",
	// Unlink category (TR154)
	"unlinkat", "unlink", "rmdir",
	// Rename category (TR154)
	"renameat2", "renameat", "rename",
	// Link create (TR154)
	"linkat", "link", "symlinkat", "symlink",
	// Mkdir (TR154)
	"mkdirat", "mkdir",
	// Mknod (TR154)
	"mknodat", "mknod",
	// Chmod/Chown (TR155)
	"fchmodat", "fchmodat2", "fchownat", "chmod", "chown", "lchown",
	// Truncate (TR155)
	"truncate", "truncate64",
	// Exec (TR156)
	"execve", "execveat",
}

// alwaysFatalSyscalls are unconditionally killed via ActKillProcess (TR159).
// These syscalls have no legitimate use in the sandboxed agent.
var alwaysFatalSyscalls = []string{
	"ptrace",
	"kexec_load",
	"kexec_file_load",
	"init_module",
	"finit_module",
	"delete_module",
	"bpf",
	"seccomp",
	"mount",
	"umount2",
	"pivot_root",
	"chroot",
	"reboot",
	"sethostname",
	"setdomainname",
}

// CompileSeccomp builds a seccomp BPF filter from the given options.
// The compiled filter bytes can be loaded via syscall.SYS_SECCOMP or
// transferred to a launcher shim via Unix socket (TR170).
//
// The ResolvedPolicy parameter is reserved for future path-level hints;
// the current implementation applies uniform USER_NOTIF for all filtered
// syscalls — path resolution happens in the supervisor (TR163).
func CompileSeccomp(opts SeccompOptions) ([]byte, error) {
	// Default action: allow everything not explicitly filtered (NG12).
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return nil, fmt.Errorf("creating seccomp filter: %w", err)
	}
	defer filter.Release()

	// Disable no-new-privs here; the caller (launcher) sets it separately
	// before installing the filter (PR_SET_NO_NEW_PRIVS, TR161).
	if err := filter.SetNoNewPrivsBit(false); err != nil {
		return nil, fmt.Errorf("setting no-new-privs bit: %w", err)
	}

	// Add USER_NOTIF rules for path-taking syscalls.
	if err := addRules(filter, filteredSyscalls, libseccomp.ActNotify); err != nil {
		return nil, fmt.Errorf("adding filtered syscall rules: %w", err)
	}

	// Add KILL_PROCESS (or ERRNO in REPL mode) for always-fatal syscalls.
	killAction := libseccomp.ActKillProcess
	if opts.TestREPLMode {
		killAction = libseccomp.ActErrno.SetReturnCode(int16(1)) // EPERM=1
	}
	if err := addRules(filter, alwaysFatalSyscalls, killAction); err != nil {
		return nil, fmt.Errorf("adding always-fatal syscall rules: %w", err)
	}

	bpf, err := exportBPF(filter)
	if err != nil {
		return nil, fmt.Errorf("exporting BPF: %w", err)
	}
	return bpf, nil
}

// exportBPF exports the compiled BPF filter to a byte slice.
// It uses ExportBPF to a temp file because ExportBPFMem requires libseccomp
// >= 2.6.0 and we target 2.5.x (Debian 12 stable).
func exportBPF(filter *libseccomp.ScmpFilter) ([]byte, error) {
	f, err := os.CreateTemp("", "rampart-seccomp-*.bpf")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if err := filter.ExportBPF(f); err != nil {
		return nil, fmt.Errorf("ExportBPF: %w", err)
	}

	// Seek back and read the bytes.
	if _, err := f.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("seeking temp file: %w", err)
	}
	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat temp file: %w", err)
	}
	buf := make([]byte, stat.Size())
	if _, err := f.Read(buf); err != nil {
		return nil, fmt.Errorf("reading BPF bytes: %w", err)
	}
	return buf, nil
}

// addRules adds unconditional action rules for each named syscall.
// Syscalls that don't exist on the current architecture are skipped silently —
// this is expected when building for arm64 (e.g., i386 variants don't exist).
func addRules(filter *libseccomp.ScmpFilter, names []string, action libseccomp.ScmpAction) error {
	for _, name := range names {
		sc, err := libseccomp.GetSyscallFromName(name)
		if err != nil {
			// Syscall not present on this architecture — skip.
			continue
		}
		if err := filter.AddRule(sc, action); err != nil {
			return fmt.Errorf("adding rule for %s: %w", name, err)
		}
	}
	return nil
}
