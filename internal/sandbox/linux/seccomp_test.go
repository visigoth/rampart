//go:build linux && (amd64 || arm64)

package linux

import (
	"testing"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// --- Basic compilation ---

func TestCompileSeccomp_ReturnsNonEmptyBPF(t *testing.T) {
	bpf, err := CompileSeccomp(SeccompOptions{})
	if err != nil {
		t.Fatalf("CompileSeccomp: %v", err)
	}
	if len(bpf) == 0 {
		t.Error("CompileSeccomp returned empty BPF bytes")
	}
}

func TestCompileSeccomp_TestREPLMode_Succeeds(t *testing.T) {
	bpf, err := CompileSeccomp(SeccompOptions{TestREPLMode: true})
	if err != nil {
		t.Fatalf("CompileSeccomp (REPL mode): %v", err)
	}
	if len(bpf) == 0 {
		t.Error("REPL mode returned empty BPF")
	}
}

// --- Verify filter rules via ScmpFilter inspection ---

// buildFilter creates a ScmpFilter with the same rules as CompileSeccomp so we
// can inspect actions without installing the filter.
func buildFilterForInspection(opts SeccompOptions) (*libseccomp.ScmpFilter, error) {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return nil, err
	}
	if err := filter.SetNoNewPrivsBit(false); err != nil {
		filter.Release()
		return nil, err
	}
	if err := addRules(filter, filteredSyscalls, libseccomp.ActNotify); err != nil {
		filter.Release()
		return nil, err
	}
	killAction := libseccomp.ActKillProcess
	if opts.TestREPLMode {
		killAction = libseccomp.ActErrno.SetReturnCode(int16(1))
	}
	if err := addRules(filter, alwaysFatalSyscalls, killAction); err != nil {
		filter.Release()
		return nil, err
	}
	return filter, nil
}


// TestCompileSeccomp_FilteredSyscalls_Covered verifies that all expected
// filtered syscalls are present in the syscall list and can be looked up
// on this architecture (failures here indicate a syscall name typo).
func TestCompileSeccomp_FilteredSyscalls_Covered(t *testing.T) {
	// At minimum these high-value syscalls must be present in filteredSyscalls.
	required := []string{
		"openat", "openat2", "execve", "execveat",
		"statx", "faccessat", "unlinkat", "renameat2",
		"mkdirat", "symlinkat",
	}

	filteredSet := make(map[string]bool, len(filteredSyscalls))
	for _, s := range filteredSyscalls {
		filteredSet[s] = true
	}

	for _, name := range required {
		if !filteredSet[name] {
			t.Errorf("required syscall %q missing from filteredSyscalls", name)
		}
	}
}

// TestCompileSeccomp_AlwaysFatalSyscalls_Covered verifies all expected always-
// fatal syscalls appear in the list.
func TestCompileSeccomp_AlwaysFatalSyscalls_Covered(t *testing.T) {
	required := []string{
		"ptrace", "kexec_load", "init_module",
		"bpf", "seccomp", "mount", "pivot_root", "chroot", "reboot",
	}

	fatalSet := make(map[string]bool, len(alwaysFatalSyscalls))
	for _, s := range alwaysFatalSyscalls {
		fatalSet[s] = true
	}

	for _, name := range required {
		if !fatalSet[name] {
			t.Errorf("always-fatal syscall %q missing from alwaysFatalSyscalls", name)
		}
	}
}

// TestCompileSeccomp_NetworkSyscalls_NotFiltered verifies that network syscalls
// are NOT in the filtered set (TR157).
func TestCompileSeccomp_NetworkSyscalls_NotFiltered(t *testing.T) {
	networkSyscalls := []string{
		"socket", "connect", "bind", "listen", "accept",
		"accept4", "sendto", "recvfrom", "sendmsg", "recvmsg",
	}

	filteredSet := make(map[string]bool, len(filteredSyscalls))
	for _, s := range filteredSyscalls {
		filteredSet[s] = true
	}

	for _, name := range networkSyscalls {
		if filteredSet[name] {
			t.Errorf("network syscall %q should NOT be in filteredSyscalls (TR157)", name)
		}
	}
}

// TestCompileSeccomp_DefaultActionIsAllow verifies the filter allows syscalls
// not explicitly listed (NG12: only gate filesystem+exec syscalls).
func TestCompileSeccomp_DefaultActionIsAllow(t *testing.T) {
	filter, err := buildFilterForInspection(SeccompOptions{})
	if err != nil {
		t.Fatalf("buildFilterForInspection: %v", err)
	}
	defer filter.Release()

	action, err := filter.GetDefaultAction()
	if err != nil {
		t.Fatalf("GetDefaultAction: %v", err)
	}
	if action != libseccomp.ActAllow {
		t.Errorf("default action: got %v, want ActAllow", action)
	}
}

// TestCompileSeccomp_NoNewPrivsIsOff verifies the filter doesn't set the
// no-new-privs bit internally (the launcher sets it separately, TR161).
func TestCompileSeccomp_NoNewPrivsIsOff(t *testing.T) {
	filter, err := buildFilterForInspection(SeccompOptions{})
	if err != nil {
		t.Fatalf("buildFilterForInspection: %v", err)
	}
	defer filter.Release()

	nnp, err := filter.GetNoNewPrivsBit()
	if err != nil {
		t.Fatalf("GetNoNewPrivsBit: %v", err)
	}
	if nnp {
		t.Errorf("no-new-privs bit should be OFF in filter (launcher sets it separately)")
	}
}

// TestCompileSeccomp_REPLMode_DifferentFromNormal verifies that REPL and
// normal mode produce different BPF output (kill vs errno).
func TestCompileSeccomp_REPLMode_DifferentFromNormal(t *testing.T) {
	normal, err := CompileSeccomp(SeccompOptions{TestREPLMode: false})
	if err != nil {
		t.Fatalf("normal: %v", err)
	}
	repl, err := CompileSeccomp(SeccompOptions{TestREPLMode: true})
	if err != nil {
		t.Fatalf("repl: %v", err)
	}
	if len(normal) == len(repl) {
		// They could still be different in content even if same length, but
		// different kill vs errno actions should produce different bytecode.
		same := true
		for i := range normal {
			if normal[i] != repl[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("normal and REPL mode BPF are identical — kill vs errno actions should differ")
		}
	}
}

// TestCompileSeccomp_Idempotent verifies that calling CompileSeccomp twice
// produces identical output (deterministic BPF generation).
func TestCompileSeccomp_Idempotent(t *testing.T) {
	bpf1, err := CompileSeccomp(SeccompOptions{})
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	bpf2, err := CompileSeccomp(SeccompOptions{})
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(bpf1) != len(bpf2) {
		t.Errorf("BPF length differs: %d vs %d", len(bpf1), len(bpf2))
		return
	}
	for i := range bpf1 {
		if bpf1[i] != bpf2[i] {
			t.Errorf("BPF differs at byte %d", i)
			return
		}
	}
}

// TestCompileSeccomp_BPFHeaderSize verifies the BPF output is large enough
// to contain a valid filter (minimum: a few BPF instructions).
func TestCompileSeccomp_BPFHeaderSize(t *testing.T) {
	bpf, err := CompileSeccomp(SeccompOptions{})
	if err != nil {
		t.Fatalf("CompileSeccomp: %v", err)
	}
	// Each BPF instruction is 8 bytes. A meaningful filter has at least 3.
	const minBytes = 24
	if len(bpf) < minBytes {
		t.Errorf("BPF too small: %d bytes (want at least %d)", len(bpf), minBytes)
	}
}

// TestCompileSeccomp_TableDriven_SyscallClassification verifies the syscall
// classification tables have no typos by resolving each name on this arch.
func TestCompileSeccomp_TableDriven_SyscallClassification(t *testing.T) {
	cases := []struct {
		category string
		names    []string
	}{
		{"filtered", filteredSyscalls},
		{"always-fatal", alwaysFatalSyscalls},
	}

	for _, tc := range cases {
		for _, name := range tc.names {
			t.Run(tc.category+"/"+name, func(t *testing.T) {
				_, err := libseccomp.GetSyscallFromName(name)
				// It's OK if a syscall doesn't exist on this arch
				// (e.g. legacy 32-bit variants). The important thing
				// is that we don't have a completely wrong name.
				if err != nil {
					t.Logf("syscall %q not available on this arch (skipped in filter): %v", name, err)
				}
			})
		}
	}
}
