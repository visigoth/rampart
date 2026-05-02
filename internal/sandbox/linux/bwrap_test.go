//go:build linux

package linux

import (
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/policy"
)

// hasFlag returns true if args contains the exact string flag.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// hasPair returns true if args contains flag immediately followed by value.
func hasPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// hasBind returns true if args contains --bind or --ro-bind src dst.
func hasBind(args []string, src, dst string) bool {
	return hasPair3(args, "--bind", src, dst)
}

func hasROBind(args []string, src, dst string) bool {
	return hasPair3(args, "--ro-bind", src, dst)
}

func hasPair3(args []string, flag, a, b string) bool {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == flag && args[i+1] == a && args[i+2] == b {
			return true
		}
	}
	return false
}

// countOccurrences counts how many times val appears in args.
func countOccurrences(args []string, val string) int {
	n := 0
	for _, a := range args {
		if a == val {
			n++
		}
	}
	return n
}

func minimalPolicy() *policy.ResolvedPolicy {
	return &policy.ResolvedPolicy{
		AgentName:      "test-agent",
		ProfileName:    "test-profile",
		Mode:           "enforcing",
		FilesystemMode: "none",
		NetworkMode:    "none",
	}
}

// --- Baseline namespace flags ---

func TestCompileBwrapFlags_UnshareAllPresent(t *testing.T) {
	args := CompileBwrapFlags(minimalPolicy())
	if !hasFlag(args, "--unshare-all") {
		t.Errorf("--unshare-all not found in %v", args)
	}
}

func TestCompileBwrapFlags_DieWithParentPresent(t *testing.T) {
	args := CompileBwrapFlags(minimalPolicy())
	if !hasFlag(args, "--die-with-parent") {
		t.Errorf("--die-with-parent not found in %v", args)
	}
}

func TestCompileBwrapFlags_ProcDevTmpfs(t *testing.T) {
	args := CompileBwrapFlags(minimalPolicy())
	if !hasPair(args, "--proc", "/proc") {
		t.Errorf("--proc /proc not found in %v", args)
	}
	if !hasPair(args, "--dev", "/dev") {
		t.Errorf("--dev /dev not found in %v", args)
	}
	if !hasPair(args, "--tmpfs", "/tmp") {
		t.Errorf("--tmpfs /tmp not found in %v", args)
	}
}

// --- Read paths ---

func TestCompileBwrapFlags_ReadOnlyBinds(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		Read:        []string{"/etc/ssh", "/home/user/code"},
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	if !hasROBind(args, "/etc/ssh", "/etc/ssh") {
		t.Errorf("missing --ro-bind /etc/ssh /etc/ssh in %v", args)
	}
	if !hasROBind(args, "/home/user/code", "/home/user/code") {
		t.Errorf("missing --ro-bind /home/user/code /home/user/code in %v", args)
	}
}

// --- Write paths ---

func TestCompileBwrapFlags_WritableBinds(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		Write:       []string{"/home/user/code", "/tmp/build"},
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	if !hasBind(args, "/home/user/code", "/home/user/code") {
		t.Errorf("missing --bind /home/user/code /home/user/code in %v", args)
	}
	if !hasBind(args, "/tmp/build", "/tmp/build") {
		t.Errorf("missing --bind /tmp/build /tmp/build in %v", args)
	}
}

// --- Exec paths ---

func TestCompileBwrapFlags_ExecBinds(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		Exec:        []string{"/usr/bin/go", "/usr/bin/git"},
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	if !hasBind(args, "/usr/bin/go", "/usr/bin/go") {
		t.Errorf("missing --bind /usr/bin/go /usr/bin/go in %v", args)
	}
	if !hasBind(args, "/usr/bin/git", "/usr/bin/git") {
		t.Errorf("missing --bind /usr/bin/git /usr/bin/git in %v", args)
	}
}

// --- Path overlap: write path should not also appear as ro-bind ---

func TestCompileBwrapFlags_WritePathNotROBound(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		Read:        []string{"/home/user/code"},
		Write:       []string{"/home/user/code"},
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	if hasROBind(args, "/home/user/code", "/home/user/code") {
		t.Errorf("write path /home/user/code should NOT appear as --ro-bind")
	}
	if !hasBind(args, "/home/user/code", "/home/user/code") {
		t.Errorf("write path /home/user/code should appear as --bind")
	}
	// Ensure not duplicated
	n := countOccurrences(args, "/home/user/code")
	if n > 2 { // appears at most twice: once as key, once as value
		t.Errorf("/home/user/code appears %d times, expected at most 2", n)
	}
}

// --- Exec path overlap with write path dedup ---

func TestCompileBwrapFlags_ExecAndWriteOverlapNoDup(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		Write:       []string{"/usr/local/bin"},
		Exec:        []string{"/usr/local/bin"},
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	bindCount := 0
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && args[i+1] == "/usr/local/bin" && args[i+2] == "/usr/local/bin" {
			bindCount++
		}
	}
	if bindCount != 1 {
		t.Errorf("expected exactly 1 --bind for /usr/local/bin, got %d (args: %v)", bindCount, args)
	}
}

// --- Empty policy ---

func TestCompileBwrapFlags_EmptyPolicy_HasBaseline(t *testing.T) {
	rp := minimalPolicy()
	args := CompileBwrapFlags(rp)

	required := []string{"--unshare-all", "--die-with-parent"}
	for _, r := range required {
		if !hasFlag(args, r) {
			t.Errorf("missing baseline flag %q in empty policy args %v", r, args)
		}
	}
}

// --- Workdir ---

func TestCompileBwrapFlags_WorkdirBound(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		Workdir:     "/home/user/project",
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	if !hasBind(args, "/home/user/project", "/home/user/project") {
		t.Errorf("workdir /home/user/project not found as --bind in %v", args)
	}
}

func TestCompileBwrapFlags_EmptyWorkdir_NoExtraBinds(t *testing.T) {
	rp := minimalPolicy()
	rp.Workdir = ""
	args := CompileBwrapFlags(rp)

	// There should be no --bind from workdir (only --ro-bind-try for defaults).
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" {
			// Check it's not an empty string bind.
			if args[i+1] == "" || args[i+2] == "" {
				t.Errorf("empty string in --bind at index %d: %v", i, args[i:i+3])
			}
		}
	}
}

// --- Environment variable injection ---

func TestCompileBwrapFlags_PolicyModeEnvVar(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "my-profile",
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	if !hasPair3(args, "--setenv", "RAMPART_POLICY_MODE", "enforcing") {
		t.Errorf("RAMPART_POLICY_MODE=enforcing not in %v", args)
	}
	if !hasPair3(args, "--setenv", "RAMPART_PROFILE", "my-profile") {
		t.Errorf("RAMPART_PROFILE=my-profile not in %v", args)
	}
}

func TestCompileBwrapFlags_NetworkBlockedEnvVar(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		NetworkMode: "none",
	}
	args := CompileBwrapFlags(rp)

	if !hasPair3(args, "--setenv", "RAMPART_NET", "blocked") {
		t.Errorf("RAMPART_NET=blocked not found in %v", args)
	}
}

func TestCompileBwrapFlags_NetworkFilteredEnvVar(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "p",
		NetworkMode: "filtered",
	}
	args := CompileBwrapFlags(rp)

	if !hasPair3(args, "--setenv", "RAMPART_NET", "filtered") {
		t.Errorf("RAMPART_NET=filtered not found in %v", args)
	}
}

// --- Table-driven full scenarios ---

func TestCompileBwrapFlags_TableDriven(t *testing.T) {
	cases := []struct {
		name         string
		rp           *policy.ResolvedPolicy
		wantFlags    []string // must be present
		wantPairs    [][2]string
		wantBind     [][2]string // --bind src dst
		wantROBind   [][2]string // --ro-bind src dst
		wantNotBind  [][2]string // must NOT appear as --bind
		wantNotROBind [][2]string
	}{
		{
			name: "minimal_policy_baseline",
			rp:   minimalPolicy(),
			wantFlags: []string{"--unshare-all", "--die-with-parent"},
			wantPairs: [][2]string{{"--proc", "/proc"}, {"--dev", "/dev"}, {"--tmpfs", "/tmp"}},
		},
		{
			name: "read_only_policy",
			rp: &policy.ResolvedPolicy{
				Mode: "enforcing", ProfileName: "p",
				Read:        []string{"/etc", "/usr/share/doc"},
				NetworkMode: "none",
			},
			wantROBind:  [][2]string{{"/etc", "/etc"}, {"/usr/share/doc", "/usr/share/doc"}},
			wantNotBind: [][2]string{{"/etc", "/etc"}, {"/usr/share/doc", "/usr/share/doc"}},
		},
		{
			name: "read_write_policy",
			rp: &policy.ResolvedPolicy{
				Mode: "enforcing", ProfileName: "p",
				Read:        []string{"/etc/ssl"},
				Write:       []string{"/home/user/code", "/tmp/scratch"},
				NetworkMode: "none",
			},
			wantROBind:   [][2]string{{"/etc/ssl", "/etc/ssl"}},
			wantBind:     [][2]string{{"/home/user/code", "/home/user/code"}, {"/tmp/scratch", "/tmp/scratch"}},
			wantNotROBind: [][2]string{{"/home/user/code", "/home/user/code"}},
		},
		{
			name: "exec_policy",
			rp: &policy.ResolvedPolicy{
				Mode: "enforcing", ProfileName: "p",
				Exec:        []string{"/usr/bin/node"},
				NetworkMode: "none",
			},
			wantBind: [][2]string{{"/usr/bin/node", "/usr/bin/node"}},
		},
		{
			name: "permissive_mode",
			rp: &policy.ResolvedPolicy{
				Mode: "permissive", ProfileName: "p",
				NetworkMode: "none",
			},
			wantFlags: []string{"--unshare-all"},
		},
		{
			name: "path_with_spaces",
			rp: &policy.ResolvedPolicy{
				Mode: "enforcing", ProfileName: "p",
				Write:       []string{"/home/user/my project"},
				NetworkMode: "none",
			},
			wantBind: [][2]string{{"/home/user/my project", "/home/user/my project"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := CompileBwrapFlags(tc.rp)

			for _, f := range tc.wantFlags {
				if !hasFlag(args, f) {
					t.Errorf("missing flag %q", f)
				}
			}
			for _, p := range tc.wantPairs {
				if !hasPair(args, p[0], p[1]) {
					t.Errorf("missing pair %q %q", p[0], p[1])
				}
			}
			for _, b := range tc.wantBind {
				if !hasBind(args, b[0], b[1]) {
					t.Errorf("missing --bind %q %q", b[0], b[1])
				}
			}
			for _, b := range tc.wantROBind {
				if !hasROBind(args, b[0], b[1]) {
					t.Errorf("missing --ro-bind %q %q", b[0], b[1])
				}
			}
			for _, b := range tc.wantNotBind {
				if hasBind(args, b[0], b[1]) {
					t.Errorf("unexpected --bind %q %q", b[0], b[1])
				}
			}
			for _, b := range tc.wantNotROBind {
				if hasROBind(args, b[0], b[1]) {
					t.Errorf("unexpected --ro-bind %q %q", b[0], b[1])
				}
			}
		})
	}
}

// --- Verify no "--" terminator included (callers append it) ---

func TestCompileBwrapFlags_NoDoubleDashTerminator(t *testing.T) {
	args := CompileBwrapFlags(minimalPolicy())
	for _, a := range args {
		if a == "--" {
			t.Errorf("CompileBwrapFlags should not include '--' command separator: %v", args)
		}
	}
}

// --- Spot-check default ro-bind-try entries are present ---

func TestCompileBwrapFlags_DefaultROBindTryPresent(t *testing.T) {
	args := CompileBwrapFlags(minimalPolicy())

	// At least /etc/ssl should appear via --ro-bind-try.
	found := false
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--ro-bind-try" && args[i+1] == "/etc/ssl" && args[i+2] == "/etc/ssl" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("--ro-bind-try /etc/ssl /etc/ssl not found (should be in default binds)")
	}
}

// --- Verify output is a valid flat argument list (no nested slices) ---

func TestCompileBwrapFlags_ValidFlatArgList(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:        "enforcing",
		ProfileName: "default",
		Workdir:     "/workspace",
		Read:        []string{"/etc/ssl", "/usr/share"},
		Write:       []string{"/workspace", "/tmp/out"},
		Exec:        []string{"/usr/bin/go", "/usr/bin/git"},
		NetworkMode: "filtered",
	}
	args := CompileBwrapFlags(rp)

	for i, a := range args {
		if a == "" {
			t.Errorf("empty string at index %d in args %v", i, args)
		}
		if strings.Contains(a, "\x00") {
			t.Errorf("null byte in arg at index %d: %q", i, a)
		}
	}
}
