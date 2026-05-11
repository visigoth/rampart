//go:build darwin

package macos

import (
	"fmt"
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/policy"
)

func TestCompileSBPL_DenyDefaultBaseline(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, "(deny default)") {
		t.Error("expected (deny default) baseline in SBPL output")
	}
	if !strings.Contains(sbpl, "(version 1)") {
		t.Error("expected (version 1) in SBPL output")
	}
}

func TestCompileSBPL_ReadPaths(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Read: []string{"/home/user/project"},
	}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, `(subpath "/home/user/project")`) {
		t.Errorf("expected read path in SBPL, got:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, "file-read*") {
		t.Error("expected file-read* rule for read path")
	}
}

func TestCompileSBPL_WritePaths(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Write: []string{"/home/user/output"},
	}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, `(subpath "/home/user/output")`) {
		t.Errorf("expected write path in SBPL, got:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, "file-write*") {
		t.Error("expected file-write* rule for write path")
	}
}

func TestCompileSBPL_ExecPaths(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Exec: []string{"/usr/local/bin/node"},
	}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, `(subpath "/usr/local/bin/node")`) {
		t.Errorf("expected exec path in SBPL, got:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, "process-exec") {
		t.Error("expected process-exec rule for exec path")
	}
}

func TestCompileSBPL_NetworkFull(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		NetworkMode: "full",
	}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, "(allow network*)") {
		t.Errorf("expected (allow network*) for full network mode, got:\n%s", sbpl)
	}
}

func TestCompileSBPL_NetworkFiltered(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		NetworkMode:    "filtered",
		AllowedDomains: []string{"api.anthropic.com", "github.com"},
	}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, `"api.anthropic.com:*"`) {
		t.Errorf("expected api.anthropic.com domain rule, got:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, `"github.com:*"`) {
		t.Errorf("expected github.com domain rule, got:\n%s", sbpl)
	}
	if strings.Contains(sbpl, "(allow network*)") {
		t.Error("filtered mode should not have (allow network*)")
	}
}

func TestCompileSBPL_EmptyPolicy(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, "(deny default)") {
		t.Error("empty policy must still have (deny default)")
	}
}

// TestCompileSBPL_AllowsTTYIoctlAndWrite covers the second load-bearing
// baseline for interactive agents: TIOCSETA (raw mode), TIOCGWINSZ
// (window size), and writing characters to the tty all need file-ioctl
// + file-write-data on /dev. Without these, claude (and any other TUI
// agent) fails with "setRawMode failed with errno: 1" at startup and
// never becomes interactive in the user's terminal.
func TestCompileSBPL_AllowsTTYIoctlAndWrite(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, `(allow file-ioctl
    (subpath "/dev"))`) {
		t.Error("baseline SBPL must include file-ioctl on /dev for TTY tcsetattr / TIOCGWINSZ")
	}
	if !strings.Contains(sbpl, `(allow file-write-data
    (subpath "/dev"))`) {
		t.Error("baseline SBPL must include file-write-data on /dev for writing to TTY and /dev/null")
	}
}

// TestCompileSBPL_AllowsLoopbackInFilteredMode covers another load-bearing
// baseline: the rampart forward proxy binds 127.0.0.1 and the agent
// connects there for every HTTPS request. Without a loopback rule, the
// agent's proxy connection silently hangs and its event loop blocks
// indefinitely. Full mode is covered by (allow network*); none mode is
// intentionally network-denied so loopback should not appear there.
func TestCompileSBPL_AllowsLoopbackInFilteredMode(t *testing.T) {
	rp := &policy.ResolvedPolicy{NetworkMode: "filtered"}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	// Seatbelt's `remote tcp` syntax only accepts `*` or `localhost` as the
	// host portion — numeric IPs (127.0.0.1, [::1]) error at policy load.
	// The `localhost` keyword matches both IPv4 and IPv6 loopback.
	if !strings.Contains(sbpl, `(remote tcp "localhost:*")`) {
		t.Error("filtered-mode SBPL must allow loopback outbound for the proxy (remote tcp \"localhost:*\")")
	}

	// In none mode, the loopback rule should not appear (network is denied).
	rpNone := &policy.ResolvedPolicy{NetworkMode: "none"}
	sbplNone, _ := CompileSBPL(rpNone, false)
	if strings.Contains(sbplNone, `(remote tcp "localhost:*")`) {
		t.Error("none-mode SBPL must NOT include the loopback allow rule")
	}
}

// TestCompileSBPL_AllowsHomebrewPrefixReads covers another load-bearing baseline
// for any agent that's a Homebrew binary: dyld must be able to open the
// shared libraries the binary links against, which on macOS Homebrew
// install live under /opt/homebrew/opt/<formula>/lib (or /usr/local/opt
// on Intel). Without read access here, claude/tig/gh and friends fail
// at startup with: dyld "file system sandbox blocked open()" — even
// when their exec path is allowed.
func TestCompileSBPL_AllowsHomebrewPrefixReads(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, `(subpath "/opt/homebrew")`) {
		t.Error("baseline SBPL must include (subpath \"/opt/homebrew\") read access for Apple Silicon Homebrew dyld")
	}
	if !strings.Contains(sbpl, `(subpath "/usr/local")`) {
		t.Error("baseline SBPL must include (subpath \"/usr/local\") read access for Intel Homebrew dyld")
	}
}

// TestCompileSBPL_AllowsProcessFork covers a load-bearing baseline: with
// (deny default), Seatbelt requires (allow process-fork) for posix_spawn
// to succeed at all. Without it, agents inside the sandbox can't spawn
// any subprocess (not even the binaries listed in their exec policy)
// and crash at startup with EPERM during fork+exec.
func TestCompileSBPL_AllowsProcessFork(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if !strings.Contains(sbpl, "(allow process-fork)") {
		t.Error("baseline SBPL must include (allow process-fork) — without it, posix_spawn fails with EPERM regardless of process-exec rules")
	}
}

func TestCompileSBPL_ParamPlaceholders(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	for _, param := range []string{"HOME", "WORKDIR", "TMPDIR", "CLAUDE_BIN_DIR"} {
		if !strings.Contains(sbpl, `(param "`+param+`")`) {
			t.Errorf("expected (param %q) in SBPL output", param)
		}
	}
}

func TestCompileSBPL_EscapesQuotesInPaths(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Read: []string{`/home/user/dir"with"quotes`},
	}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	if strings.Contains(sbpl, `dir"with"`) {
		t.Error("unescaped double-quote found in SBPL output")
	}
	if !strings.Contains(sbpl, `dir\"with\"`) {
		t.Errorf("expected escaped quotes in path, got:\n%s", sbpl)
	}
}

func TestCompileSBPL_BaselineDenyDefault(t *testing.T) {
	// SIGKILL on policy violations is enforced at the supervisor layer (FT7),
	// not in SBPL — see template comment. Both modes therefore use plain
	// (deny default) which returns EPERM on disallowed operations.
	for _, testMode := range []bool{false, true} {
		rp := &policy.ResolvedPolicy{}
		out, err := CompileSBPL(rp, testMode)
		if err != nil {
			t.Fatalf("CompileSBPL(testMode=%v): %v", testMode, err)
		}
		if strings.Contains(out, "send-signal SIGKILL") {
			t.Errorf("testMode=%v: SBPL must not embed SIGKILL deny rules; got:\n%s", testMode, out)
		}
		if !strings.Contains(out, "(deny default)") {
			t.Errorf("testMode=%v: SBPL must keep (deny default) baseline; got:\n%s", testMode, out)
		}
	}
}

func TestCompileSBPL_LargePolicyReasonableSize(t *testing.T) {
	paths := make([]string, 100)
	for i := range paths {
		paths[i] = fmt.Sprintf("/home/user/dir%d", i)
	}
	rp := &policy.ResolvedPolicy{
		Read:        paths,
		NetworkMode: "filtered",
		AllowedDomains: func() []string {
			d := make([]string, 10)
			for i := range d {
				d[i] = fmt.Sprintf("host%d.example.com", i)
			}
			return d
		}(),
	}
	sbpl, err := CompileSBPL(rp, false)
	if err != nil {
		t.Fatalf("CompileSBPL: %v", err)
	}
	// A 100-path policy should be well under 100 KB.
	if len(sbpl) > 100*1024 {
		t.Errorf("SBPL output unreasonably large: %d bytes", len(sbpl))
	}
}

func TestSbplEscape(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`plain`, `plain`},
		{`has"quote`, `has\"quote`},
		{`has\backslash`, `has\\backslash`},
		{`has"both\combined`, `has\"both\\combined`},
	}
	for _, tt := range tests {
		got := sbplEscape(tt.input)
		if got != tt.want {
			t.Errorf("sbplEscape(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
