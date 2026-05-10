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
