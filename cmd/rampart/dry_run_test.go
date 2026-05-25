package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/policy"
)

// --- resolvePolicyPaths ---

// resolvedJoin returns what paths.Resolve would produce for base + leaf:
// resolve symlinks of base (which exists), append the (non-existent) leaf.
// On macOS, this turns /var/folders/... into /private/var/folders/...
func resolvedJoin(t *testing.T, base, leaf string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		resolved = base
	}
	return filepath.Join(resolved, leaf)
}

func TestResolvePolicyPaths_TildeExpandsToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	rp := &policy.ResolvedPolicy{
		Read:  []string{"~/.gitconfig"},
		Write: []string{"~/.claude"},
		Exec:  []string{"~/bin/local-tool"},
	}
	if err := resolvePolicyPaths(rp, "/some/git/root", "/cwd"); err != nil {
		t.Fatalf("resolvePolicyPaths: %v", err)
	}

	if want := resolvedJoin(t, home, ".gitconfig"); rp.Read[0] != want {
		t.Errorf("Read[0] = %q, want %q", rp.Read[0], want)
	}
	if want := resolvedJoin(t, home, ".claude"); rp.Write[0] != want {
		t.Errorf("Write[0] = %q, want %q", rp.Write[0], want)
	}
	if want := resolvedJoin(t, home, "bin/local-tool"); rp.Exec[0] != want {
		t.Errorf("Exec[0] = %q, want %q", rp.Exec[0], want)
	}
}

func TestResolvePolicyPaths_RelativeJoinsGitRoot(t *testing.T) {
	gitRoot := t.TempDir()
	rp := &policy.ResolvedPolicy{
		Read:  []string{".git", "node_modules"},
		Write: []string{"."},
	}
	if err := resolvePolicyPaths(rp, gitRoot, "/should-not-be-used"); err != nil {
		t.Fatalf("resolvePolicyPaths: %v", err)
	}

	if want := resolvedJoin(t, gitRoot, ".git"); rp.Read[0] != want {
		t.Errorf("Read[0] = %q, want %q", rp.Read[0], want)
	}

	// "." resolves to the gitRoot itself, fully evaluated.
	wantWrite, _ := filepath.EvalSymlinks(gitRoot)
	if wantWrite == "" {
		wantWrite = gitRoot
	}
	if rp.Write[0] != wantWrite {
		t.Errorf("Write[0] = %q, want %q (gitRoot)", rp.Write[0], wantWrite)
	}
}

func TestResolvePolicyPaths_AbsolutePathUnchanged(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Exec: []string{"/usr/bin/security", "/opt/homebrew/bin/claude"},
	}
	if err := resolvePolicyPaths(rp, "/some/git/root", "/cwd"); err != nil {
		t.Fatalf("resolvePolicyPaths: %v", err)
	}
	// /usr/bin/security exists, EvalSymlinks resolves it. The key invariant
	// is that an absolute system path is not relocated under git root.
	for _, p := range rp.Exec {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("absolute path became non-absolute: %q", p)
		}
		if strings.Contains(p, "/some/git/root") {
			t.Errorf("absolute path was joined to gitRoot: %q", p)
		}
	}
}

func TestResolvePolicyPaths_FallsBackToCWDWhenNoGitRoot(t *testing.T) {
	cwd := t.TempDir()
	rp := &policy.ResolvedPolicy{
		Write: []string{"foo"},
	}
	if err := resolvePolicyPaths(rp, "", cwd); err != nil {
		t.Fatalf("resolvePolicyPaths: %v", err)
	}
	if want := resolvedJoin(t, cwd, "foo"); rp.Write[0] != want {
		t.Errorf("Write[0] = %q, want %q (fallback CWD)", rp.Write[0], want)
	}
}

// --- printHumanReadable table-driven tests ---

func TestPrintHumanReadable_SimplePolicy(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:           "enforcing",
		FilesystemMode: "read-write",
		Read:           []string{"/etc/ssl"},
		Write:          []string{"/tmp"},
		Exec:           []string{"/usr/bin/git"},
		NetworkMode:    "filtered",
		AllowedDomains: []string{"api.anthropic.com"},
	}
	cp := &compiledPolicy{Policy: rp, AgentName: "coding", ProfileName: "myproject/default"}

	out := &bytes.Buffer{}
	printHumanReadable(cp, out)
	s := out.String()

	checks := []string{
		"=== rampart dry-run ===",
		"agent:   coding",
		"profile: myproject/default",
		"mode:    enforcing",
		"filesystem",
		"mode: read-write",
		"/etc/ssl",
		"/tmp",
		"/usr/bin/git",
		"network",
		"mode: filtered",
		"api.anthropic.com",
	}
	for _, want := range checks {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, s)
		}
	}
}

func TestPrintHumanReadable_WithWarnings(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:           "enforcing",
		FilesystemMode: "none",
		NetworkMode:    "none",
		Warnings:       []string{"path /nonexistent does not exist", "domain '*.evil.com' not granted"},
	}
	cp := &compiledPolicy{Policy: rp, AgentName: "planning", ProfileName: "proj/default"}

	out := &bytes.Buffer{}
	printHumanReadable(cp, out)
	s := out.String()

	if !strings.Contains(s, "warnings") {
		t.Error("output missing warnings section")
	}
	if !strings.Contains(s, "/nonexistent") {
		t.Error("output missing warning about /nonexistent")
	}
	if !strings.Contains(s, "evil.com") {
		t.Error("output missing warning about evil.com")
	}
}

func TestPrintHumanReadable_WithCLIOverrides(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Mode:            "enforcing",
		FilesystemMode:  "read-write",
		CLIExtraPaths:   []string{"/opt/extra"},
		CLIExtraDomains: []string{"custom.corp"},
		NetworkMode:     "filtered",
	}
	cp := &compiledPolicy{Policy: rp, AgentName: "coding", ProfileName: "proj/ci"}

	out := &bytes.Buffer{}
	printHumanReadable(cp, out)
	s := out.String()

	if !strings.Contains(s, "--allow-path") {
		t.Error("CLI extra path should show source 'CLI --allow-path'")
	}
	if !strings.Contains(s, "/opt/extra") {
		t.Error("output missing CLI extra path /opt/extra")
	}
	if !strings.Contains(s, "--allow-domain") {
		t.Error("CLI extra domain should show source 'CLI --allow-domain'")
	}
	if !strings.Contains(s, "custom.corp") {
		t.Error("output missing CLI extra domain custom.corp")
	}
}

func TestPrintHumanReadable_NoOptionalSections(t *testing.T) {
	// A minimal policy with no paths, domains, or warnings.
	rp := &policy.ResolvedPolicy{
		Mode:           "permissive",
		FilesystemMode: "none",
		NetworkMode:    "none",
	}
	cp := &compiledPolicy{Policy: rp, AgentName: "restricted", ProfileName: "proj/noop"}

	out := &bytes.Buffer{}
	printHumanReadable(cp, out)
	s := out.String()

	// Header must appear.
	if !strings.Contains(s, "=== rampart dry-run ===") {
		t.Error("header missing")
	}
	// Optional sections must NOT appear when empty.
	if strings.Contains(s, "warnings") {
		t.Error("warnings section should be absent when empty")
	}
}

// --- runDryRun integration test ---

func TestRunDryRun_Integration(t *testing.T) {
	// Build a temp git repo with valid agent + profile config.
	gitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	r := filepath.Join(gitDir, ".rampart")
	write(filepath.Join(r, "defaults.hcl"), `
defaults {
  default_agent   = "coding"
  default_profile = "testproj/default"
}
`)
	write(filepath.Join(r, "agents.hcl"), `
agent "coding" {
  filesystem   = "read-write"
  network_mode = "filtered"
}
`)
	write(filepath.Join(r, "profiles", "testproj", "default.hcl"), `
profile "default" {
  workdir = "."
  write   = ["/tmp"]
  allowed_domains = ["api.example.com"]
}
`)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}

	flags := &runFlags{mode: "enforcing"}
	out := &bytes.Buffer{}
	if err := runDryRun(flags, out); err != nil {
		t.Fatalf("runDryRun: %v", err)
	}

	s := out.String()
	mustContain := []string{
		"=== rampart dry-run ===",
		"agent:   coding",
		"profile: testproj/default",
		"mode:    enforcing",
		"filesystem",
		"network",
		"--- platform-native rules ---",
	}
	for _, want := range mustContain {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, s)
		}
	}
}

func TestRunDryRun_NoProfile_Errors(t *testing.T) {
	// No .rampart/defaults.hcl and no --profile flag: should error.
	gitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}

	flags := &runFlags{mode: "enforcing"}
	err := runDryRun(flags, &bytes.Buffer{})
	if err == nil {
		t.Error("expected error when no profile configured, got nil")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("error should mention 'profile': %v", err)
	}
}

func TestRunDryRun_ExitZeroOnSuccess(t *testing.T) {
	// runDryRun must return nil (exit 0) on a valid policy.
	gitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	write := func(path, content string) {
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte(content), 0o644)
	}
	r := filepath.Join(gitDir, ".rampart")
	write(filepath.Join(r, "agents.hcl"), `
agent "coding" {
  filesystem   = "read-write"
  network_mode = "none"
}
`)
	write(filepath.Join(r, "profiles", "p", "default.hcl"), `
profile "default" { workdir = "." }
`)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(gitDir)

	flags := &runFlags{agent: "coding", profile: "p/default", mode: "enforcing"}
	if err := runDryRun(flags, &bytes.Buffer{}); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

// --- --dry-run flag wiring (via rootCmd) ---

func TestRootCmd_DryRunFlag_UsesRunDryRun(t *testing.T) {
	// Build a temp git repo and verify --dry-run produces policy output.
	gitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	write := func(path, content string) {
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte(content), 0o644)
	}
	r := filepath.Join(gitDir, ".rampart")
	write(filepath.Join(r, "agents.hcl"), `
agent "coding" {
  filesystem   = "read-write"
  network_mode = "none"
}
`)
	write(filepath.Join(r, "profiles", "myp", "default.hcl"), `
profile "default" { workdir = "." }
`)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(gitDir)

	cmd := rootCmd()
	cmd.SetArgs([]string{"--dry-run", "--agent", "coding", "--profile", "myp/default", "--", "true"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("--dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "=== rampart dry-run ===") {
		t.Errorf("--dry-run should print policy summary, got: %q", out.String())
	}
}
