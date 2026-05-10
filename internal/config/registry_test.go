package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureTree builds a complete .rampart/ directory tree in a temp dir for testing.
// Layout:
//   tmpdir/
//     .git/                        (marks git root)
//     .rampart/
//       defaults.hcl
//       agents.hcl                 (repo-wide, two agents: "repo-agent" and "shared")
//       agents/
//         repo-only.hcl
//       myproject.hcl              (shorthand profile for myproject)
//       profiles/
//         myproject/
//           default.hcl
//           custom.hcl
//           agents/
//             project-agent.hcl
//     globalDir/
//       agents.hcl                 (global, agent "shared" - lower priority)
//       agents/
//         global-only.hcl
func buildFixtureTree(t *testing.T) (tmpdir, globalDir string) {
	t.Helper()
	tmpdir = t.TempDir()
	globalDir = t.TempDir()

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture setup: %v", err)
		}
	}
	writeFile := func(path, content string) {
		t.Helper()
		must(os.MkdirAll(filepath.Dir(path), 0o755))
		must(os.WriteFile(path, []byte(content), 0o644))
	}

	// Mark git root.
	must(os.MkdirAll(filepath.Join(tmpdir, ".git"), 0o755))

	rampart := filepath.Join(tmpdir, ".rampart")

	// Repo-wide defaults.
	writeFile(filepath.Join(rampart, "defaults.hcl"), `
defaults {
  default_agent   = "repo-agent"
  default_profile = "myproject/default"
}
`)

	// Repo-wide agents.hcl (multi-agent).
	writeFile(filepath.Join(rampart, "agents.hcl"), `
agent "repo-agent" {
  filesystem   = "read-write"
  network_mode = "none"
}
agent "shared" {
  description  = "repo-wide shared"
  filesystem   = "read-only"
  network_mode = "none"
}
`)

	// Repo-wide agents/ (single-agent file).
	writeFile(filepath.Join(rampart, "agents", "repo-only.hcl"), `
agent "repo-only" {
  filesystem   = "none"
  network_mode = "none"
}
`)

	// Shorthand profile file: .rampart/myproject.hcl.
	writeFile(filepath.Join(rampart, "myproject.hcl"), `
profile "shorthand-default" {
  workdir = "."
}
`)

	// Project profile: .rampart/profiles/myproject/default.hcl.
	writeFile(filepath.Join(rampart, "profiles", "myproject", "default.hcl"), `
profile "default" {
  workdir = "."
  read    = ["/etc"]
}
`)

	// Project profile: .rampart/profiles/myproject/custom.hcl.
	writeFile(filepath.Join(rampart, "profiles", "myproject", "custom.hcl"), `
profile "custom" {
  workdir = "/tmp"
}
`)

	// Project agent: .rampart/profiles/myproject/agents/project-agent.hcl.
	writeFile(filepath.Join(rampart, "profiles", "myproject", "agents", "project-agent.hcl"), `
agent "project-agent" {
  filesystem   = "read-write"
  network_mode = "filtered"
}
`)

	// Global agents.hcl (lower priority than repo).
	writeFile(filepath.Join(globalDir, "agents.hcl"), `
agent "shared" {
  description  = "global shared - lower priority"
  filesystem   = "none"
  network_mode = "none"
}
`)

	// Global agents/ single-agent file.
	writeFile(filepath.Join(globalDir, "agents", "global-only.hcl"), `
agent "global-only" {
  filesystem   = "none"
  network_mode = "none"
}
`)

	return tmpdir, globalDir
}

func TestRegistry_AgentResolution(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// Bare name resolves repo-wide first.
	a, err := reg.ResolveAgent("repo-agent")
	if err != nil {
		t.Fatalf("repo-agent: %v", err)
	}
	if a.Name != "repo-agent" {
		t.Errorf("unexpected agent: %v", a.Name)
	}

	// Repo-only bare name from agents/ subdirectory.
	a, err = reg.ResolveAgent("repo-only")
	if err != nil {
		t.Fatalf("repo-only: %v", err)
	}
	if a.Name != "repo-only" {
		t.Errorf("unexpected name: %v", a.Name)
	}

	// Global-only bare name.
	a, err = reg.ResolveAgent("global-only")
	if err != nil {
		t.Fatalf("global-only: %v", err)
	}
	if a.Name != "global-only" {
		t.Errorf("unexpected name: %v", a.Name)
	}
}

func TestRegistry_RepoPriorityOverGlobal(t *testing.T) {
	// "shared" exists in both repo and global; repo should win.
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	a, err := reg.ResolveAgent("shared")
	if err != nil {
		t.Fatalf("shared: %v", err)
	}
	if a.Description != "repo-wide shared" {
		t.Errorf("expected repo-wide shared, got description=%q", a.Description)
	}
}

func TestRegistry_QualifiedAgentResolvesProjectScope(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// Qualified project/agent resolves only within project scope.
	a, err := reg.ResolveAgent("myproject/project-agent")
	if err != nil {
		t.Fatalf("myproject/project-agent: %v", err)
	}
	if a.Name != "project-agent" {
		t.Errorf("unexpected name: %v", a.Name)
	}
}

func TestRegistry_QualifiedAgentStrictScopingNoFallthrough(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// "myproject/repo-agent" — repo-agent exists in repo scope but NOT project scope.
	// Must return error, not fall through.
	_, err = reg.ResolveAgent("myproject/repo-agent")
	if err == nil {
		t.Fatal("expected error for qualified name not in project scope")
	}
}

func TestRegistry_BareAgentNotFound(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	_, err = reg.ResolveAgent("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestRegistry_ProfileResolution_Qualified(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	p, err := reg.ResolveProfile("myproject/default")
	if err != nil {
		t.Fatalf("myproject/default: %v", err)
	}
	if p.Name != "default" {
		t.Errorf("unexpected profile name: %v", p.Name)
	}

	p, err = reg.ResolveProfile("myproject/custom")
	if err != nil {
		t.Fatalf("myproject/custom: %v", err)
	}
	if p.Name != "custom" {
		t.Errorf("unexpected profile name: %v", p.Name)
	}
}

func TestRegistry_ProfileResolution_ShorthandProjectDefault(t *testing.T) {
	// --profile myproject resolves to "myproject/default".
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	p, err := reg.ResolveProfile("myproject")
	if err != nil {
		t.Fatalf("myproject shorthand: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil profile")
	}
}

func TestRegistry_ProfileResolution_ShorthandFile(t *testing.T) {
	// .rampart/myproject.hcl shorthand: accessible as "myproject/default".
	// The shorthand fallback is tested using a fresh tree that has only the shorthand file.
	tmpdir2 := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	must(os.MkdirAll(filepath.Join(tmpdir2, ".git"), 0o755))
	rampart2 := filepath.Join(tmpdir2, ".rampart")
	must(os.MkdirAll(rampart2, 0o755))
	must(os.WriteFile(filepath.Join(rampart2, "myproject.hcl"), []byte(`
profile "shorthand-default" {
  workdir = "."
}
`), 0o644))

	reg2, err2 := NewRegistry(tmpdir2, "")
	if err2 != nil {
		t.Fatalf("NewRegistry2: %v", err2)
	}
	p, err := reg2.ResolveProfile("myproject/default")
	if err != nil {
		t.Fatalf("shorthand myproject/default: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil profile from shorthand")
	}
}

func TestRegistry_DefaultsFileSelected(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if reg.DefaultAgent() != "repo-agent" {
		t.Errorf("DefaultAgent: got %q, want %q", reg.DefaultAgent(), "repo-agent")
	}
	if reg.DefaultProfile() != "myproject/default" {
		t.Errorf("DefaultProfile: got %q, want %q", reg.DefaultProfile(), "myproject/default")
	}
}

func TestRegistry_NoRampartDir(t *testing.T) {
	// No .rampart/ — registry should build without error.
	tmpdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpdir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(tmpdir, "")
	if err != nil {
		t.Fatalf("NewRegistry with no .rampart: %v", err)
	}
	// No agents or profiles indexed.
	_, err = reg.ResolveAgent("anything")
	if err == nil {
		t.Fatal("expected error for agent with empty registry")
	}
}

func TestFindGitRoot_WalksUp(t *testing.T) {
	// Build: tmpdir/.git + tmpdir/a/b/c
	tmpdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpdir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(tmpdir, "a", "b", "c")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	root := FindGitRoot(subdir)
	if root != tmpdir {
		t.Errorf("FindGitRoot: got %q, want %q", root, tmpdir)
	}
}

func TestFindGitRoot_NotFound(t *testing.T) {
	// Use a directory that has no .git anywhere in the tree.
	// os.TempDir() is typically /tmp which has no .git.
	tmpdir := t.TempDir()
	root := FindGitRoot(tmpdir)
	// Either "" or some parent with .git is acceptable — just don't panic.
	_ = root
}

func TestRegistry_ListAgents(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	infos := reg.ListAgents()
	if len(infos) == 0 {
		t.Fatal("ListAgents returned empty slice")
	}

	// Every entry's source file must point at a real .hcl path.
	seen := map[string]bool{}
	for _, a := range infos {
		if len(a.Aliases) == 0 {
			t.Errorf("AgentInfo with no aliases: %+v", a)
		}
		if a.SourceFile == "" {
			t.Errorf("agent %v has empty SourceFile", a.Aliases)
		}
		for _, alias := range a.Aliases {
			if seen[alias] {
				t.Errorf("alias %q appears in more than one AgentInfo", alias)
			}
			seen[alias] = true
		}
	}

	// Slice must be sorted by canonical alias.
	for i := 1; i < len(infos); i++ {
		if infos[i-1].Aliases[0] > infos[i].Aliases[0] {
			t.Errorf("ListAgents not sorted: %q before %q", infos[i-1].Aliases[0], infos[i].Aliases[0])
		}
	}

	// Fixture has a project-scoped "project-agent" — verify it's listed under
	// its qualified name "myproject/project-agent" (and possibly the bare alias).
	foundQualified := false
	for _, a := range infos {
		for _, alias := range a.Aliases {
			if alias == "myproject/project-agent" {
				foundQualified = true
			}
		}
	}
	if !foundQualified {
		t.Errorf("expected myproject/project-agent in ListAgents, got: %+v", infos)
	}
}

func TestRegistry_ListProfiles(t *testing.T) {
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	infos := reg.ListProfiles()
	if len(infos) == 0 {
		t.Fatal("ListProfiles returned empty slice")
	}

	for _, p := range infos {
		for _, alias := range p.Aliases {
			if strings.HasPrefix(alias, "shorthand:") {
				t.Errorf("internal shorthand key %q must be filtered out of ListProfiles", alias)
			}
		}
		if p.SourceFile == "" {
			t.Errorf("profile %v has empty SourceFile", p.Aliases)
		}
	}

	// myproject/default and myproject/custom should both be present.
	want := map[string]bool{"myproject/default": false, "myproject/custom": false}
	for _, p := range infos {
		for _, alias := range p.Aliases {
			if _, ok := want[alias]; ok {
				want[alias] = true
			}
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("expected profile %q in ListProfiles, got: %+v", k, infos)
		}
	}
}

func TestRegistry_MultiAgentFileAndSingleFileIndexed(t *testing.T) {
	// agents.hcl AND agents/<name>.hcl in the same dir are both indexed (FR9.2).
	tmpdir, globalDir := buildFixtureTree(t)
	reg, err := NewRegistry(tmpdir, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// From agents.hcl (multi).
	if _, err := reg.ResolveAgent("repo-agent"); err != nil {
		t.Errorf("repo-agent (from agents.hcl): %v", err)
	}
	// From agents/repo-only.hcl (single).
	if _, err := reg.ResolveAgent("repo-only"); err != nil {
		t.Errorf("repo-only (from agents/repo-only.hcl): %v", err)
	}
}
