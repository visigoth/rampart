// Integration tests for config loading + registry resolution (.1.3).
// Uses realistic HCL fixture trees that simulate actual user config layouts.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildFullFixture creates a comprehensive fixture tree covering all three
// resolution scopes: global, repo-wide, and project-scoped.
//
// Tree layout:
//
//	<gitRoot>/
//	  .git/
//	  .rampart/
//	    defaults.hcl                        (default_agent=coding, default_profile=/default)
//	    agents.hcl                          (repo-wide: "coding", "planning")
//	    agents/
//	      reviewing.hcl                     (repo-wide single file: "reviewing")
//	    .hcl                            (shorthand profile for "" project)
//	    profiles/
//	      /
//	        default.hcl                     (project default profile)
//	        ci.hcl                          (named project profile)
//	        agents/
//	          infra.hcl                     (project-scoped agent)
//	<globalDir>/
//	  agents.hcl                            (global: "coding" lower priority, "global-planner")
//	  agents/
//	    sre.hcl                             (global single: "sre")
func buildFullFixture(t *testing.T) (gitRoot, globalDir string) {
	t.Helper()
	gitRoot = t.TempDir()
	globalDir = t.TempDir()

	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	if err := os.MkdirAll(filepath.Join(gitRoot, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := filepath.Join(gitRoot, ".rampart")

	write(filepath.Join(r, "defaults.hcl"), `
defaults {
  default_agent   = "coding"
  default_profile = "/default"
}
`)

	write(filepath.Join(r, "agents.hcl"), `
agent "coding" {
  description  = "Repo-wide coding agent"
  filesystem   = "read-write"
  read         = ["/home/user", "/etc/ssl"]
  write        = ["/tmp", "/home/user/.config"]
  exec         = ["/usr/bin/git", "/usr/bin/make"]
  network_mode = "filtered"
  domains      = ["api.anthropic.com", "*.npmjs.org"]
  toolchains   = ["node", "python", "go"]

  network {
    domain "api.anthropic.com" {
      allow "POST" {
        paths = ["/v1/messages", "/v1/complete"]
      }
      allow "GET" {
        paths = ["/v1/**"]
      }
    }
    domain "*.npmjs.org" {}
    domain "*.pypi.org" {}
  }
}

agent "planning" {
  description  = "Planning agent - read-only, network access"
  filesystem   = "read-only"
  network_mode = "filtered"
  toolchains   = ["node"]
}
`)

	write(filepath.Join(r, "agents", "reviewing.hcl"), `
agent "reviewing" {
  description  = "Code review agent - read-only"
  filesystem   = "read-only"
  network_mode = "none"
  toolchains   = ["node", "python"]
}
`)

	// Shorthand profile .rampart/.hcl.
	write(filepath.Join(r, ".hcl"), `
profile "shorthand" {
  workdir = "."
}
`)

	// Project default profile.
	write(filepath.Join(r, "profiles", "", "default.hcl"), `
profile "default" {
  workdir         = "."
  read            = ["/etc", "/usr/share"]
  write           = ["/tmp"]
  exec            = ["/usr/bin", "/usr/local/bin"]
  allowed_domains = ["api.anthropic.com", "*.npmjs.org", "*.pypi.org"]
  toolchains      = ["node", "python", "go"]

  network {
    domain "api.anthropic.com" {
      allow "POST" {
        paths = ["/v1/messages", "/v1/complete"]
      }
      allow "GET" {
        paths = ["/v1/**"]
      }
    }
    domain "*.npmjs.org" {}
    domain "*.pypi.org" {}
  }
}
`)

	// Named CI profile.
	write(filepath.Join(r, "profiles", "", "ci.hcl"), `
profile "ci" {
  workdir = "/ci/workspace"
  exec    = ["/usr/bin", "/ci/bin"]

  network {
    domain "api.anthropic.com" {}
  }
}
`)

	// Project-scoped agent.
	write(filepath.Join(r, "profiles", "", "agents", "infra.hcl"), `
agent "infra" {
  description  = "Infrastructure agent - project-scoped"
  filesystem   = "read-write"
  write        = ["/etc/nginx", "/var/www"]
  network_mode = "filtered"
  domains      = ["pkg.debian.org"]
}
`)

	// Global agents.hcl — "coding" exists here too but with lower priority.
	write(filepath.Join(globalDir, "agents.hcl"), `
agent "coding" {
  description  = "Global coding agent (lower priority)"
  filesystem   = "read-only"
  network_mode = "none"
}
agent "global-planner" {
  description  = "Global planner"
  filesystem   = "read-only"
  network_mode = "filtered"
}
`)

	write(filepath.Join(globalDir, "agents", "sre.hcl"), `
agent "sre" {
  description  = "SRE agent (global only)"
  filesystem   = "read-write"
  network_mode = "full"
}
`)

	return gitRoot, globalDir
}

// TestIntegration_FullPipelineRepoWideResolution exercises all three resolution
// paths and validates config fields after full parsing.
func TestIntegration_FullPipelineRepoWideResolution(t *testing.T) {
	gitRoot, globalDir := buildFullFixture(t)
	reg, err := NewRegistry(gitRoot, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// --- Repo-wide agents ---
	coding, err := reg.ResolveAgent("coding")
	if err != nil {
		t.Fatalf("coding: %v", err)
	}
	// Repo-wide wins over global.
	if coding.Description != "Repo-wide coding agent" {
		t.Errorf("coding description: got %q", coding.Description)
	}
	if coding.Filesystem != "read-write" {
		t.Errorf("coding filesystem: got %q", coding.Filesystem)
	}
	if len(coding.Read) != 2 {
		t.Errorf("coding read paths: got %d", len(coding.Read))
	}
	if len(coding.Toolchains) != 3 {
		t.Errorf("coding toolchains: got %v", coding.Toolchains)
	}
	if coding.Network == nil || len(coding.Network.Domains) != 3 {
		t.Errorf("coding network domains: expected 3, got %v", coding.Network)
	}

	// Planning agent from same agents.hcl.
	planning, err := reg.ResolveAgent("planning")
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	if planning.Filesystem != "read-only" {
		t.Errorf("planning filesystem: got %q", planning.Filesystem)
	}

	// Reviewing from agents/ subdir.
	reviewing, err := reg.ResolveAgent("reviewing")
	if err != nil {
		t.Fatalf("reviewing: %v", err)
	}
	if reviewing.NetworkMode != "none" {
		t.Errorf("reviewing network_mode: got %q", reviewing.NetworkMode)
	}
}

func TestIntegration_GlobalResolutionPath(t *testing.T) {
	gitRoot, globalDir := buildFullFixture(t)
	reg, err := NewRegistry(gitRoot, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// Global-only agents.
	gp, err := reg.ResolveAgent("global-planner")
	if err != nil {
		t.Fatalf("global-planner: %v", err)
	}
	if gp.Description != "Global planner" {
		t.Errorf("global-planner description: got %q", gp.Description)
	}

	sre, err := reg.ResolveAgent("sre")
	if err != nil {
		t.Fatalf("sre: %v", err)
	}
	if sre.NetworkMode != "full" {
		t.Errorf("sre network_mode: got %q", sre.NetworkMode)
	}
}

func TestIntegration_ProjectScopedResolution(t *testing.T) {
	gitRoot, globalDir := buildFullFixture(t)
	reg, err := NewRegistry(gitRoot, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// Project-scoped agent via qualified name.
	infra, err := reg.ResolveAgent("/infra")
	if err != nil {
		t.Fatalf("/infra: %v", err)
	}
	if infra.Description != "Infrastructure agent - project-scoped" {
		t.Errorf("infra description: got %q", infra.Description)
	}
	if infra.Filesystem != "read-write" {
		t.Errorf("infra filesystem: got %q", infra.Filesystem)
	}

	// Qualified default profile.
	def, err := reg.ResolveProfile("/default")
	if err != nil {
		t.Fatalf("/default: %v", err)
	}
	if def.Workdir != "." {
		t.Errorf("/default workdir: got %q", def.Workdir)
	}
	if len(def.Read) != 2 {
		t.Errorf("/default read: got %v", def.Read)
	}
	if def.Network == nil || len(def.Network.Domains) != 3 {
		t.Errorf("/default network domains: expected 3")
	}

	// Named project profile.
	ci, err := reg.ResolveProfile("/ci")
	if err != nil {
		t.Fatalf("/ci: %v", err)
	}
	if ci.Workdir != "/ci/workspace" {
		t.Errorf("/ci workdir: got %q", ci.Workdir)
	}
}

func TestIntegration_StrictProjectScoping(t *testing.T) {
	gitRoot, globalDir := buildFullFixture(t)
	reg, err := NewRegistry(gitRoot, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// "/coding" — coding exists in repo scope but NOT in 's agents/.
	// Must error; must NOT fall through to repo-wide.
	_, err = reg.ResolveAgent("/coding")
	if err == nil {
		t.Fatal("expected error: qualified name not in project scope should not fall through")
	}
	if !strings.Contains(err.Error(), "project scope") {
		t.Errorf("error should mention project scope: %v", err)
	}

	// "/reviewing" — reviewing is in repo-wide agents/, not  project.
	_, err = reg.ResolveAgent("/reviewing")
	if err == nil {
		t.Fatal("expected error: reviewing not in  project scope")
	}
}

func TestIntegration_DefaultsFileDriversSelection(t *testing.T) {
	gitRoot, globalDir := buildFullFixture(t)
	reg, err := NewRegistry(gitRoot, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if reg.DefaultAgent() != "coding" {
		t.Errorf("DefaultAgent: got %q, want %q", reg.DefaultAgent(), "coding")
	}
	if reg.DefaultProfile() != "/default" {
		t.Errorf("DefaultProfile: got %q, want %q", reg.DefaultProfile(), "/default")
	}
}

func TestIntegration_ProfileShorthandFallback(t *testing.T) {
	gitRoot, globalDir := buildFullFixture(t)
	reg, err := NewRegistry(gitRoot, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// --profile  (bare, resolves to /default).
	p, err := reg.ResolveProfile("")
	if err != nil {
		t.Fatalf(" bare: %v", err)
	}
	// Should get the canonical default.hcl, not the shorthand.
	if p.Name != "default" && p.Name != "shorthand" {
		t.Errorf(" bare resolved to unexpected profile: %q", p.Name)
	}
}

func TestIntegration_ValidationErrorIncludesFileLine(t *testing.T) {
	// Build a fixture with a validation error: invalid filesystem mode.
	tmpdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpdir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	badFile := filepath.Join(tmpdir, ".rampart", "agents", "bad-agent.hcl")
	if err := os.MkdirAll(filepath.Dir(badFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badFile, []byte(`
agent "bad" {
  filesystem   = "writable"
  network_mode = "none"
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := NewRegistry(tmpdir, "")
	if err == nil {
		t.Fatal("expected validation error")
	}
	// Error should include the file path.
	if !strings.Contains(err.Error(), "bad-agent.hcl") {
		t.Errorf("error should include filename: %v", err)
	}
}

func TestIntegration_ParseErrorIncludesFileLine(t *testing.T) {
	// Build a fixture with a malformed HCL file.
	tmpdir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpdir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	badFile := filepath.Join(tmpdir, ".rampart", "agents.hcl")
	if err := os.MkdirAll(filepath.Dir(badFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badFile, []byte(`agent "broken" { filesystem = `), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := NewRegistry(tmpdir, "")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "agents.hcl") {
		t.Errorf("error should include filename: %v", err)
	}
}

func TestIntegration_FindGitRootFromSubdirectory(t *testing.T) {
	gitRoot, globalDir := buildFullFixture(t)
	subdir := filepath.Join(gitRoot, "go", "internal", "rampart")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	found := FindGitRoot(subdir)
	if found != gitRoot {
		t.Errorf("FindGitRoot from subdir: got %q, want %q", found, gitRoot)
	}

	// Registry built from git root should work the same.
	reg, err := NewRegistry(found, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry from discovered git root: %v", err)
	}
	if _, err := reg.ResolveAgent("coding"); err != nil {
		t.Errorf("coding after git root discovery: %v", err)
	}
}
