package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeModuleFile is a tiny test helper that drops `content` into
// <root>/<rel>.hcl, creating intermediate directories. Returns the
// absolute path it wrote to so tests can assert on it.
func writeModuleFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	abs := filepath.Join(root, rel+".hcl")
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(abs), err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", abs, err)
	}
	return abs
}

// modSearchRoot builds a search-root layout for module tests: returns the
// directory tree where modules live (caller writes <root>/<rel>.hcl). The
// expander treats this as either a repo root or a global root depending
// on which arg the test passes.
func modSearchRoot(t *testing.T, label string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), label, ".rampart", "modules")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", d, err)
	}
	return d
}

// loadProfileWithUse drops a profile.hcl + module tree under tmp dirs,
// runs the registry indexing path, and returns the resolved profile.
// gitRoot's modules dir is .rampart/modules; globalDir's is modules.
func loadProfileWithUse(t *testing.T, profileSrc string, modules map[string]string, repoMods map[string]string) (*ProfileConfig, error) {
	t.Helper()
	gitRoot := t.TempDir()
	globalDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitRoot, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(gitRoot, ".rampart", "profiles", "p"), 0o755); err != nil {
		t.Fatalf("mkdir profiles/p: %v", err)
	}
	profilePath := filepath.Join(gitRoot, ".rampart", "profiles", "p", "default.hcl")
	if err := os.WriteFile(profilePath, []byte(profileSrc), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	for rel, content := range modules {
		writeModuleFile(t, filepath.Join(globalDir, "modules"), rel, content)
	}
	for rel, content := range repoMods {
		writeModuleFile(t, filepath.Join(gitRoot, ".rampart", "modules"), rel, content)
	}
	reg, err := NewRegistry(gitRoot, globalDir)
	if err != nil {
		return nil, err
	}
	return reg.ResolveProfile("p/default")
}

// TestExpandUse_StringVarSubstitution exercises the load-bearing happy path:
// a profile uses a module with a string parameter, ${var.foo} interpolates
// into the module's path lists, and the resulting profile carries them.
func TestExpandUse_StringVarSubstitution(t *testing.T) {
	moduleSrc := `
variable "venv" {
  type    = string
  default = ".venv"
}

read = ["/usr/lib/python3"]
exec = ["${var.venv}/bin/python", "${var.venv}/bin/pip"]
write = ["${var.venv}"]
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "lang/python" {
    venv = "/home/user/repo/.venv"
  }
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"lang/python": moduleSrc,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	wantExec := []string{"/home/user/repo/.venv/bin/python", "/home/user/repo/.venv/bin/pip"}
	if !sliceEqual(p.Exec, wantExec) {
		t.Errorf("Exec = %v, want %v", p.Exec, wantExec)
	}
	if !sliceEqual(p.Write, []string{"/home/user/repo/.venv"}) {
		t.Errorf("Write = %v, want [\"/home/user/repo/.venv\"]", p.Write)
	}
	if !sliceEqual(p.Read, []string{"/usr/lib/python3"}) {
		t.Errorf("Read = %v, want [\"/usr/lib/python3\"]", p.Read)
	}
}

// TestExpandUse_DefaultsApply when an arg is omitted, the module's default
// is used.
func TestExpandUse_DefaultsApply(t *testing.T) {
	moduleSrc := `
variable "venv" {
  type    = string
  default = ".venv"
}
exec = ["${var.venv}/bin/python"]
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "lang/python" {}
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"lang/python": moduleSrc,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !sliceEqual(p.Exec, []string{".venv/bin/python"}) {
		t.Errorf("Exec = %v, want [\".venv/bin/python\"]", p.Exec)
	}
}

// TestExpandUse_RequiredVarMissing returns a clear error pointing at the
// use block.
func TestExpandUse_RequiredVarMissing(t *testing.T) {
	moduleSrc := `
variable "venv" { type = string }
exec = ["${var.venv}/bin/python"]
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "lang/python" {}
}
`
	_, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"lang/python": moduleSrc,
	}, nil)
	if err == nil {
		t.Fatal("expected error for missing required variable")
	}
	// HCL's schema-driven decode emits "Missing required argument" before
	// our custom fallback check fires; either wording is acceptable as long
	// as the variable name appears.
	if !strings.Contains(err.Error(), "venv") {
		t.Errorf("error message must name the missing variable: got %q", err.Error())
	}
	if !strings.Contains(strings.ToLower(err.Error()), "required") &&
		!strings.Contains(strings.ToLower(err.Error()), "missing") {
		t.Errorf("error message should signal missing/required: got %q", err.Error())
	}
}

// TestExpandUse_UnknownArg is rejected by the schema-driven decode of the
// use block body.
func TestExpandUse_UnknownArg(t *testing.T) {
	moduleSrc := `
variable "venv" { type = string, default = ".venv" }
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "lang/python" {
    venv      = "/v"
    not_a_var = "x"
  }
}
`
	_, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"lang/python": moduleSrc,
	}, nil)
	if err == nil {
		t.Fatal("expected error for unknown argument")
	}
}

// TestExpandUse_TypeMismatch rejects a list arg passed to a string variable.
func TestExpandUse_TypeMismatch(t *testing.T) {
	moduleSrc := `
variable "name" { type = string }
exec = ["${var.name}"]
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "lang/x" {
    name = ["a", "b"]
  }
}
`
	_, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"lang/x": moduleSrc,
	}, nil)
	if err == nil {
		t.Fatal("expected type mismatch error")
	}
}

// TestExpandUse_ListStringVar covers the second supported v1 type.
func TestExpandUse_ListStringVar(t *testing.T) {
	moduleSrc := `
variable "extras" {
  type    = list(string)
  default = ["/etc/ssl"]
}
read = var.extras
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "system/extras" {
    extras = ["/a", "/b"]
  }
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"system/extras": moduleSrc,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !sliceEqual(p.Read, []string{"/a", "/b"}) {
		t.Errorf("Read = %v, want [/a /b]", p.Read)
	}
}

// TestExpandUse_DedupPaths concatenated then deduped — two modules each
// granting /usr/bin yield one entry.
func TestExpandUse_DedupPaths(t *testing.T) {
	a := `read = ["/usr/bin", "/usr/share"]`
	b := `read = ["/usr/bin", "/etc"]`
	profileSrc := `
profile "default" {
  workdir = "."
  use "a" {}
  use "b" {}
  read = ["/usr/bin", "/var/log"]
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"a": a,
		"b": b,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []string{"/usr/bin", "/var/log", "/usr/share", "/etc"}
	if !sliceEqual(p.Read, want) {
		t.Errorf("Read = %v, want %v (dedup of /usr/bin, original order preserved)", p.Read, want)
	}
}

// TestExpandUse_NetworkConcat both modules contribute domain blocks; the
// resulting profile has both.
func TestExpandUse_NetworkConcat(t *testing.T) {
	a := `
network {
  domain "api.anthropic.com" {
  }
}
`
	b := `
network {
  domain "api.openai.com" {
  }
}
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "ai/anthropic" {}
  use "ai/openai" {}
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"ai/anthropic": a,
		"ai/openai":    b,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.Network == nil || len(p.Network.Domains) != 2 {
		t.Fatalf("expected 2 domain blocks, got %+v", p.Network)
	}
	patterns := []string{p.Network.Domains[0].Pattern, p.Network.Domains[1].Pattern}
	wantA, wantB := "api.anthropic.com", "api.openai.com"
	if !((patterns[0] == wantA && patterns[1] == wantB) || (patterns[0] == wantB && patterns[1] == wantA)) {
		t.Errorf("domain patterns = %v, want both of %s and %s", patterns, wantA, wantB)
	}
}

// TestExpandUse_TransitiveComposition module A uses module B; profile uses
// A; B's contributions show up in the resolved profile.
func TestExpandUse_TransitiveComposition(t *testing.T) {
	base := `read = ["/etc/passwd"]`
	withBase := `
use "system/base" {}
read = ["/etc/hosts"]
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "system/with-base" {}
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"system/base":      base,
		"system/with-base": withBase,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []string{"/etc/hosts", "/etc/passwd"}
	if !sliceEqual(p.Read, want) {
		t.Errorf("Read = %v, want %v", p.Read, want)
	}
}

// TestExpandUse_TransitiveVarPassthrough parent module accepts a variable
// and forwards it to a child via the var.x reference syntax.
func TestExpandUse_TransitiveVarPassthrough(t *testing.T) {
	child := `
variable "p" { type = string }
exec = ["${var.p}/bin"]
`
	parent := `
variable "venv" { type = string }
use "child" {
  p = "${var.venv}/wrapper"
}
`
	profileSrc := `
profile "default" {
  workdir = "."
  use "parent" {
    venv = "/opt/v"
  }
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"parent": parent,
		"child":  child,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !sliceEqual(p.Exec, []string{"/opt/v/wrapper/bin"}) {
		t.Errorf("Exec = %v, want [\"/opt/v/wrapper/bin\"]", p.Exec)
	}
}

// TestExpandUse_DirectCycle a self-cycle (a uses a) is rejected with a
// clear chain.
func TestExpandUse_DirectCycle(t *testing.T) {
	a := `use "a" {}`
	profileSrc := `
profile "default" {
  workdir = "."
  use "a" {}
}
`
	_, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"a": a,
	}, nil)
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error must mention cycle, got %q", err.Error())
	}
}

// TestExpandUse_IndirectCycle a → b → a is rejected.
func TestExpandUse_IndirectCycle(t *testing.T) {
	a := `use "b" {}`
	b := `use "a" {}`
	profileSrc := `
profile "default" {
  workdir = "."
  use "a" {}
}
`
	_, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"a": a,
		"b": b,
	}, nil)
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error must mention cycle, got %q", err.Error())
	}
}

// TestResolveModulePath_RepoBeatsGlobal repo-local modules take precedence
// over globally-installed ones with the same relative name. This is the
// search-path "first match wins" rule.
func TestResolveModulePath_RepoBeatsGlobal(t *testing.T) {
	repoMod := `read = ["/repo"]`
	globalMod := `read = ["/global"]`
	profileSrc := `
profile "default" {
  workdir = "."
  use "shared" {}
}
`
	p, err := loadProfileWithUse(t, profileSrc, map[string]string{
		"shared": globalMod,
	}, map[string]string{
		"shared": repoMod,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !sliceEqual(p.Read, []string{"/repo"}) {
		t.Errorf("Read = %v, want [/repo] (repo-local must win)", p.Read)
	}
}

// TestResolveModulePath_NotFound returns a useful error listing the
// search paths it tried.
func TestResolveModulePath_NotFound(t *testing.T) {
	profileSrc := `
profile "default" {
  workdir = "."
  use "missing/module" {}
}
`
	_, err := loadProfileWithUse(t, profileSrc, nil, nil)
	if err == nil {
		t.Fatal("expected not-found error")
	}
	if !strings.Contains(err.Error(), "missing/module") {
		t.Errorf("error must name the missing module, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "tried") {
		t.Errorf("error should list attempted paths, got %q", err.Error())
	}
}

// TestParseModuleFile_DuplicateVariable rejected at parse time.
func TestParseModuleFile_DuplicateVariable(t *testing.T) {
	src := `
variable "x" { type = string }
variable "x" { type = string }
`
	_, err := ParseModuleFile("/test/dup.hcl", "dup", []byte(src))
	if err == nil {
		t.Fatal("expected duplicate-variable error")
	}
}

// TestParseModuleFile_UnsupportedType rejects v1-out-of-scope types.
func TestParseModuleFile_UnsupportedType(t *testing.T) {
	src := `
variable "x" { type = bool }
`
	_, err := ParseModuleFile("/test/badtype.hcl", "badtype", []byte(src))
	if err == nil {
		t.Fatal("expected unsupported-type error")
	}
	if !strings.Contains(err.Error(), "unsupported type") {
		t.Errorf("error must mention unsupported type, got %q", err.Error())
	}
}

// TestParseModuleFile_DefaultTypeMismatch a string default for a
// list(string) variable is rejected.
func TestParseModuleFile_DefaultTypeMismatch(t *testing.T) {
	src := `
variable "x" {
  type    = list(string)
  default = "scalar"
}
`
	_, err := ParseModuleFile("/test/typemismatch.hcl", "typemismatch", []byte(src))
	if err == nil {
		t.Fatal("expected default type-mismatch error")
	}
}

// sliceEqual compares string slices in order.
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
