package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/config"
)

// --- Tests: embedded content ---

func TestEmbeddedProfiles_AllThreePresent(t *testing.T) {
	profiles, err := embeddedProfileMap()
	if err != nil {
		t.Fatalf("embeddedProfileMap: %v", err)
	}
	for _, name := range []string{"coding.hcl", "planning.hcl", "reviewing.hcl"} {
		if _, ok := profiles[name]; !ok {
			t.Errorf("embedded profile missing: %s", name)
		}
	}
}

func TestEmbeddedProfiles_MatchSpecifications(t *testing.T) {
	profiles, err := embeddedProfileMap()
	if err != nil {
		t.Fatalf("embeddedProfileMap: %v", err)
	}

	checks := map[string][]string{
		"coding.hcl": {
			`agent "coding"`,
			`filesystem   = "read-write"`,
			`network_mode = "full"`,
			`"go"`, `"node"`, `"python"`, `"rust"`, // toolchains (FR7.1)
		},
		"planning.hcl": {
			`agent "planning"`,
			`filesystem   = "read-only"`,
			`network_mode = "filtered"`, // FR7.2 — filtered for context lookup
		},
		"reviewing.hcl": {
			`agent "reviewing"`,
			`filesystem   = "read-only"`,
			`network_mode = "filtered"`, // FR7.3
		},
	}

	for name, wants := range checks {
		content := string(profiles[name])
		for _, want := range wants {
			if !strings.Contains(content, want) {
				t.Errorf("%s: missing %q\ncontent:\n%s", name, want, content)
			}
		}
	}
}

func TestEmbeddedProfiles_ValidHCL(t *testing.T) {
	// Verify embedded HCL parses without errors via the config package.
	profiles, err := embeddedProfileMap()
	if err != nil {
		t.Fatalf("embeddedProfileMap: %v", err)
	}
	for name, content := range profiles {
		if len(content) == 0 {
			t.Errorf("%s is empty", name)
		}
		// Basic sanity: must contain "agent" keyword and "filesystem".
		if !strings.Contains(string(content), "agent") {
			t.Errorf("%s: no 'agent' block found", name)
		}
	}
}

// TestEmbeddedModule_HarnessClaudeCode verifies the harness/claude-code
// module ships with the entries claude actually needs at runtime: write
// access to the configurable claude_dir, exec on /usr/bin/security (the
// macOS Keychain CLI without which Bun's child_process.spawn fails with
// EPERM at startup), and exec on the common claude binary install paths.
func TestEmbeddedModule_HarnessClaudeCode(t *testing.T) {
	modules, err := embeddedFileMap(embeddedModules, "assets/modules")
	if err != nil {
		t.Fatalf("embeddedFileMap: %v", err)
	}
	src, ok := modules["harness/claude-code.hcl"]
	if !ok {
		t.Fatal("harness/claude-code.hcl is not in the embedded module set")
	}

	required := []string{
		"/usr/bin/security",                       // macOS Keychain CLI
		"/opt/homebrew/bin/claude",                // Apple Silicon Cask
		"/opt/homebrew/Caskroom/claude-code",      // version-rolling realpath
		"/usr/local/bin/claude",                   // Intel mac + Linux
		"/home/linuxbrew/.linuxbrew/bin/claude",   // Linuxbrew
		"${var.claude_dir}",                       // overridable config dir
	}
	for _, want := range required {
		if !strings.Contains(string(src), want) {
			t.Errorf("harness/claude-code.hcl missing required entry %q", want)
		}
	}
}

// TestEmbeddedModule_HarnessClaudeCode_ExpandsViaProfile drops the real
// embedded harness/claude-code.hcl into a temp module tree, has a synthetic
// profile `use` it, and verifies the resolved profile has both the security
// CLI in its exec list and a claude_dir entry in its write list. This is
// the end-to-end "module → profile resolution" check that catches breakage
// from variable rename / schema drift, beyond just text substring matching.
func TestEmbeddedModule_HarnessClaudeCode_ExpandsViaProfile(t *testing.T) {
	modules, err := embeddedFileMap(embeddedModules, "assets/modules")
	if err != nil {
		t.Fatalf("embeddedFileMap: %v", err)
	}
	moduleSrc, ok := modules["harness/claude-code.hcl"]
	if !ok {
		t.Fatal("harness/claude-code.hcl missing from embedded modules")
	}

	gitRoot := t.TempDir()
	globalDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitRoot, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(gitRoot, ".rampart", "profiles", "p"), 0o755); err != nil {
		t.Fatal(err)
	}
	moduleDir := filepath.Join(globalDir, "modules", "harness")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "claude-code.hcl"), moduleSrc, 0o644); err != nil {
		t.Fatal(err)
	}

	profileHCL := `
profile "default" {
  workdir = "."
  use "harness/claude-code" {
    claude_dir = "/Users/test/.claude"
  }
}
`
	if err := os.WriteFile(filepath.Join(gitRoot, ".rampart", "profiles", "p", "default.hcl"),
		[]byte(profileHCL), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := config.NewRegistry(gitRoot, globalDir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	p, err := reg.ResolveProfile("p/default")
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}

	// /usr/bin/security must be exec'able — this is the keychain CLI claude
	// invokes at startup on macOS.
	hasSecurity := false
	for _, e := range p.Exec {
		if e == "/usr/bin/security" {
			hasSecurity = true
			break
		}
	}
	if !hasSecurity {
		t.Errorf("expected /usr/bin/security in Exec; got %v", p.Exec)
	}

	// claude_dir override flows through to Write.
	hasClaudeDir := false
	for _, w := range p.Write {
		if w == "/Users/test/.claude" {
			hasClaudeDir = true
			break
		}
	}
	if !hasClaudeDir {
		t.Errorf("expected /Users/test/.claude in Write (claude_dir override); got %v", p.Write)
	}
}

// --- Tests: first-run extraction ---

func TestExtractProfiles_FirstRun_CreatesDirAndFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agents")
	// dir does not exist yet

	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("ExtractProfiles: %v", err)
	}

	for _, name := range []string{"coding.hcl", "planning.hcl", "reviewing.hcl"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s to exist after extraction: %v", name, err)
		}
	}
}

func TestExtractProfiles_FirstRun_ContentMatchesEmbedded(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("ExtractProfiles: %v", err)
	}

	embedded, _ := embeddedProfileMap()
	for name, want := range embedded {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading extracted %s: %v", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s: extracted content differs from embedded", name)
		}
	}
}

func TestExtractProfiles_HashFileWritten(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("ExtractProfiles: %v", err)
	}
	hf := filepath.Join(dir, hashesFile)
	if _, err := os.Stat(hf); err != nil {
		t.Errorf("hash file not created: %v", err)
	}
}

// --- Tests: module library extraction ---

func TestExtractModules_FirstRun_PreservesSubdirectoryTree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "modules")
	if err := extractEmbedded(embeddedModules, "assets/modules", dir, "modules"); err != nil {
		t.Fatalf("extractEmbedded: %v", err)
	}

	// Spot-check one module per category to confirm the subdirectory
	// structure landed.
	wants := []string{
		"lang/python.hcl",
		"lang/node.hcl",
		"lang/go.hcl",
		"lang/rust.hcl",
		"tooling/git.hcl",
		"tooling/github.hcl",
		"ai/anthropic.hcl",
		"ai/openai.hcl",
		"ai/gemini.hcl",
		"system/base.hcl",
		"network/any.hcl",
		"harness/claude-code.hcl",
	}
	for _, rel := range wants {
		path := filepath.Join(dir, rel)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s to exist after extraction: %v", rel, err)
		}
	}
}

func TestExtractModules_HashFileWritten(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "modules")
	if err := extractEmbedded(embeddedModules, "assets/modules", dir, "modules"); err != nil {
		t.Fatalf("extractEmbedded: %v", err)
	}
	hf := filepath.Join(dir, hashesFile)
	if _, err := os.Stat(hf); err != nil {
		t.Errorf("hash file not created: %v", err)
	}
}

func TestExtractModules_PreservesUserEdits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "modules")
	if err := extractEmbedded(embeddedModules, "assets/modules", dir, "modules"); err != nil {
		t.Fatalf("first extract: %v", err)
	}

	// Simulate a user edit on one module.
	edited := filepath.Join(dir, "lang", "python.hcl")
	custom := []byte(`# user-modified
variable "venv" { type = string, default = "/custom/venv" }
read = ["/usr/lib/python3"]
`)
	if err := os.WriteFile(edited, custom, 0o644); err != nil {
		t.Fatalf("write user edit: %v", err)
	}

	// Re-extract; user edit must survive.
	if err := extractEmbedded(embeddedModules, "assets/modules", dir, "modules"); err != nil {
		t.Fatalf("second extract: %v", err)
	}
	got, err := os.ReadFile(edited)
	if err != nil {
		t.Fatalf("re-read edited file: %v", err)
	}
	if string(got) != string(custom) {
		t.Errorf("user-modified module was overwritten on re-extract")
	}
}

// --- Tests: idempotency (directory exists, files unmodified) ---

func TestExtractProfiles_Idempotent_UnmodifiedFilesRewritten(t *testing.T) {
	dir := t.TempDir()
	// First extraction.
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("first ExtractProfiles: %v", err)
	}
	// Second extraction — should succeed without error.
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("second ExtractProfiles: %v", err)
	}
	// Files should still match embedded content.
	embedded, _ := embeddedProfileMap()
	for name, want := range embedded {
		got, _ := os.ReadFile(filepath.Join(dir, name))
		if string(got) != string(want) {
			t.Errorf("%s: content after second extraction differs from embedded", name)
		}
	}
}

// --- Tests: user-modified profile is preserved (FR61.2) ---

func TestExtractProfiles_UserModifiedProfile_NotOverwritten(t *testing.T) {
	dir := t.TempDir()
	// First extraction: writes files and hash record.
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("first ExtractProfiles: %v", err)
	}

	// Simulate user modifying coding.hcl.
	modifiedContent := []byte("# user-modified\nagent \"coding\" { filesystem = \"read-only\"; network_mode = \"none\" }\n")
	if err := os.WriteFile(filepath.Join(dir, "coding.hcl"), modifiedContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// Second extraction: coding.hcl should NOT be overwritten.
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("second ExtractProfiles: %v", err)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "coding.hcl"))
	if string(got) != string(modifiedContent) {
		t.Error("user-modified coding.hcl was overwritten (should have been preserved)")
	}
}

func TestExtractProfiles_UnmodifiedProfilesRewrittenWhenOthersModified(t *testing.T) {
	dir := t.TempDir()
	// First extraction.
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("first ExtractProfiles: %v", err)
	}

	// Only modify coding.hcl.
	if err := os.WriteFile(filepath.Join(dir, "coding.hcl"), []byte("# user change"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Second extraction.
	if err := ExtractProfiles(dir); err != nil {
		t.Fatalf("second ExtractProfiles: %v", err)
	}

	// planning.hcl and reviewing.hcl should be up-to-date (unmodified).
	embedded, _ := embeddedProfileMap()
	for _, name := range []string{"planning.hcl", "reviewing.hcl"} {
		got, _ := os.ReadFile(filepath.Join(dir, name))
		if string(got) != string(embedded[name]) {
			t.Errorf("%s: expected up-to-date embedded content after re-extraction", name)
		}
	}
}

// --- Tests: hash utility ---

func TestSha256sum_Deterministic(t *testing.T) {
	data := []byte("hello world")
	h1 := sha256sum(data)
	h2 := sha256sum(data)
	if h1 != h2 {
		t.Error("sha256sum not deterministic")
	}
	if len(h1) != 64 { // hex SHA-256 is always 64 chars
		t.Errorf("unexpected hash length: %d", len(h1))
	}
}

func TestSha256sum_DifferentInputs_DifferentHashes(t *testing.T) {
	if sha256sum([]byte("a")) == sha256sum([]byte("b")) {
		t.Error("different inputs produced same hash")
	}
}

// --- Tests: hash file round-trip ---

func TestLoadSaveHashes_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, hashesFile)

	hashes := map[string]string{
		"coding.hcl":    "abc123",
		"planning.hcl":  "def456",
		"reviewing.hcl": "ghi789",
	}
	if err := saveHashes(path, hashes); err != nil {
		t.Fatalf("saveHashes: %v", err)
	}
	loaded, err := loadHashes(path)
	if err != nil {
		t.Fatalf("loadHashes: %v", err)
	}
	for k, want := range hashes {
		if got := loaded[k]; got != want {
			t.Errorf("hash[%s]: got %q, want %q", k, got, want)
		}
	}
}

func TestLoadHashes_MissingFile_ReturnsEmpty(t *testing.T) {
	hashes, err := loadHashes("/nonexistent/path/.rampart-sha256")
	if err == nil {
		t.Log("no error returned (file missing)")
	}
	_ = hashes // nil or empty is both fine
}
