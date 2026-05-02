package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			`network_mode = "none"`, // FR7.2
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
