package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestMigrateLegacyUserDir_RemovesUnmodifiedFiles drops the .rampart-sha256
// manifest + a file whose hash matches the manifest; after migration the
// file is gone, the manifest is gone, and the parent directories are
// cleaned up.
func TestMigrateLegacyUserDir_RemovesUnmodifiedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	modulesDir := filepath.Join(home, ".local", "share", "rampart", "modules")
	if err := os.MkdirAll(filepath.Join(modulesDir, "network"), 0o755); err != nil {
		t.Fatal(err)
	}

	content := []byte("# bundled network/any.hcl\nallowed_domains = [\"*\"]\n")
	contentPath := filepath.Join(modulesDir, "network", "any.hcl")
	if err := os.WriteFile(contentPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(modulesDir, ".rampart-sha256")
	sum := sha256.Sum256(content)
	if err := os.WriteFile(manifestPath, []byte("network/any.hcl="+hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := migrateLegacyUserDir(); err != nil {
		t.Fatalf("migrateLegacyUserDir: %v", err)
	}

	if _, err := os.Stat(contentPath); !os.IsNotExist(err) {
		t.Errorf("module file should have been removed; stat err: %v", err)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Errorf("manifest should have been removed; stat err: %v", err)
	}
}

// TestMigrateLegacyUserDir_PreservesUserEdits keeps any file whose hash
// has drifted from the manifest. User edits survive even though rampart
// no longer manages the dir.
func TestMigrateLegacyUserDir_PreservesUserEdits(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	modulesDir := filepath.Join(home, ".local", "share", "rampart", "modules")
	if err := os.MkdirAll(filepath.Join(modulesDir, "network"), 0o755); err != nil {
		t.Fatal(err)
	}

	originalContent := []byte("# bundled\n")
	editedContent := []byte("# user-edited\n")
	contentPath := filepath.Join(modulesDir, "network", "any.hcl")
	// File on disk is the EDITED version; manifest records hash of the
	// pristine bundled version.
	if err := os.WriteFile(contentPath, editedContent, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(modulesDir, ".rampart-sha256")
	origSum := sha256.Sum256(originalContent)
	if err := os.WriteFile(manifestPath, []byte("network/any.hcl="+hex.EncodeToString(origSum[:])+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := migrateLegacyUserDir(); err != nil {
		t.Fatalf("migrateLegacyUserDir: %v", err)
	}

	got, err := os.ReadFile(contentPath)
	if err != nil {
		t.Fatalf("user-edited file should have survived: %v", err)
	}
	if string(got) != string(editedContent) {
		t.Errorf("user edits clobbered: got %q, want %q", got, editedContent)
	}
	// Manifest should still exist so the next run can re-evaluate (in
	// case the user reverts their edit).
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("manifest should be kept when user edits survive: %v", err)
	}
}

// TestMigrateLegacyUserDir_NoManifest_NoOp is idempotent / safe when
// there's no manifest to act on (fresh install or already migrated).
func TestMigrateLegacyUserDir_NoManifest_NoOp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := migrateLegacyUserDir(); err != nil {
		t.Errorf("migrateLegacyUserDir should be a safe no-op: %v", err)
	}
}
