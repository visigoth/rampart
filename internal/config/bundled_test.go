package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/visigoth/rampart/internal/config"
)

// TestResolveModuleContent_FallsBackToBundled verifies the new precedence
// order: disk (repo / user-global) wins when present, but a missing
// module is resolved from the bundled fs.FS. Prevents regression of the
// "auto-extract to user dir, then forget to refresh on upgrade" pattern.
func TestResolveModuleContent_FallsBackToBundled(t *testing.T) {
	bundled := fstest.MapFS{
		"assets/modules/network/any.hcl": &fstest.MapFile{
			Data: []byte("# bundled-network-any\nallowed_domains = [\"*\"]\n"),
		},
	}

	src, origin, err := config.ResolveModuleContent("network/any", "", "", bundled)
	if err != nil {
		t.Fatalf("ResolveModuleContent: %v", err)
	}
	if !strings.Contains(string(src), "bundled-network-any") {
		t.Errorf("expected bundled content; got %q", string(src))
	}
	if !strings.HasPrefix(origin, "bundled:") {
		t.Errorf("origin = %q, want a bundled: prefix", origin)
	}
}

// TestResolveModuleContent_DiskBeatsBundled asserts that a user-supplied
// module at the global-user-dir layer still shadows the bundled default.
// This is the path that lets users override bundled content (e.g. drop
// a custom network/any.hcl into ~/.local/share/rampart/modules/).
func TestResolveModuleContent_DiskBeatsBundled(t *testing.T) {
	globalDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(globalDir, "modules", "network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(globalDir, "modules", "network", "any.hcl"),
		[]byte("# user-override-network-any\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	bundled := fstest.MapFS{
		"assets/modules/network/any.hcl": &fstest.MapFile{
			Data: []byte("# bundled-network-any\n"),
		},
	}

	src, origin, err := config.ResolveModuleContent("network/any", "", globalDir, bundled)
	if err != nil {
		t.Fatalf("ResolveModuleContent: %v", err)
	}
	if !strings.Contains(string(src), "user-override-network-any") {
		t.Errorf("expected user override to win; got %q", string(src))
	}
	if strings.HasPrefix(origin, "bundled:") {
		t.Errorf("origin = %q, expected disk path (user dir should beat bundled)", origin)
	}
}

// TestResolveModuleContent_NoBundled_NotFound checks the error path:
// nil bundled fs + no on-disk hit produces a useful error listing every
// place that was tried.
func TestResolveModuleContent_NoBundled_NotFound(t *testing.T) {
	_, _, err := config.ResolveModuleContent("nope/missing", "/no/such/git", t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found': %v", err)
	}
}

// TestResolveModuleContentFromDirs_PrecedenceOrder verifies the four-tier
// resolution chain when running under `just install`-style wiring: the
// per-repo dir beats the user-override dir, which beats the install
// share dir, which beats the embedded fallback. This is the canonical
// production setup — getting this wrong is how upgrades go silently
// stale.
func TestResolveModuleContentFromDirs_PrecedenceOrder(t *testing.T) {
	userDir := t.TempDir()
	installDir := t.TempDir()
	gitRoot := t.TempDir()

	for _, fixture := range []struct {
		root, tag string
	}{
		{gitRoot, "from-repo"},
		{userDir, "from-user-override"},
		{installDir, "from-install-share"},
	} {
		dir := filepath.Join(fixture.root, "modules", "tooling")
		if fixture.root == gitRoot {
			dir = filepath.Join(fixture.root, ".rampart", "modules", "tooling")
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "demo.hcl"),
			[]byte("# "+fixture.tag+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	bundled := fstest.MapFS{
		"assets/modules/tooling/demo.hcl": &fstest.MapFile{
			Data: []byte("# from-bundled-embed\n"),
		},
	}

	// All four sources present → repo wins.
	src, _, err := config.ResolveModuleContentFromDirs("tooling/demo", gitRoot,
		[]string{userDir, installDir}, bundled)
	if err != nil {
		t.Fatalf("all sources: %v", err)
	}
	if !strings.Contains(string(src), "from-repo") {
		t.Errorf("expected repo to win; got %q", src)
	}

	// Drop repo → user-override wins.
	os.RemoveAll(filepath.Join(gitRoot, ".rampart"))
	src, _, err = config.ResolveModuleContentFromDirs("tooling/demo", gitRoot,
		[]string{userDir, installDir}, bundled)
	if err != nil {
		t.Fatalf("no repo: %v", err)
	}
	if !strings.Contains(string(src), "from-user-override") {
		t.Errorf("expected user override to win; got %q", src)
	}

	// Drop user-override → install-share-dir wins.
	os.RemoveAll(filepath.Join(userDir, "modules"))
	src, _, err = config.ResolveModuleContentFromDirs("tooling/demo", gitRoot,
		[]string{userDir, installDir}, bundled)
	if err != nil {
		t.Fatalf("install-share only: %v", err)
	}
	if !strings.Contains(string(src), "from-install-share") {
		t.Errorf("expected install-share to win; got %q", src)
	}

	// Drop install-share-dir → bundled embed wins (go-install fallback).
	os.RemoveAll(filepath.Join(installDir, "modules"))
	src, origin, err := config.ResolveModuleContentFromDirs("tooling/demo", gitRoot,
		[]string{userDir, installDir}, bundled)
	if err != nil {
		t.Fatalf("bundled only: %v", err)
	}
	if !strings.Contains(string(src), "from-bundled-embed") {
		t.Errorf("expected bundled to win; got %q", src)
	}
	if !strings.HasPrefix(origin, "bundled:") {
		t.Errorf("expected bundled: origin prefix; got %q", origin)
	}
}

// TestNewRegistryWithBundled_IndexesBundledAgents verifies that an agent
// living only in the bundled fs.FS is discovered by the registry (no
// on-disk extraction required).
func TestNewRegistryWithBundled_IndexesBundledAgents(t *testing.T) {
	bundled := fstest.MapFS{
		"assets/agents/coding.hcl": &fstest.MapFile{
			Data: []byte(`agent "coding" {
  filesystem   = "read-write"
  network_mode = "filtered"
}
`),
		},
	}

	reg, err := config.NewRegistryWithBundled("", "", bundled)
	if err != nil {
		t.Fatalf("NewRegistryWithBundled: %v", err)
	}
	a, err := reg.ResolveAgent("coding")
	if err != nil {
		t.Fatalf("ResolveAgent(coding): %v", err)
	}
	if a.Filesystem != "read-write" {
		t.Errorf("Filesystem = %q, want read-write", a.Filesystem)
	}
}
