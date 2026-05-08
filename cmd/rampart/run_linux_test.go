//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/visigoth/rampart/internal/policy"
)

// TestAbsolutizePolicyPaths_RelativeAgainstWorkdir confirms HCL-style
// relative grants ("." / "subdir") become absolute against the launch
// workdir. Without this, bwrap's `--bind . .` is interpreted relative to
// bwrap's launch CWD which is unreliable across nested mount namespaces
// (the bug 's E2E first surfaced).
func TestAbsolutizePolicyPaths_RelativeAgainstWorkdir(t *testing.T) {
	wd, err := os.MkdirTemp("/tmp", "absolutize")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(wd) })

	resolved, err := filepath.EvalSymlinks(wd)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	rp := &policy.ResolvedPolicy{
		Workdir: ".",
		Read:    []string{"."},
		Write:   []string{".", "subdir"},
		Exec:    []string{"."},
	}
	if err := os.MkdirAll(filepath.Join(wd, "subdir"), 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	out := absolutizePolicyPaths(rp, wd)

	if out.Workdir != resolved {
		t.Errorf("Workdir = %q, want %q", out.Workdir, resolved)
	}
	if len(out.Read) != 1 || out.Read[0] != resolved {
		t.Errorf("Read = %v, want [%q]", out.Read, resolved)
	}
	if len(out.Write) != 2 {
		t.Fatalf("Write = %v, want 2 entries", out.Write)
	}
	if out.Write[0] != resolved {
		t.Errorf("Write[0] = %q, want %q", out.Write[0], resolved)
	}
	if want := filepath.Join(resolved, "subdir"); out.Write[1] != want {
		t.Errorf("Write[1] = %q, want %q", out.Write[1], want)
	}
}

// TestAbsolutizePolicyPaths_AbsolutePathsUnchanged ensures absolute paths
// pass through untouched (modulo symlink eval) — the resolver must not
// re-anchor /etc/passwd to the workdir.
func TestAbsolutizePolicyPaths_AbsolutePathsUnchanged(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		Workdir: "/var/empty",
		Read:    []string{"/etc/passwd"},
	}
	out := absolutizePolicyPaths(rp, "/tmp")
	if out.Workdir != "/var/empty" {
		t.Errorf("Workdir absolute path mutated: %q", out.Workdir)
	}
	if len(out.Read) != 1 || out.Read[0] != "/etc/passwd" {
		t.Errorf("Read absolute path mutated: %v", out.Read)
	}
}

// TestAbsolutizePolicyPaths_EmptyWorkdir documents that an empty workdir
// stays empty — bwrap.go's `if rp.Workdir != ""` skip kicks in. Avoids
// emitting --bind "" which would error.
func TestAbsolutizePolicyPaths_EmptyWorkdir(t *testing.T) {
	rp := &policy.ResolvedPolicy{Workdir: ""}
	out := absolutizePolicyPaths(rp, "/tmp")
	if out.Workdir != "" {
		t.Errorf("empty Workdir should stay empty, got %q", out.Workdir)
	}
}
