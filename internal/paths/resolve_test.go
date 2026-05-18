package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolve_TildeExpandsToHome(t *testing.T) {
	home := t.TempDir()
	ctx := Context{Home: home}

	got, err := Resolve("~", ctx)
	if err != nil {
		t.Fatalf("~ expansion: %v", err)
	}
	// EvalSymlinks may resolve the tempdir itself.
	if !strings.HasPrefix(got, filepath.VolumeName(home)) {
		t.Errorf("~ should start with volume: got %q", got)
	}
}

func TestResolve_TildeSlashExpandsToHomeSubpath(t *testing.T) {
	home := t.TempDir()
	// Create a real subdirectory so EvalSymlinks works.
	subdir := filepath.Join(home, "code", "demo")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := Context{Home: home}

	got, err := Resolve("~/code/demo", ctx)
	if err != nil {
		t.Fatalf("~/code/demo expansion: %v", err)
	}
	wantSuffix := filepath.Join("code", "demo")
	if !strings.HasSuffix(got, wantSuffix) {
		t.Errorf("want suffix %q in %q", wantSuffix, got)
	}
}

func TestResolve_DotExpandsToGitRoot(t *testing.T) {
	gitRoot := t.TempDir()
	ctx := Context{GitRoot: gitRoot}

	got, err := Resolve(".", ctx)
	if err != nil {
		t.Fatalf("dot expansion: %v", err)
	}
	// EvalSymlinks on gitRoot (which is a tempdir) should be equivalent.
	want, _ := filepath.EvalSymlinks(gitRoot)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolve_DotExpandsToHomeWhenNoGitRoot(t *testing.T) {
	home := t.TempDir()
	ctx := Context{Home: home}

	got, err := Resolve(".", ctx)
	if err != nil {
		t.Fatalf("dot (no git root): %v", err)
	}
	want, _ := filepath.EvalSymlinks(home)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolve_RelativePathExpandsToGitRoot(t *testing.T) {
	gitRoot := t.TempDir()
	subdir := filepath.Join(gitRoot, "go", "internal")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := Context{GitRoot: gitRoot}

	got, err := Resolve("go/internal", ctx)
	if err != nil {
		t.Fatalf("relative path: %v", err)
	}
	want, _ := filepath.EvalSymlinks(subdir)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolve_SymlinkResolved(t *testing.T) {
	tmpdir := t.TempDir()
	realDir := filepath.Join(tmpdir, "real")
	linkDir := filepath.Join(tmpdir, "link")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skip("symlink creation failed, likely no permission:", err)
	}

	ctx := Context{GitRoot: tmpdir}
	got, err := Resolve(linkDir, ctx)
	if err != nil {
		t.Fatalf("symlink resolution: %v", err)
	}
	if got == linkDir {
		t.Errorf("symlink was not resolved: got %q", got)
	}
	real, _ := filepath.EvalSymlinks(realDir)
	if got != real {
		t.Errorf("got %q, want %q", got, real)
	}
}

func TestResolve_NonExistentPathPartialResolution(t *testing.T) {
	tmpdir := t.TempDir()
	ctx := Context{GitRoot: tmpdir}

	// The path /etc/ssh may or may not exist, but a path deep in tmpdir won't.
	got, err := Resolve(filepath.Join(tmpdir, "does", "not", "exist"), ctx)
	if err != nil {
		t.Fatalf("non-existent path: %v", err)
	}
	// Should return something that starts with tmpdir (resolved) + suffix.
	realTmp, _ := filepath.EvalSymlinks(tmpdir)
	if !strings.HasPrefix(got, realTmp) {
		t.Errorf("resolved path %q should be under %q", got, realTmp)
	}
	if !strings.HasSuffix(got, filepath.Join("does", "not", "exist")) {
		t.Errorf("resolved path %q should keep non-existent suffix", got)
	}
}

func TestResolve_TrailingSlashNormalized(t *testing.T) {
	tmpdir := t.TempDir()
	ctx := Context{GitRoot: tmpdir}

	got, err := Resolve(tmpdir+"/", ctx)
	if err != nil {
		t.Fatalf("trailing slash: %v", err)
	}
	if strings.HasSuffix(got, "/") {
		t.Errorf("trailing slash not normalized: %q", got)
	}
}

func TestResolve_NullByteError(t *testing.T) {
	ctx := Context{Home: t.TempDir()}
	_, err := Resolve("/etc/ssh\x00bad", ctx)
	if err == nil {
		t.Fatal("expected error for null byte in path")
	}
}

func TestResolve_EmptyPathError(t *testing.T) {
	ctx := Context{Home: t.TempDir()}
	_, err := Resolve("", ctx)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestResolve_AbsolutePathPassesThrough(t *testing.T) {
	tmpdir := t.TempDir()
	ctx := Context{}

	got, err := Resolve(tmpdir, ctx)
	if err != nil {
		t.Fatalf("absolute path: %v", err)
	}
	want, _ := filepath.EvalSymlinks(tmpdir)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveAll_HappyPath(t *testing.T) {
	tmpdir := t.TempDir()
	sub1 := filepath.Join(tmpdir, "a")
	sub2 := filepath.Join(tmpdir, "b")
	for _, d := range []string{sub1, sub2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ctx := Context{GitRoot: tmpdir}

	got, err := ResolveAll([]string{"a", "b"}, ctx)
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d paths, want 2", len(got))
	}
	realA, _ := filepath.EvalSymlinks(sub1)
	realB, _ := filepath.EvalSymlinks(sub2)
	if got[0] != realA || got[1] != realB {
		t.Errorf("got %v, want [%q %q]", got, realA, realB)
	}
}

func TestResolveAll_ErrorPropagates(t *testing.T) {
	ctx := Context{Home: t.TempDir()}
	_, err := ResolveAll([]string{"/good", "/with\x00null"}, ctx)
	if err == nil {
		t.Fatal("expected error for null byte in second path")
	}
}
