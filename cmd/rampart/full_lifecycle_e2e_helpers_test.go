// Cross-platform helpers for the full-session-lifecycle E2E tests
// (.1.5 darwin /  linux). Lives without a build tag so both
// full_lifecycle_e2e_darwin_test.go and full_lifecycle_e2e_linux_test.go
// share the stub-agent build, .rampart scaffolding, and tmp HOME setup.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildE2EStubAgent compiles a small Go binary that performs in-policy
// filesystem operations and returns its absolute path. The binary writes a
// marker file inside STUB_WORKDIR so the parent test can assert the child
// actually ran inside the sandbox. Static Go binary (no cgo) — no dynamic
// linker bind-mounts required on Linux beyond the bwrap defaults.
func buildE2EStubAgent(t *testing.T, workdir string) string {
	t.Helper()
	src := `package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Stub agent simulating Claude Code: read+write a few files in workdir.
// All paths are in-policy under the profile compiled by rampart.
func main() {
	wd := os.Getenv("STUB_WORKDIR")
	if wd == "" {
		fmt.Fprintln(os.Stderr, "STUB_WORKDIR not set")
		os.Exit(1)
	}

	out := filepath.Join(wd, "stub.touched")
	if err := os.WriteFile(out, []byte("ok\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", out, err)
		os.Exit(2)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", out, err)
		os.Exit(3)
	}
	fmt.Printf("stub-agent: wrote+read %d bytes\n", len(data))
	os.Exit(0)
}
`
	srcDir := filepath.Join(workdir, "_stub_src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir stub src: %v", err)
	}
	srcPath := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write stub src: %v", err)
	}

	binPath := filepath.Join(workdir, "stub-agent")
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	cmd.Env = append(os.Environ(), "GOFLAGS=") // honour ambient toolchain
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build stub-agent: %v\n%s", err, out)
	}
	return binPath
}

// scaffoldE2ERampartConfig writes a minimal .rampart/ tree allowing
// read+write inside the working directory. The compiled policy grants
// access to the EvalSymlinks-resolved workdir path so it matches what
// the kernel sandbox sees (Seatbelt's /private prefix on darwin, bwrap's
// canonical bind path on linux).
func scaffoldE2ERampartConfig(t *testing.T, gitDir string) {
	t.Helper()
	rampDir := filepath.Join(gitDir, ".rampart")
	if err := os.MkdirAll(filepath.Join(rampDir, "profiles", "e2e"), 0o755); err != nil {
		t.Fatalf("mkdir .rampart: %v", err)
	}
	defaults := `defaults {
  default_agent   = "coding"
  default_profile = "e2e/default"
}
`
	if err := os.WriteFile(filepath.Join(rampDir, "defaults.hcl"), []byte(defaults), 0o644); err != nil {
		t.Fatalf("write defaults.hcl: %v", err)
	}
	agents := `agent "coding" {
}
`
	if err := os.WriteFile(filepath.Join(rampDir, "agents.hcl"), []byte(agents), 0o644); err != nil {
		t.Fatalf("write agents.hcl: %v", err)
	}
	profile := `profile "default" {
  workdir = "."
  write   = ["."]
}
`
	if err := os.WriteFile(filepath.Join(rampDir, "profiles", "e2e", "default.hcl"), []byte(profile), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
}

// makeE2ELifecycleEnv sets up a self-contained test workspace: a git dir
// with .rampart config, a stub HOME (so session sockets land in tmp), and
// chdir into the git dir. Returns the resolved git root path.
//
// /tmp is used directly rather than t.TempDir() — on darwin t.TempDir()
// returns /var/folders/... paths that can exceed sun_path's 104-byte
// limit for the session socket; /tmp is short on both platforms.
func makeE2ELifecycleEnv(t *testing.T) string {
	t.Helper()

	gitDir, err := os.MkdirTemp("/tmp", "ramp-e2e")
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(gitDir) })

	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	scaffoldE2ERampartConfig(t, gitDir)

	homeDir, err := os.MkdirTemp("/tmp", "ramp-e2e-home")
	if err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(homeDir) })
	t.Setenv("HOME", homeDir)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(gitDir); err != nil {
		t.Fatalf("chdir gitDir: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	resolved, err := filepath.EvalSymlinks(gitDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return resolved
}
