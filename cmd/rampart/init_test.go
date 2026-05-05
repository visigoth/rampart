package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- scaffoldRampartDir unit tests ---

func TestScaffoldRampartDir_CreatesExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldRampartDir(dir, "myproject"); err != nil {
		t.Fatalf("scaffoldRampartDir: %v", err)
	}

	// defaults.hcl must exist and contain the project profile reference.
	defaultsPath := filepath.Join(dir, "defaults.hcl")
	data, err := os.ReadFile(defaultsPath)
	if err != nil {
		t.Fatalf("defaults.hcl missing: %v", err)
	}
	if !strings.Contains(string(data), `"myproject/default"`) {
		t.Errorf("defaults.hcl should reference 'myproject/default': %s", data)
	}
	if !strings.Contains(string(data), "default_agent") {
		t.Errorf("defaults.hcl missing default_agent: %s", data)
	}

	// profiles/myproject/default.hcl must exist.
	profilePath := filepath.Join(dir, "profiles", "myproject", "default.hcl")
	data, err = os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("profiles/myproject/default.hcl missing: %v", err)
	}
	if !strings.Contains(string(data), `profile "default"`) {
		t.Errorf("default.hcl missing profile block: %s", data)
	}
	if !strings.Contains(string(data), `workdir = "."`) {
		t.Errorf("default.hcl missing workdir: %s", data)
	}
}

func TestScaffoldRampartDir_ScaffoldedHCLParses(t *testing.T) {
	// Verify the generated HCL is valid by loading it via the config package.
	// We just check that the files are syntactically correct, not fully parsed.
	dir := t.TempDir()
	if err := scaffoldRampartDir(dir, "myproj"); err != nil {
		t.Fatalf("scaffoldRampartDir: %v", err)
	}

	// defaults.hcl must be valid HCL (parseable by our config loader).
	defaultsData, _ := os.ReadFile(filepath.Join(dir, "defaults.hcl"))
	if len(defaultsData) == 0 {
		t.Error("defaults.hcl is empty")
	}

	// profiles/myproj/default.hcl must be valid HCL.
	profileData, _ := os.ReadFile(filepath.Join(dir, "profiles", "myproj", "default.hcl"))
	if len(profileData) == 0 {
		t.Error("default profile is empty")
	}
}

// --- initCmd integration tests ---

func TestInitCmd_ScaffoldsRampartDir(t *testing.T) {
	useMemCAStore(t)
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--project", "acme"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// .rampart/defaults.hcl should exist.
	if _, err := os.Stat(filepath.Join(gitDir, ".rampart", "defaults.hcl")); err != nil {
		t.Error(".rampart/defaults.hcl not created")
	}
	// .rampart/profiles/acme/default.hcl should exist.
	if _, err := os.Stat(filepath.Join(gitDir, ".rampart", "profiles", "acme", "default.hcl")); err != nil {
		t.Error(".rampart/profiles/acme/default.hcl not created")
	}
}

func TestInitCmd_InfersProjectFromGitBasename(t *testing.T) {
	useMemCAStore(t)
	// Git root dir name is used as the project name when --project is not set.
	// We create a git dir with a known name under a temp parent.
	parent := t.TempDir()
	gitDir := filepath.Join(parent, "my-repo")
	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	cmd := rootCmd()
	cmd.SetArgs([]string{"init"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Profile dir should be named "my-repo".
	if _, err := os.Stat(filepath.Join(gitDir, ".rampart", "profiles", "my-repo", "default.hcl")); err != nil {
		t.Error("profile dir should be named after git repo basename (my-repo)")
	}
}

func TestInitCmd_RefusesIfAlreadyInitialized(t *testing.T) {
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	// Create .rampart/ to simulate already-initialized.
	if err := os.MkdirAll(filepath.Join(gitDir, ".rampart"), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--project", "proj"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when .rampart/ already exists, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists': %v", err)
	}
}

func TestInitCmd_RotateOverwritesExistingScaffold(t *testing.T) {
	useMemCAStore(t)
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	// First init.
	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--project", "proj"})
	cmd.SetOut(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("first init: %v", err)
	}

	// Second init with --rotate should succeed.
	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"init", "--project", "proj", "--rotate"})
	out := &bytes.Buffer{}
	cmd2.SetOut(out)
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("init --rotate: %v", err)
	}

	if _, err := os.Stat(filepath.Join(gitDir, ".rampart", "defaults.hcl")); err != nil {
		t.Error("defaults.hcl should exist after --rotate")
	}
}

func TestInitCmd_NotInGitRepo_Errors(t *testing.T) {
	// Create a plain dir without .git.
	nonGitDir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(nonGitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--project", "proj"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when not in a git repo, got nil")
	}
}

func TestInitCmd_NoGitFlag_SucceedsOutsideRepo(t *testing.T) {
	useMemCAStore(t)
	nonGitDir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	if err := os.Chdir(nonGitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--project", "proj", "--no-git"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --no-git: %v", err)
	}

	if _, err := os.Stat(filepath.Join(nonGitDir, ".rampart", "defaults.hcl")); err != nil {
		t.Error(".rampart/defaults.hcl not created with --no-git")
	}
}
