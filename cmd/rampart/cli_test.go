package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Flag parsing ---

func TestRootCmd_FlagDefaults(t *testing.T) {
	cmd := rootCmd()
	flags := cmd.Flags()

	// mode defaults to "enforcing"
	modeFlag := flags.Lookup("mode")
	if modeFlag == nil {
		t.Fatal("--mode flag not registered")
	}
	if modeFlag.DefValue != "enforcing" {
		t.Errorf("--mode default: got %q, want %q", modeFlag.DefValue, "enforcing")
	}
}

func TestRootCmd_AllFlagsPresent(t *testing.T) {
	cmd := rootCmd()
	flags := cmd.Flags()

	required := []string{
		"agent", "profile", "mode", "strict", "verbose", "dry-run",
		"no-escape-hatch", "new-session", "new-window", "no-tmux", "headless",
		"allow-path", "allow-domain", "env", "no-env", "no-tls-mitm",
	}
	for _, name := range required {
		if flags.Lookup(name) == nil {
			t.Errorf("flag --%s not registered on root command", name)
		}
	}
}

func TestRootCmd_NoArgs_PrintsHelp(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)

	_ = cmd.Execute()
	if !strings.Contains(out.String(), "Usage") && !strings.Contains(out.String(), "rampart") {
		t.Errorf("expected help output, got: %q", out.String())
	}
}

func TestRootCmd_VersionFlag(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--version"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "0.1.0") {
		t.Errorf("expected version in output, got: %q", out.String())
	}
}

// --- Subcommands ---

func TestVersionSubcommand(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"version"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "rampart") {
		t.Errorf("version output should contain 'rampart': %q", out.String())
	}
}

func TestEscalationsSubcommand_NoArgs_NoActiveSessions(t *testing.T) {
	// With no rampart supervisor running, the list path discovers no
	// sockets and prints the empty-sessions message. Redirect HOME so we
	// don't accidentally find a real socket from a parallel test or session.
	t.Setenv("HOME", t.TempDir())

	cmd := rootCmd()
	cmd.SetArgs([]string{"escalations"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("escalations: %v", err)
	}
	if !strings.Contains(out.String(), "no active rampart sessions") {
		t.Errorf("expected empty-sessions message; got: %q", out.String())
	}
}

func TestEscalationsSubcommand_Approve_RejectsNonNumericID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cmd := rootCmd()
	cmd.SetArgs([]string{"escalations", "--approve", "test-id-123"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-numeric escalation ID")
	}
	if !strings.Contains(err.Error(), "invalid escalation ID") {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestEscalationsSubcommand_Approve_NumericID_NoSessions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cmd := rootCmd()
	cmd.SetArgs([]string{"escalations", "--approve", "42"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no active sessions")
	}
	if !strings.Contains(err.Error(), "no active rampart sessions") {
		t.Errorf("expected no-sessions error, got: %v", err)
	}
}

func TestEscalationsSubcommand_MutuallyExclusive(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"escalations", "--approve", "id1", "--deny", "id2"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for mutually exclusive --approve and --deny")
	}
}

func TestReviewSubcommand(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"review"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("review: %v", err)
	}
}

func TestInitSubcommand(t *testing.T) {
	useMemCAStore(t)
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--project", "testproject"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(out.String(), "testproject") {
		t.Errorf("output should mention project name: %q", out.String())
	}
}

func TestListSubcommand_Agents(t *testing.T) {
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	// Drop in a minimal repo-wide agents.hcl so the list has something to print.
	rampart := filepath.Join(gitDir, ".rampart")
	if err := os.MkdirAll(rampart, 0o755); err != nil {
		t.Fatal(err)
	}
	agents := `agent "tester" {
  description  = "test agent"
  filesystem   = "none"
  network_mode = "none"
}
`
	if err := os.WriteFile(filepath.Join(rampart, "agents.hcl"), []byte(agents), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"list", "agents"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if !strings.Contains(out.String(), "tester") {
		t.Errorf("expected 'tester' in output: %q", out.String())
	}
	if !strings.Contains(out.String(), "AGENT") {
		t.Errorf("expected table header AGENT in output: %q", out.String())
	}
}

func TestListSubcommand_Profiles_NamesOnly(t *testing.T) {
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	profileDir := filepath.Join(gitDir, ".rampart", "profiles", "demo")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prof := `profile "default" {
  workdir = "."
}
`
	if err := os.WriteFile(filepath.Join(profileDir, "default.hcl"), []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"list", "profiles", "--names-only"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	got := strings.TrimSpace(out.String())
	if got != "demo/default" {
		t.Errorf("--names-only output: got %q, want exactly %q", got, "demo/default")
	}
}

// makeTempGitRepo creates a temp directory with a .git subdirectory.
// Returns the temp dir path and the caller's original working directory.
func makeTempGitRepo(t *testing.T) (string, string) {
	t.Helper()
	gitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gitDir, ".git"), 0o755); err != nil {
		t.Fatalf("creating .git: %v", err)
	}
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return gitDir, origDir
}

func TestTestSubcommand_NoProfile_Errors(t *testing.T) {
	// testCmd requires --profile (or .rampart/defaults.hcl). Without it, loadPolicy
	// returns an error — verify the error is propagated cleanly.
	gitDir, origDir := makeTempGitRepo(t)
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()
	if err := os.Chdir(gitDir); err != nil {
		t.Fatalf("chdir to git dir: %v", err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no profile configured, got nil")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("expected profile-related error, got: %v", err)
	}
}

// --- Mode detection ---

func TestDetectMode_Headless_Flag(t *testing.T) {
	flags := &runFlags{headless: true}
	if got := DetectMode(flags); got != ModeHeadless {
		t.Errorf("--headless: got %v, want %v", got, ModeHeadless)
	}
}

func TestDetectMode_NoTmux_Flag(t *testing.T) {
	flags := &runFlags{noTmux: true}
	mode := DetectMode(flags)
	// --no-tmux only forces non-headless; the actual result depends on TTY check.
	// In CI (non-TTY), CI env may override. We just verify it's not headless
	// from the --no-tmux path alone (CI env is checked first if headless is false).
	if flags.noTmux && mode == ModeInteractiveTmux {
		t.Errorf("--no-tmux should never produce interactive-tmux mode")
	}
}

func TestDetectMode_CI_EnvForces_Headless(t *testing.T) {
	old := os.Getenv("CI")
	defer os.Setenv("CI", old)
	os.Setenv("CI", "true")

	flags := &runFlags{}
	if got := DetectMode(flags); got != ModeHeadless {
		t.Errorf("$CI=true: got %v, want headless", got)
	}
}

func TestDetectMode_NoTmux_Overrides_CI(t *testing.T) {
	old := os.Getenv("CI")
	defer os.Setenv("CI", old)
	os.Setenv("CI", "true")

	// --no-tmux takes priority over $CI (per TR99 priority order: flags > env).
	flags := &runFlags{noTmux: true}
	if got := DetectMode(flags); got != ModeInteractiveDirect {
		t.Errorf("--no-tmux should override $CI: got %v, want interactive-direct", got)
	}
}

func TestDetectMode_Headless_Flag_Overrides_CI(t *testing.T) {
	old := os.Getenv("CI")
	defer os.Setenv("CI", old)
	os.Setenv("CI", "true")

	// --headless has higher priority.
	flags := &runFlags{headless: true}
	if got := DetectMode(flags); got != ModeHeadless {
		t.Errorf("got %v, want headless", got)
	}
}

func TestDetectMode_String(t *testing.T) {
	cases := []struct {
		mode ExecutionMode
		want string
	}{
		{ModeInteractiveTmux, "interactive-tmux"},
		{ModeInteractiveDirect, "interactive-direct"},
		{ModeHeadless, "headless"},
	}
	for _, tc := range cases {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("mode %d String(): got %q, want %q", tc.mode, got, tc.want)
		}
	}
}

// --- BuildEnv ---

func TestBuildEnv_BuiltinsAlwaysPresent(t *testing.T) {
	// Ensure PATH is in the environment so it's picked up.
	if os.Getenv("PATH") == "" {
		os.Setenv("PATH", "/usr/bin:/bin")
	}

	env := BuildEnv(nil, false)

	hasPath := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			hasPath = true
		}
	}
	if !hasPath {
		t.Error("PATH should always be in env list")
	}
}

func TestBuildEnv_NoEnv_OnlyBuiltins(t *testing.T) {
	extraVars := []string{"SECRET=value", "MY_CUSTOM_VAR=foo"}
	env := BuildEnv(extraVars, true) // --no-env

	for _, kv := range env {
		if strings.HasPrefix(kv, "SECRET=") || strings.HasPrefix(kv, "MY_CUSTOM_VAR=") {
			t.Errorf("--no-env: unexpected custom var in env: %q", kv)
		}
	}
}

func TestBuildEnv_ExtraVars_Added(t *testing.T) {
	env := BuildEnv([]string{"CUSTOM_VAR=hello"}, false)

	found := false
	for _, kv := range env {
		if kv == "CUSTOM_VAR=hello" {
			found = true
		}
	}
	if !found {
		t.Error("--env CUSTOM_VAR=hello not found in env list")
	}
}

func TestBuildEnv_NoDuplicates(t *testing.T) {
	// PATH is likely set from builtins; adding it again via --env should not duplicate.
	env := BuildEnv([]string{"PATH=/custom/path"}, false)

	count := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("PATH appears %d times, want exactly 1: %v", count, env)
	}
}

func TestBuildEnv_EnvVarWithoutValue_LookupFromProcess(t *testing.T) {
	os.Setenv("RAMPART_TEST_VAR", "exists")
	defer os.Unsetenv("RAMPART_TEST_VAR")

	env := BuildEnv([]string{"RAMPART_TEST_VAR"}, false)

	found := false
	for _, kv := range env {
		if kv == "RAMPART_TEST_VAR=exists" {
			found = true
		}
	}
	if !found {
		t.Error("env var without value should be looked up from process env")
	}
}

// --- toMergeOptions ---

func TestRunFlags_ToMergeOptions(t *testing.T) {
	flags := &runFlags{
		mode:         "permissive",
		strict:       true,
		extraPaths:   []string{"/tmp/debug"},
		extraDomains: []string{"internal.corp"},
	}

	opts := flags.toMergeOptions()

	if opts.Mode != "permissive" {
		t.Errorf("Mode: got %q", opts.Mode)
	}
	if !opts.Strict {
		t.Error("Strict should be true")
	}
	if len(opts.ExtraPaths) != 1 || opts.ExtraPaths[0] != "/tmp/debug" {
		t.Errorf("ExtraPaths: got %v", opts.ExtraPaths)
	}
	if len(opts.ExtraDomains) != 1 || opts.ExtraDomains[0] != "internal.corp" {
		t.Errorf("ExtraDomains: got %v", opts.ExtraDomains)
	}
}

// --- Help output ---

func TestRootCmd_HelpDocumentsFlags(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--help"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)

	_ = cmd.Execute()
	output := out.String()

	requiredInHelp := []string{
		"--agent", "--profile", "--mode", "--strict", "--verbose",
		"--allow-path", "--allow-domain",
	}
	for _, flag := range requiredInHelp {
		if !strings.Contains(output, flag) {
			t.Errorf("help output missing %q", flag)
		}
	}
}
