package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/config"
	"github.com/visigoth/rampart/internal/policy"
)

// TestRunLaunch_EmptyArgs returns an error without touching the filesystem.
func TestRunLaunch_EmptyArgs(t *testing.T) {
	flags := &runFlags{}
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	code, err := runLaunch(context.Background(), flags, nil, nil, out, errOut)
	if err == nil {
		t.Fatal("expected error for empty args, got nil")
	}
	if code == 0 {
		t.Errorf("expected non-zero exit code, got %d", code)
	}
}

// TestRunLaunch_NoProfile_Errors verifies that missing config produces a
// loadPolicy error rather than silently launching.
func TestRunLaunch_NoProfile_Errors(t *testing.T) {
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	flags := &runFlags{}
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	code, err := runLaunch(context.Background(), flags, []string{"echo", "hi"}, nil, out, errOut)
	if err == nil {
		t.Fatal("expected error when no profile is configured")
	}
	if code == 0 {
		t.Errorf("expected non-zero exit code, got %d", code)
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("expected profile-related error, got: %v", err)
	}
}

// TestStartProxyForPolicy_NoTLSMITM_SkipsCA verifies that --no-tls-mitm
// (or profile no_tls_mitm) lets the proxy start without an installed CA,
// even when the profile's network rules would otherwise auto-promote
// domains to MITM via path matching.
func TestStartProxyForPolicy_NoTLSMITM_SkipsCA(t *testing.T) {
	// No CA on disk for this test.
	t.Setenv("HOME", t.TempDir())

	cp := &compiledPolicy{
		AgentName:   "admin",
		ProfileName: "permissive",
		Policy: &policy.ResolvedPolicy{
			Mode:      "enforcing",
			NoTLSMITM: true,
			ProxyACLs: []config.DomainConfig{
				{
					Pattern: "*",
					Allow: []config.RuleConfig{
						{Method: "GET", Paths: []string{"/**"}},
					},
				},
			},
		},
	}

	sub, _, err := startProxyForPolicy(cp)
	if err != nil {
		t.Fatalf("startProxyForPolicy with NoTLSMITM should succeed without CA; got: %v", err)
	}
	if sub == nil {
		t.Fatal("expected a non-nil proxy subsystem")
	}
	defer sub.p.Close()
}

// TestRootCmd_Launch_ReachesRunLaunch_NotPlaceholder verifies the wiring no
// longer prints the old "launch (not yet implemented)" placeholder. It runs
// the cobra command in a temp git dir without a profile and asserts the
// failure mode is the runLaunch error path, not the placeholder string.
func TestRootCmd_Launch_ReachesRunLaunch_NotPlaceholder(t *testing.T) {
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())

	// Capture the exit code via the test seam instead of os.Exit.
	var capturedCode int
	origExit := exitWithCode
	exitWithCode = func(code int) { capturedCode = code }
	defer func() { exitWithCode = origExit }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"--", "echo", "hi"})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	_ = cmd.Execute()

	combined := out.String() + errOut.String()
	if strings.Contains(combined, "not yet implemented") {
		t.Errorf("RunE still prints the old placeholder: %q", combined)
	}
	if capturedCode == 0 {
		t.Errorf("expected non-zero exit code from runLaunch failure, got 0")
	}
	if !strings.Contains(combined, "profile") {
		t.Errorf("expected profile-related error in output, got: %q", combined)
	}
}

