package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocsManGeneratesOmnibusManPage(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"docs", "man", "--output-dir", tmpDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("docs man failed: %v", err)
	}

	manPath := filepath.Join(tmpDir, "rampart.1")
	data, err := os.ReadFile(manPath)
	if err != nil {
		t.Fatalf("expected man page at %s: %v", manPath, err)
	}
	got := string(data)

	// Exactly one .TH header — confirms omnibus, not per-subcommand.
	if n := strings.Count(got, ".TH RAMPART 1"); n != 1 {
		t.Errorf("expected exactly one .TH header (omnibus form); got %d", n)
	}

	// Section structure: each entry below is a load-bearing reference
	// the user can't discover from `rampart <cmd> --help` alone.
	requiredHeadings := []string{
		".SH NAME",
		".SH SYNOPSIS",
		".SH DESCRIPTION",
		".SH GLOBAL FLAGS",
		".SH SUBCOMMANDS",
		".SH CONFIGURATION",
		".SH FILES",
		".SH ENVIRONMENT",
	}
	for _, h := range requiredHeadings {
		if !strings.Contains(got, h) {
			t.Errorf("man page missing required section: %s", h)
		}
	}

	requiredTopics := []string{
		"Agent and profile resolution",
		"Module resolution",
		"Profile inheritance",
		"Path expansion",
		"Network policy layers",
		"Profile fields reference",
	}
	for _, topic := range requiredTopics {
		if !strings.Contains(got, topic) {
			t.Errorf("man page missing CONFIGURATION subsection: %q", topic)
		}
	}

	// Key subcommands appear as .SS entries with their flags rendered.
	requiredSubcommands := []string{
		".SS rampart escalations",
		".SS rampart init",
		".SS rampart list",
		".SS rampart review",
		".SS rampart version",
	}
	for _, sub := range requiredSubcommands {
		if !strings.Contains(got, sub) {
			t.Errorf("man page missing subcommand section: %s", sub)
		}
	}
	for _, flag := range []string{"approve", "deny", "watch"} {
		if !strings.Contains(got, "\\-\\-"+flag) {
			t.Errorf("man page missing --%s flag rendering", flag)
		}
	}
}

func TestCompletionCommandIsAvailable(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"completion", "zsh"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("completion zsh failed: %v", err)
	}
}
