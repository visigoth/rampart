package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlagPrintsVersion(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--version"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "0.1.0") {
		t.Errorf("expected version output to contain %q, got %q", "0.1.0", got)
	}
}

func TestRootCommandUsage(t *testing.T) {
	cmd := rootCmd()
	if cmd.Use != "rampart" {
		t.Errorf("expected Use=%q, got %q", "rampart", cmd.Use)
	}
}
