package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocsManGeneratesManPage(t *testing.T) {
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
	if !strings.Contains(got, "RAMPART") {
		t.Errorf("man page missing RAMPART header; got:\n%s", got)
	}
}

func TestCompletionCommandIsAvailable(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"completion", "zsh"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("completion zsh failed: %v", err)
	}
}
