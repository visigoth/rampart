package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultEngineConfigPath_HomeSet pins the canonical layout
// $HOME/.config/rampart/config.json so that runLaunch's engine wiring
// and the offline `rampart review` reader stay in lock-step.
func TestDefaultEngineConfigPath_HomeSet(t *testing.T) {
	t.Setenv("HOME", "/tmp/fake-home")
	got := defaultEngineConfigPath()
	want := filepath.Join("/tmp/fake-home", ".config", "rampart", "config.json")
	if got != want {
		t.Errorf("defaultEngineConfigPath() = %q, want %q", got, want)
	}
}

// TestDefaultEngineConfigPath_HomeUnset documents the fallback used in
// stripped CI environments — the relative path .config/rampart/config.json,
// which the engine treats as missing on read and creates on write.
func TestDefaultEngineConfigPath_HomeUnset(t *testing.T) {
	// Use t.Setenv first to register a restore hook, then unset for the test
	// body. After test return, t.Setenv's cleanup restores the original HOME
	// — Unsetenv alone leaves HOME empty for sibling tests (e.g. `go build`
	// inside test helpers, which fails with "GOCACHE is not defined").
	t.Setenv("HOME", os.Getenv("HOME"))
	if err := os.Unsetenv("HOME"); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}

	got := defaultEngineConfigPath()
	if !strings.HasSuffix(got, filepath.Join(".config", "rampart", "config.json")) {
		t.Errorf("defaultEngineConfigPath() = %q, expected suffix .config/rampart/config.json", got)
	}
	if filepath.IsAbs(got) {
		t.Errorf("with HOME unset, path should be relative; got %q", got)
	}
}
