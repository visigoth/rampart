//go:build darwin

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestInfoPlistEmbedded verifies that the Info.plist file is embedded into
// the running binary's __TEXT,__info_plist Mach-O section. This is required
// for stable CFBundleIdentifier so that macOS Keychain ACLs (used by FT16
// for MITM CA storage per TR20) remain consistent across rebuilds.
//
// Note: this test only works when the test binary itself was built with the
// linker flag (-Wl,-sectcreate,__TEXT,__info_plist,Info.plist). The Justfile
// recipe rampart-build adds this flag. `go test ./cmd/rampart` without the
// flag will skip with a clear message.
func TestInfoPlistEmbedded(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Info.plist embedding is macOS-specific")
	}

	// otool -P prints the contents of the __TEXT,__info_plist section
	exePath, err := exec.LookPath("otool")
	if err != nil {
		t.Skip("otool not available")
	}

	testBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	_ = testBinary

	// Find the test binary path. Go test compiles a test binary; we want
	// to inspect that, not the regular build output. os.Executable gives
	// us the test binary path.
	cmd := exec.Command(exePath, "-P", os.Args[0])
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("otool -P failed: %v", err)
	}

	got := string(out)
	if !strings.Contains(got, "(__TEXT,__info_plist) section") {
		t.Skipf("Info.plist section not present in test binary; build with -ldflags='-linkmode external -extldflags=-Wl,-sectcreate,__TEXT,__info_plist,%s' to enable", filepath.Join("Info.plist"))
	}

	// Verify expected keys
	requiredKeys := []string{
		"com.shaheengandhi.rampart",
		"<key>CFBundleIdentifier</key>",
		"<key>CFBundleVersion</key>",
		"<key>LSMinimumSystemVersion</key>",
	}
	for _, key := range requiredKeys {
		if !strings.Contains(got, key) {
			t.Errorf("Info.plist missing expected content %q", key)
		}
	}

	// Sanity: the bundle ID should appear exactly once
	if c := bytes.Count(out, []byte("com.shaheengandhi.rampart")); c != 1 {
		t.Errorf("expected bundle ID to appear exactly once, got %d occurrences", c)
	}
}
