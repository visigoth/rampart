//go:build linux

// Package main_test contains environment tests (.5) that verify the
// devcontainer provides all tools rampart needs at runtime and test time.
// Run with: go test ./cmd/rampart/ -run TestEnvironment -v
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEnvironment_BwrapPresent verifies bubblewrap is installed and executable.
func TestEnvironment_BwrapPresent(t *testing.T) {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatalf("bwrap not found in PATH: %v (install: apt-get install bubblewrap)", err)
	}
	// Verify it's executable by asking for version.
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("bwrap --version failed: %v\n%s", err, out)
	}
	t.Logf("bwrap: %s", strings.TrimSpace(string(out)))
}

// TestEnvironment_IptablesPresent verifies iptables is installed.
func TestEnvironment_IptablesPresent(t *testing.T) {
	path, err := exec.LookPath("iptables")
	if err != nil {
		// iptables may be iptables-legacy or iptables-nft; either is fine.
		if p2, err2 := exec.LookPath("iptables-legacy"); err2 == nil {
			t.Logf("iptables (legacy): %s", p2)
			return
		}
		t.Fatalf("iptables not found in PATH: %v (install: apt-get install iptables)", err)
	}
	t.Logf("iptables: %s", path)
}

// TestEnvironment_LibseccompDevInstalled verifies libseccomp-dev headers are present.
// The Go libseccomp bindings require these headers at build time.
func TestEnvironment_LibseccompDevInstalled(t *testing.T) {
	header := "/usr/include/seccomp.h"
	if _, err := os.Stat(header); err != nil {
		t.Fatalf("libseccomp-dev header not found at %s: %v (install: apt-get install libseccomp-dev)", header, err)
	}
	t.Logf("libseccomp-dev: %s present", header)
}

// TestEnvironment_CACertificatesPresent verifies ca-certificates are installed.
// Required for HTTPS connections in the MITM proxy and certificate trust injection.
func TestEnvironment_CACertificatesPresent(t *testing.T) {
	certsDir := "/etc/ssl/certs"
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		t.Fatalf("ca-certificates not installed: %s missing: %v", certsDir, err)
	}
	var pemCount int
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".pem" || filepath.Ext(e.Name()) == ".crt" {
			pemCount++
		}
	}
	if pemCount == 0 {
		t.Fatalf("ca-certificates: no .pem/.crt files found in %s", certsDir)
	}
	t.Logf("ca-certificates: %d cert files in %s", pemCount, certsDir)
}

// TestEnvironment_GoVersion verifies the Go toolchain is 1.26 or newer.
func TestEnvironment_GoVersion(t *testing.T) {
	v := runtime.Version() // e.g. "go1.26.1"
	t.Logf("Go runtime: %s", v)

	// Strip "go" prefix and parse major.minor.
	vStr := strings.TrimPrefix(v, "go")
	var major, minor int
	if _, err := readTwoInts(vStr, &major, &minor); err != nil {
		t.Fatalf("parsing Go version %q: %v", v, err)
	}
	if major < 1 || (major == 1 && minor < 26) {
		t.Errorf("Go %d.%d < 1.26; rampart requires go1.26+ (go.mod specifies 1.26.1)", major, minor)
	}
}

// TestEnvironment_Build verifies the rampart module compiles without errors.
// This is a smoke test: if it fails, no other tests would run either.
func TestEnvironment_Build(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build test in short mode")
	}
	out, err := exec.Command("go", "build", "-C", moduleRoot(t), "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./... failed:\n%s", out)
	}
}

// TestEnvironment_AllRampartPackagesPass is an environment-level gate: it runs
// the rampart-specific packages and fails if any non-environment test fails.
// Non-rampart packages (autocoder) may have known pre-existing failures; they
// are excluded here.
//
// This test is skipped when running inside a subprocess to prevent recursion.
func TestEnvironment_AllRampartPackagesPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full suite run in short mode")
	}
	if os.Getenv("RAMPART_ENV_TEST_SUBPROCESS") == "1" {
		t.Skip("skipping recursive invocation inside environment test subprocess")
	}
	pkgs := []string{
		"./cmd/rampart/...",
		"./internal/rampart/...",
	}
	for _, pkg := range pkgs {
		cmd := exec.Command("go", "test", "-C", moduleRoot(t), "-count=1", pkg)
		cmd.Env = append(os.Environ(), "RAMPART_ENV_TEST_SUBPROCESS=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("go test %s failed:\n%s", pkg, out)
		} else {
			t.Logf("go test %s: PASS", pkg)
		}
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// moduleRoot returns the absolute path to the go/ module root.
func moduleRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test binary's directory to find go.mod.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not find go.mod from %s", wd)
	return ""
}

// readTwoInts parses "MAJOR.MINOR[.PATCH]" from s into *major and *minor.
func readTwoInts(s string, major, minor *int) (int, error) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, nil
	}
	parseDigits(parts[0], major)
	parseDigits(parts[1], minor)
	return *major, nil
}

// parseDigits reads leading decimal digits from s into *out.
func parseDigits(s string, out *int) {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	*out = n
}
