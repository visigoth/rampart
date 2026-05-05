//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// skipIfNoKeychainEntitlement skips the test when the running binary lacks the
// keychain-access-groups entitlement. Without it, SaveCA fails with
// errSecMissingEntitlement (-34018). The plain `go test` binary is adhoc-signed
// and has no entitlements; the installed `rampart` binary is signed with them.
func skipIfNoKeychainEntitlement(t *testing.T) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("skipping Keychain-dependent test: cannot locate test binary: %v", err)
	}
	out, err := exec.Command("codesign", "-d", "--entitlements", "-", exe).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "keychain-access-groups") {
		t.Skip("skipping Keychain-dependent test: test binary lacks keychain-access-groups entitlement (run via signed `rampart` binary instead)")
	}
}
