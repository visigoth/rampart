//go:build !darwin

package main

import "testing"

// skipIfNoKeychainEntitlement is a no-op on non-darwin platforms — the
// keychain-access-groups entitlement is darwin-specific.
func skipIfNoKeychainEntitlement(t *testing.T) {
	t.Helper()
}
