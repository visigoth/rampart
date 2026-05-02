//go:build darwin

package ca

import (
	"os"
	"testing"
)

// Darwin Keychain security tests (TR20, TR29).
// These require an interactive macOS session with Keychain access.
// They are skipped in headless/CI environments.

func skipIfHeadlessDarwin(t *testing.T) {
	t.Helper()
	if os.Getenv("CI") != "" || !hasGUISession() {
		t.Skip("skipping Keychain test: no GUI session (headless/CI)")
	}
}

// TestSaveCA_KeyNeverOnDisk verifies that after SaveCA the private key is not
// present as a file on disk — it lives only in the login Keychain (TR20).
func TestSaveCA_KeyNeverOnDisk(t *testing.T) {
	skipIfHeadlessDarwin(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { RemoveCA() })

	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	dir, err := DefaultConfigDir()
	if err != nil {
		t.Fatalf("DefaultConfigDir: %v", err)
	}

	// ~/.config/rampart/ should not contain a private key file.
	// On macOS, SaveCA stores nothing to disk (Keychain-only).
	entries, readErr := os.ReadDir(dir)
	if os.IsNotExist(readErr) {
		return // dir doesn't exist — nothing on disk, test passes
	}
	if readErr != nil {
		t.Fatalf("ReadDir: %v", readErr)
	}
	for _, e := range entries {
		if e.Name() == "ca-key.pem" {
			t.Error("ca-key.pem found on disk — private key must be Keychain-only (TR20)")
		}
	}
}

// TestKeychain_IsInstalled verifies the cert is present in Keychain after SaveCA.
func TestKeychain_IsInstalled(t *testing.T) {
	skipIfHeadlessDarwin(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { RemoveCA() })

	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	ok, err := IsInstalled()
	if err != nil {
		t.Fatalf("IsInstalled: %v", err)
	}
	if !ok {
		t.Error("IsInstalled = false after SaveCA, want true")
	}
}

// TestLoadCA_ReturnsKeychainSigner verifies LoadCA returns a *keychainSigner,
// not a raw *ecdsa.PrivateKey — the private key never leaves Keychain (TR29).
func TestLoadCA_ReturnsKeychainSigner(t *testing.T) {
	skipIfHeadlessDarwin(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { RemoveCA() })

	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	loaded, err := LoadCA()
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	if _, ok := loaded.TLSCert().PrivateKey.(*keychainSigner); !ok {
		t.Fatalf("PrivateKey type = %T, want *keychainSigner (TR29)", loaded.TLSCert().PrivateKey)
	}
}

// TestKeychainSigner_CanSign verifies the keychainSigner produces valid signatures
// via SecKeyCreateSignature without extracting the key (TR29).
func TestKeychainSigner_CanSign(t *testing.T) {
	skipIfHeadlessDarwin(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { RemoveCA() })

	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	loaded, err := LoadCA()
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	signer := loaded.TLSCert().PrivateKey.(*keychainSigner)
	digest := make([]byte, 32) // synthetic SHA-256 digest
	sig, err := signer.Sign(nil, digest, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("Sign returned empty signature")
	}
}

// TestRemoveCA_ClearsKeychain verifies RemoveCA removes the cert and key from Keychain.
func TestRemoveCA_ClearsKeychain(t *testing.T) {
	skipIfHeadlessDarwin(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	if err := RemoveCA(); err != nil {
		t.Fatalf("RemoveCA: %v", err)
	}

	ok, err := IsInstalled()
	if err != nil {
		t.Fatalf("IsInstalled after RemoveCA: %v", err)
	}
	if ok {
		t.Error("IsInstalled = true after RemoveCA, want false")
	}
}
