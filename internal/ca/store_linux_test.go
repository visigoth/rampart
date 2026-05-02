//go:build linux

package ca

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempConfigDir sets DefaultConfigDir to a temp dir for the duration of the test.
func withTempConfigDir(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	// Override HOME so DefaultConfigDir resolves to tmp/.config/rampart.
	t.Setenv("HOME", tmp)
	t.Cleanup(func() {
		if origHome == "" {
			os.Unsetenv("HOME")
		}
	})
}

func TestSaveCA_CreatesFiles(t *testing.T) {
	withTempConfigDir(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	dir, _ := DefaultConfigDir()
	if _, err := os.Stat(filepath.Join(dir, certFileName)); err != nil {
		t.Errorf("ca.pem missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err != nil {
		t.Errorf("ca-key.pem missing: %v", err)
	}
}

func TestSaveCA_FilePermissions(t *testing.T) {
	withTempConfigDir(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	dir, _ := DefaultConfigDir()

	// Directory must be 0700.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("dir mode = %04o, want 0700", perm)
	}

	// ca.pem must be 0644.
	certInfo, err := os.Stat(filepath.Join(dir, certFileName))
	if err != nil {
		t.Fatalf("stat ca.pem: %v", err)
	}
	if perm := certInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("ca.pem mode = %04o, want 0644", perm)
	}

	// ca-key.pem must be 0600 (TR21).
	keyInfo, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatalf("stat ca-key.pem: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("ca-key.pem mode = %04o, want 0600", perm)
	}
}

func TestSaveLoadCA_RoundTrip(t *testing.T) {
	withTempConfigDir(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	loaded, err := LoadCA()
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	// Cert should match.
	if loaded.Cert.SerialNumber.Cmp(gen.Cert.SerialNumber) != 0 {
		t.Error("loaded cert serial number differs from generated")
	}
	if string(loaded.CertPEM) != string(gen.CertPEM) {
		t.Error("loaded CertPEM differs from generated")
	}
	if loaded.TLSCert().Leaf == nil {
		t.Error("loaded TLSCert.Leaf is nil")
	}
}

func TestIsInstalled_FalseWhenMissing(t *testing.T) {
	withTempConfigDir(t)
	ok, err := IsInstalled()
	if err != nil {
		t.Fatalf("IsInstalled: %v", err)
	}
	if ok {
		t.Error("IsInstalled = true for empty dir, want false")
	}
}

func TestIsInstalled_TrueAfterSave(t *testing.T) {
	withTempConfigDir(t)
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
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

func TestRemoveCA_DeletesFiles(t *testing.T) {
	withTempConfigDir(t)
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

	dir, _ := DefaultConfigDir()
	if _, err := os.Stat(filepath.Join(dir, certFileName)); !os.IsNotExist(err) {
		t.Error("ca.pem still exists after RemoveCA")
	}
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); !os.IsNotExist(err) {
		t.Error("ca-key.pem still exists after RemoveCA")
	}
}

func TestRemoveCA_IdempotentWhenMissing(t *testing.T) {
	withTempConfigDir(t)
	// RemoveCA on an empty dir should not error.
	if err := RemoveCA(); err != nil {
		t.Errorf("RemoveCA on empty dir: %v", err)
	}
}

func TestLoadCA_ErrNotInstalledWhenMissing(t *testing.T) {
	withTempConfigDir(t)
	_, err := LoadCA()
	if err != ErrNotInstalled {
		t.Errorf("LoadCA err = %v, want ErrNotInstalled", err)
	}
}
