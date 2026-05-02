//go:build linux

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

const (
	certFileName = "ca.pem"
	keyFileName  = "ca-key.pem"
	dirMode      = 0700
	certMode     = 0644
	keyMode      = 0600
)

// SaveCA persists the CA cert and private key to ~/.config/rampart/ (TR21, TR23).
// Directory is created with mode 0700; ca.pem is 0644, ca-key.pem is 0600.
func SaveCA(certPEM, keyPEM []byte) error {
	dir, err := DefaultConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("setting dir permissions: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFileName), certPEM, certMode); err != nil {
		return fmt.Errorf("writing ca.pem: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFileName), keyPEM, keyMode); err != nil {
		return fmt.Errorf("writing ca-key.pem: %w", err)
	}
	return nil
}

// LoadCA reads the CA from ~/.config/rampart/ and returns it ready for proxy use.
// Returns ErrNotInstalled if the CA files are missing.
func LoadCA() (*CA, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, certFileName))
	if os.IsNotExist(err) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, fmt.Errorf("reading ca.pem: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if os.IsNotExist(err) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, fmt.Errorf("reading ca-key.pem: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading CA key pair: %w", err)
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	tlsCert.Leaf = cert

	return &CA{
		Cert:    cert,
		CertPEM: certPEM,
		tlsCert: tlsCert,
	}, nil
}

// IsInstalled reports whether the CA is present on disk.
func IsInstalled() (bool, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(filepath.Join(dir, certFileName))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// RemoveCA deletes the CA cert and key files from ~/.config/rampart/.
func RemoveCA() error {
	dir, err := DefaultConfigDir()
	if err != nil {
		return err
	}
	certErr := os.Remove(filepath.Join(dir, certFileName))
	keyErr := os.Remove(filepath.Join(dir, keyFileName))
	if certErr != nil && !os.IsNotExist(certErr) {
		return fmt.Errorf("removing ca.pem: %w", certErr)
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return fmt.Errorf("removing ca-key.pem: %w", keyErr)
	}
	return nil
}
