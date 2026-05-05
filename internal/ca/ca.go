// Package ca manages the rampart persistent MITM CA certificate (FT16, FR68).
//
// The CA is generated once by 'rampart init' and reused across sessions,
// making runtime headless-friendly (trust established at init time).
//
// Platform storage:
//   - macOS: Keychain stores cert and private key; key never extracted to disk (TR20).
//   - Linux: ~/.config/rampart/ca.pem (0644), ca-key.pem (0600) (TR21).
//
// Usage:
//
//	gen, err := ca.Generate()         // creates new CA
//	err = ca.SaveCA(gen.CertPEM, gen.KeyPEM) // persists to platform storage
//	ca, err := ca.LoadCA()             // loads for runtime use
//	proxy.Start(proxy.Config{CA: ca.TLSCert()})
//
// Design ref: .plans/rampart/tdd/mitm-cert-management.org TR19-TR35.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/visigoth/rampart/internal/policy"
)

// ErrNotInstalled is returned by LoadCA when no CA has been installed.
var ErrNotInstalled = errors.New("rampart CA not installed: run 'rampart init' to set it up")

// CA storage is dispatched through these function variables so tests can swap
// in an in-memory store. Production code reads/writes the platform-specific
// store (Keychain on darwin, ~/.config/rampart on linux) via the default
// implementations defined in store_<os>.go.
var (
	// SaveCA persists the CA cert and private key to platform storage.
	SaveCA = saveCA
	// LoadCA retrieves the CA from platform storage. Returns ErrNotInstalled
	// if no CA has been saved.
	LoadCA = loadCA
	// IsInstalled reports whether a CA is currently in platform storage.
	IsInstalled = isInstalled
	// RemoveCA deletes the CA cert and private key from platform storage.
	RemoveCA = removeCA
)

// CA is the runtime representation of the rampart MITM certificate authority.
// Obtain via LoadCA; use TLSCert for proxy integration.
type CA struct {
	// Cert is the parsed CA certificate.
	Cert *x509.Certificate
	// CertPEM is the PEM-encoded CA certificate (for trust store injection).
	CertPEM []byte

	// tlsCert is the goproxy-compatible certificate with the appropriate Signer.
	// On Linux: PrivateKey is *ecdsa.PrivateKey.
	// On macOS: PrivateKey is a *keychainSigner backed by SecKeyRef (TR29).
	tlsCert tls.Certificate
}

// TLSCert returns the goproxy-compatible certificate.
func (ca *CA) TLSCert() *tls.Certificate {
	return &ca.tlsCert
}

// Generated is the output of Generate: the CA for immediate use plus key PEM for storage.
type Generated struct {
	*CA
	// KeyPEM is the PEM-encoded private key. Pass to SaveCA for platform storage.
	// After SaveCA, the key lives only in platform storage.
	KeyPEM []byte
}

// Generate creates a new ECDSA P-256 self-signed CA with 10-year validity (TR19, TR22).
// The returned Generated.KeyPEM must be passed to SaveCA to persist the CA.
func Generate() (*Generated, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA P-256 key: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("rampart CA (%s)", hostname),
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("assembling TLS certificate: %w", err)
	}
	tlsCert.Leaf = cert

	return &Generated{
		CA: &CA{
			Cert:    cert,
			CertPEM: certPEM,
			tlsCert: tlsCert,
		},
		KeyPEM: keyPEM,
	}, nil
}

// NeedsMITM reports whether the resolved policy requires MITM inspection (TR35).
// Returns true if the policy has any MITM domains (domains with path rules).
func NeedsMITM(rp *policy.ResolvedPolicy) bool {
	return len(rp.MitmDomains) > 0
}

// DefaultConfigDir returns the rampart config directory (~/.config/rampart/).
func DefaultConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}
	return filepath.Join(home, ".config", "rampart"), nil
}
