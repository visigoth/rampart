//go:build linux

package ca

import (
	"fmt"
	"os"
)

// systemCACandidates are the standard CA bundle paths checked in order.
var systemCACandidates = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
	"/etc/pki/tls/certs/ca-bundle.crt",  // RHEL/CentOS/Fedora
	"/etc/ssl/cert.pem",                  // Alpine
}

// BuildCABundle creates a temporary PEM file containing the system CA bundle
// plus the rampart CA certificate (TR30, TR31, TR32).
// The caller must call cleanup() to remove the temp file.
func BuildCABundle(caCertPEM []byte) (bundlePath string, cleanup func(), err error) {
	bundle := buildBundle(caCertPEM)

	f, err := os.CreateTemp("", fmt.Sprintf("rampart-%d-ca-bundle-*.pem", os.Getpid()))
	if err != nil {
		return "", nil, fmt.Errorf("creating CA bundle temp file: %w", err)
	}
	if _, err := f.Write(bundle); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, fmt.Errorf("writing CA bundle: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", nil, fmt.Errorf("closing CA bundle temp file: %w", err)
	}
	path := f.Name()
	return path, func() { os.Remove(path) }, nil
}

// BwrapCAFlags returns bwrap arguments that bind-mount the CA bundle into the
// sandbox and set the standard CA environment variables (TR31, TR33).
func BwrapCAFlags(bundlePath string) []string {
	const debianBundle = "/etc/ssl/certs/ca-certificates.crt"
	const rhelBundle = "/etc/pki/tls/certs/ca-bundle.crt"
	return []string{
		"--ro-bind", bundlePath, debianBundle,
		"--ro-bind", bundlePath, rhelBundle,
		"--setenv", "SSL_CERT_FILE", debianBundle,
		"--setenv", "NODE_EXTRA_CA_CERTS", debianBundle,
		"--setenv", "REQUESTS_CA_BUNDLE", debianBundle,
	}
}

// buildBundle assembles the combined CA bundle bytes.
func buildBundle(caCertPEM []byte) []byte {
	var bundle []byte

	// Try to use the host system bundle first.
	for _, path := range systemCACandidates {
		data, err := os.ReadFile(path)
		if err == nil {
			bundle = data
			break
		}
	}

	// If no system bundle found, the rampart CA alone is sufficient for the
	// bwrap sandbox — all HTTPS traffic is routed through the rampart proxy (TR32).

	// Append the rampart CA.
	bundle = append(bundle, caCertPEM...)
	return bundle
}
