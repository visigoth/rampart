//go:build linux

package ca

import (
	"bytes"
	"crypto/x509"
	"os"
	"testing"
)

func TestBuildCABundle_ContainsRampartCA(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	bundlePath, cleanup, err := BuildCABundle(gen.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}
	defer cleanup()

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("reading bundle: %v", err)
	}
	if !bytes.Contains(data, gen.CertPEM) {
		t.Error("bundle does not contain rampart CA cert PEM")
	}
}

func TestBuildCABundle_IsValidCertPool(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	bundlePath, cleanup, err := BuildCABundle(gen.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}
	defer cleanup()

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("reading bundle: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Error("bundle is not valid PEM cert pool")
	}
}

func TestBuildCABundle_Cleanup(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	bundlePath, cleanup, err := BuildCABundle(gen.CertPEM)
	if err != nil {
		t.Fatalf("BuildCABundle: %v", err)
	}

	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle file should exist before cleanup: %v", err)
	}

	cleanup()

	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Error("bundle file should be removed after cleanup()")
	}
}

func TestBwrapCAFlags_CoversBothBundlePaths(t *testing.T) {
	flags := BwrapCAFlags("/tmp/test-bundle.pem")

	hasDebian := false
	hasRHEL := false
	for i, f := range flags {
		if f == "/etc/ssl/certs/ca-certificates.crt" {
			hasDebian = true
		}
		if f == "/etc/pki/tls/certs/ca-bundle.crt" {
			hasRHEL = true
		}
		_ = i
	}
	if !hasDebian {
		t.Error("BwrapCAFlags missing Debian bundle path /etc/ssl/certs/ca-certificates.crt")
	}
	if !hasRHEL {
		t.Error("BwrapCAFlags missing RHEL bundle path /etc/pki/tls/certs/ca-bundle.crt")
	}
}

func TestBwrapCAFlags_SetsEnvVars(t *testing.T) {
	flags := BwrapCAFlags("/tmp/test-bundle.pem")
	envVars := map[string]bool{
		"SSL_CERT_FILE":        false,
		"NODE_EXTRA_CA_CERTS":  false,
		"REQUESTS_CA_BUNDLE":   false,
	}
	for i := 0; i+1 < len(flags); i++ {
		if flags[i] == "--setenv" {
			envVars[flags[i+1]] = true
		}
	}
	for v, found := range envVars {
		if !found {
			t.Errorf("BwrapCAFlags missing env var %s (TR33)", v)
		}
	}
}

func TestBuildBundle_FallsBackToGoRoots(t *testing.T) {
	// Use an empty CA cert list — just verify buildBundle returns something non-empty.
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bundle := buildBundle(gen.CertPEM)
	if len(bundle) == 0 {
		t.Error("buildBundle returned empty bundle")
	}
	// Must end with or contain the rampart CA PEM.
	if !bytes.Contains(bundle, gen.CertPEM) {
		t.Error("buildBundle does not contain rampart CA cert")
	}
}
