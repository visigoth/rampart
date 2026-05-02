package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/policy"
)

func TestGenerate_ECDSAKeyPair(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// TLSCert.PrivateKey should be *ecdsa.PrivateKey on all platforms when generated.
	key, ok := gen.TLSCert().PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("PrivateKey type = %T, want *ecdsa.PrivateKey", gen.TLSCert().PrivateKey)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", key.Curve)
	}
}

func TestGenerate_TenYearValidity(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cert := gen.Cert
	validity := cert.NotAfter.Sub(cert.NotBefore)
	minValidity := 9 * 365 * 24 * time.Hour
	if validity < minValidity {
		t.Errorf("validity = %v, want >= 9 years", validity)
	}
}

func TestGenerate_CABasicConstraints(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cert := gen.Cert
	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid = false")
	}
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}
	if !cert.MaxPathLenZero {
		t.Error("MaxPathLenZero = false, want true")
	}
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, want)
	}
}

func TestGenerate_SubjectCN(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cn := gen.Cert.Subject.CommonName
	if cn == "" {
		t.Error("CommonName is empty")
	}
	// Should contain "rampart CA".
	if len(cn) < len("rampart CA") {
		t.Errorf("CommonName %q too short", cn)
	}
}

func TestGenerate_CertPEM(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(gen.CertPEM) == 0 {
		t.Error("CertPEM is empty")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(gen.CertPEM) {
		t.Error("CertPEM is not valid PEM")
	}
}

func TestGenerate_KeyPEM(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(gen.KeyPEM) == 0 {
		t.Error("KeyPEM is empty")
	}
}

func TestGenerate_TLSCert_HasLeaf(t *testing.T) {
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gen.TLSCert().Leaf == nil {
		t.Error("TLSCert.Leaf is nil")
	}
}

func TestNeedsMITM_EmptyPolicy(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	if NeedsMITM(rp) {
		t.Error("NeedsMITM = true for empty policy, want false")
	}
}

func TestNeedsMITM_WithMitmDomains(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		MitmDomains: []string{"api.example.com"},
	}
	if !NeedsMITM(rp) {
		t.Error("NeedsMITM = false when MitmDomains is set, want true")
	}
}

func TestDefaultConfigDir_ContainsRampart(t *testing.T) {
	dir, err := DefaultConfigDir()
	if err != nil {
		t.Fatalf("DefaultConfigDir: %v", err)
	}
	if dir == "" {
		t.Error("DefaultConfigDir returned empty string")
	}
}
