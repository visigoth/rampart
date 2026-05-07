package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/proxy"
)

// TestProxySubsystem_NameStable pins the subsystem name used for diagnostics.
func TestProxySubsystem_NameStable(t *testing.T) {
	ps := &proxySubsystem{}
	if got := ps.Name(); got != "proxy" {
		t.Errorf("Name() = %q, want %q", got, "proxy")
	}
}

// TestProxySubsystem_RunBlocksUntilCtxDone verifies the adapter holds the
// proxy alive until ctx is cancelled, then closes it cleanly.
func TestProxySubsystem_RunBlocksUntilCtxDone(t *testing.T) {
	p, err := proxy.Start(proxy.Config{})
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	ps := &proxySubsystem{p: p}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ps.Run(ctx) }()

	// Run must not return before ctx is cancelled.
	select {
	case err := <-done:
		t.Fatalf("Run returned before ctx cancel: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// TestProxySubsystem_RunRemovesCACertFile verifies the temp PEM bundle is
// cleaned up on shutdown so we don't leak files across sessions.
func TestProxySubsystem_RunRemovesCACertFile(t *testing.T) {
	p, err := proxy.Start(proxy.Config{})
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	caPath := filepath.Join(t.TempDir(), "rampart-ca.pem")
	if err := os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatalf("seeding ca file: %v", err)
	}

	ps := &proxySubsystem{p: p, caCertPath: caPath}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := ps.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Errorf("CA cert path still exists: err=%v", err)
	}
}

// TestProxyEnvVars_NoCAOmitsBundleVars covers the tunnel-only case where
// MITM is not in use; only the proxy URL vars should be set.
func TestProxyEnvVars_NoCAOmitsBundleVars(t *testing.T) {
	got := proxyEnvVars(31337, "")

	mustContain(t, got, "HTTP_PROXY=http://127.0.0.1:31337")
	mustContain(t, got, "HTTPS_PROXY=http://127.0.0.1:31337")
	mustContain(t, got, "http_proxy=http://127.0.0.1:31337")
	mustContain(t, got, "https_proxy=http://127.0.0.1:31337")

	for _, kv := range got {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		switch k {
		case "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS":
			t.Errorf("unexpected CA env var when caCertPath empty: %q", kv)
		}
	}
}

// TestProxyEnvVars_WithCAIncludesBundleVars covers the MITM case where the CA
// bundle path must be exposed under the standard env names so language
// runtimes (Go, Python, Node) trust the rampart CA.
func TestProxyEnvVars_WithCAIncludesBundleVars(t *testing.T) {
	got := proxyEnvVars(8080, "/tmp/ca.pem")

	mustContain(t, got, "HTTP_PROXY=http://127.0.0.1:8080")
	mustContain(t, got, "SSL_CERT_FILE=/tmp/ca.pem")
	mustContain(t, got, "REQUESTS_CA_BUNDLE=/tmp/ca.pem")
	mustContain(t, got, "NODE_EXTRA_CA_CERTS=/tmp/ca.pem")
}

func mustContain(t *testing.T, env []string, want string) {
	t.Helper()
	for _, kv := range env {
		if kv == want {
			return
		}
	}
	t.Errorf("env missing %q\ngot: %v", want, env)
}
