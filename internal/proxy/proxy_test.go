package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/visigoth/rampart/internal/proxy"
)

// startTestProxy starts a proxy with the given rules and returns the proxy, its URL,
// and a cleanup function.
func startTestProxy(t *testing.T, rules []proxy.ProxyACLRule) (*proxy.Proxy, *url.URL) {
	t.Helper()
	p, err := proxy.Start(proxy.Config{Rules: rules})
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("127.0.0.1:%d", p.Port),
	}
	return p, proxyURL
}

// httpClientViaProxy returns an http.Client that routes through the proxy.
func httpClientViaProxy(proxyURL *url.URL) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
}

// httpClientViaProxyWithCA returns an http.Client that routes through the proxy and
// trusts the provided CA cert PEM for HTTPS MITM.
func httpClientViaProxyWithCA(t *testing.T, proxyURL *url.URL, caPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse CA cert PEM")
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}
}

func TestProxy_AllowedHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello")
	}))
	defer upstream.Close()

	host := mustParseURL(t, upstream.URL).Hostname()
	rules := []proxy.ProxyACLRule{
		{Domain: host, Items: nil, MITM: false}, // empty Items = allow all (TR4)
	}
	_, proxyURL := startTestProxy(t, rules)
	client := httpClientViaProxy(proxyURL)

	resp, err := client.Get(upstream.URL + "/foo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
}

func TestProxy_DeniedHTTP_UnknownDomain(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// No rules at all → domain not found → deny.
	_, proxyURL := startTestProxy(t, nil)
	client := httpClientViaProxy(proxyURL)

	resp, err := client.Get(upstream.URL + "/secret")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	assertDenyBody(t, resp)
}

func TestProxy_DeniedHTTP_ACLRule(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host := mustParseURL(t, upstream.URL).Hostname()
	rules := []proxy.ProxyACLRule{
		{
			Domain: host,
			Items: []proxy.ACLItem{
				{Allow: true, Method: "GET", Paths: []string{"/allowed"}},
				{Allow: false}, // deny everything else
			},
		},
	}
	_, proxyURL := startTestProxy(t, rules)
	client := httpClientViaProxy(proxyURL)

	resp, err := client.Get(upstream.URL + "/forbidden")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	assertDenyBody(t, resp)
}

func TestProxy_AllowedHTTP_PathACL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "allowed")
	}))
	defer upstream.Close()

	host := mustParseURL(t, upstream.URL).Hostname()
	rules := []proxy.ProxyACLRule{
		{
			Domain: host,
			Items: []proxy.ACLItem{
				{Allow: true, Method: "GET", Paths: []string{"/api/**"}},
				{Allow: false},
			},
		},
	}
	_, proxyURL := startTestProxy(t, rules)
	client := httpClientViaProxy(proxyURL)

	resp, err := client.Get(upstream.URL + "/api/v1/resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestProxy_DeniedHTTPS_UnknownDomain(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// No rules → CONNECT should be rejected.
	_, proxyURL := startTestProxy(t, nil)

	// Use a client that skips upstream TLS verification but has no proxy CA.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test only
			},
		},
	}

	_, err := client.Get(upstream.URL + "/secret")
	if err == nil {
		t.Fatal("expected error (CONNECT rejected), got nil")
	}
	// goproxy responds with 403 for rejected CONNECT.
}

func TestProxy_AllowedHTTPS_Tunnel(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "secure")
	}))
	defer upstream.Close()

	host := mustParseURL(t, upstream.URL).Hostname()
	// Domain allowed, no path rules → tunnel (no MITM).
	rules := []proxy.ProxyACLRule{
		{Domain: host, Items: nil, MITM: false},
	}
	_, proxyURL := startTestProxy(t, rules)

	// Must trust the upstream test server's cert (not the proxy CA).
	pool := x509.NewCertPool()
	for _, c := range upstream.TLS.Certificates {
		x509Cert, _ := x509.ParseCertificate(c.Certificate[0])
		pool.AddCert(x509Cert)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure" {
		t.Errorf("body = %q, want %q", body, "secure")
	}
}

func TestProxy_MITM_AllowedPath(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "mitm-allowed")
	}))
	defer upstream.Close()

	host := mustParseURL(t, upstream.URL).Hostname()
	rules := []proxy.ProxyACLRule{
		{
			Domain: host,
			Items: []proxy.ACLItem{
				{Allow: true, Paths: []string{"/allowed/**"}},
				{Allow: false},
			},
			MITM: true,
		},
	}
	p, proxyURL := startTestProxy(t, rules)
	client := httpClientViaProxyWithCA(t, proxyURL, p.CACertPEM)

	resp, err := client.Get(upstream.URL + "/allowed/resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestProxy_MITM_DeniedPath(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host := mustParseURL(t, upstream.URL).Hostname()
	rules := []proxy.ProxyACLRule{
		{
			Domain: host,
			Items: []proxy.ACLItem{
				{Allow: true, Paths: []string{"/allowed/**"}},
				{Allow: false},
			},
			MITM: true,
		},
	}
	p, proxyURL := startTestProxy(t, rules)
	client := httpClientViaProxyWithCA(t, proxyURL, p.CACertPEM)

	resp, err := client.Get(upstream.URL + "/forbidden/resource")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	assertDenyBody(t, resp)
}

// assertDenyBody verifies the response body is valid JSON with an "error" field.
func assertDenyBody(t *testing.T, resp *http.Response) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body is not JSON: %v\nbody: %s", err, body)
	}
	if m["error"] == nil {
		t.Errorf("deny body missing 'error' field: %s", body)
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	return u
}
