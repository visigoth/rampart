// Package proxy implements the rampart HTTP forward proxy (FT16).
//
// The proxy enforces network ACL rules derived from the resolved policy:
//   - HTTP requests: domain + method/path filtering with 403 on deny.
//   - HTTPS CONNECT: domain check; tunnel (OkConnect) or MITM (MitmConnect).
//   - HTTPS MITM: decrypts TLS for domains with path rules, re-applies ACL.
//   - All requests are audit-logged via slog.
//
// Design refs: .plans/rampart/features/network-isolation.org,
//              .plans/rampart/contracts/api4-http-proxy.org, TR1-TR18.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
)

// Config holds proxy startup configuration.
type Config struct {
	// Rules are the compiled ACL rules, sorted by specificity descending.
	// Use CompileACLRules to build from ResolvedPolicy.ProxyACLs.
	Rules []ProxyACLRule
	// Logger receives audit log entries. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

// Proxy is a running HTTP forward proxy.
type Proxy struct {
	// Port is the loopback TCP port the proxy is listening on.
	Port int
	// CACertPEM is the ephemeral CA certificate in PEM format.
	// Install this in the sandbox trust store for MITM to work.
	CACertPEM []byte

	ln  net.Listener
	srv *http.Server
}

// Start starts the proxy on a random loopback port and returns immediately.
// Call Close to stop the proxy.
func Start(cfg Config) (*Proxy, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Generate per-session ephemeral CA for MITM (TR68.1).
	ca, caPEM, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("generating MITM CA: %w", err)
	}

	// Build the goproxy handler.
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false

	mitmAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(ca),
	}

	// HTTPS CONNECT handler: domain check, then MITM or tunnel (TR6, TR67, TR68).
	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		rule, ok := FindMatchingRule(cfg.Rules, host)
		if !ok {
			cfg.Logger.Info("proxy CONNECT denied",
				"host", host, "reason", "domain not in allowed list")
			return goproxy.RejectConnect, host
		}
		if rule.MITM {
			return mitmAction, host
		}
		return goproxy.OkConnect, host
	})

	// HTTP (and MITM'd HTTPS) request handler: domain + method/path ACL (TR3, TR12, TR66).
	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		host := req.Host
		method := req.Method
		path := req.URL.Path
		if path == "" {
			path = "/"
		}

		rule, ok := FindMatchingRule(cfg.Rules, host)
		if !ok {
			cfg.Logger.Info("proxy request denied",
				"method", method, "host", host, "path", path, "reason", "domain not in allowed list")
			return req, denyResponse(req, domainFromHost(host), method, path, "domain not in allowed list")
		}

		verdict := rule.EvalRequest(method, path)
		if verdict == VerdictDeny {
			cfg.Logger.Info("proxy request denied",
				"method", method, "host", host, "path", path, "domain", rule.Domain, "reason", "acl rule")
			return req, denyResponse(req, domainFromHost(host), method, path, "denied by ACL rule")
		}

		cfg.Logger.Info("proxy request allowed",
			"method", method, "host", host, "path", path, "domain", rule.Domain)
		return req, nil
	})

	// Listen on random loopback port (AC30, FR65).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("proxy listen: %w", err)
	}

	srv := &http.Server{Handler: gp}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			cfg.Logger.Warn("proxy server error", "err", err)
		}
	}()

	return &Proxy{
		Port:      ln.Addr().(*net.TCPAddr).Port,
		CACertPEM: caPEM,
		ln:        ln,
		srv:       srv,
	}, nil
}

// Close shuts the proxy down.
func (p *Proxy) Close() error {
	return p.srv.Close()
}

// denyResponse builds a 403 JSON response per TR12.
func denyResponse(req *http.Request, domain, method, path, reason string) *http.Response {
	type body struct {
		Error  string `json:"error"`
		Domain string `json:"domain"`
		Method string `json:"method"`
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	b, _ := json.Marshal(body{
		Error:  "forbidden",
		Domain: domain,
		Method: method,
		Path:   path,
		Reason: reason,
	})
	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(newJSONReader(b)),
		ContentLength: int64(len(b)),
		Request:       req,
	}
	return resp
}

type jsonReader struct{ data []byte }

func newJSONReader(b []byte) *jsonReader { return &jsonReader{data: b} }

func (j *jsonReader) Read(p []byte) (int, error) {
	if len(j.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, j.data)
	j.data = j.data[n:]
	return n, nil
}

// generateCA generates an ephemeral ECDSA CA certificate for MITM.
// Returns the tls.Certificate and its PEM-encoded DER bytes for env injection.
func generateCA() (*tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Rampart Proxy"},
			CommonName:   "Rampart Ephemeral CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("loading key pair: %w", err)
	}
	if tlsCert.Leaf, err = x509.ParseCertificate(certDER); err != nil {
		return nil, nil, fmt.Errorf("parsing leaf: %w", err)
	}

	return &tlsCert, certPEM, nil
}
