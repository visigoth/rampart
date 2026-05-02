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
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
)

// Config holds proxy startup configuration.
type Config struct {
	// Rules are the compiled ACL rules, sorted by specificity descending.
	// Use CompileACLRules to build from ResolvedPolicy.ProxyACLs.
	Rules []ProxyACLRule
	// Logger receives audit log entries. Defaults to slog.Default() if nil.
	Logger *slog.Logger
	// CA is the persistent MITM CA certificate. Required when any rule has MITM: true.
	// If nil and MITM rules exist, Start returns an error directing the user to run 'rampart init'.
	// If nil and no MITM rules exist, the proxy runs in tunnel-only mode (TR35).
	CA *tls.Certificate
}

// Proxy is a running HTTP forward proxy.
type Proxy struct {
	// Port is the loopback TCP port the proxy is listening on.
	Port int
	// CACertPEM is the CA certificate PEM (set when CA was provided in Config).
	// Use this to configure the sandbox trust store for MITM to work.
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

	// Validate: MITM rules require a CA (TR28).
	var mitmAction *goproxy.ConnectAction
	for _, r := range cfg.Rules {
		if r.MITM {
			if cfg.CA == nil {
				return nil, fmt.Errorf("MITM required by ACL rules but no CA installed: run 'rampart init'")
			}
			mitmAction = &goproxy.ConnectAction{
				Action:    goproxy.ConnectMitm,
				TLSConfig: goproxy.TLSConfigFromCA(cfg.CA),
			}
			break
		}
	}

	// Extract CA cert PEM for trust store injection.
	var caPEM []byte
	if cfg.CA != nil && cfg.CA.Leaf != nil {
		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cfg.CA.Leaf.Raw})
	}

	// Build the goproxy handler.
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false

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

