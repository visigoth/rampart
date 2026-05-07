package main

import "fmt"

// proxyEnvVars returns the env-var entries (KEY=VALUE) injected into the
// sandboxed Cmd.Env when the proxy is active. caCertPath may be empty when no
// MITM is required; in that case only HTTP_PROXY/HTTPS_PROXY are set.
func proxyEnvVars(port int, caCertPath string) []string {
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	env := []string{
		"HTTP_PROXY=" + url,
		"HTTPS_PROXY=" + url,
		"http_proxy=" + url,
		"https_proxy=" + url,
	}
	if caCertPath != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCertPath,
			"REQUESTS_CA_BUNDLE="+caCertPath,
			"NODE_EXTRA_CA_CERTS="+caCertPath,
		)
	}
	return env
}
