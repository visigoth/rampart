package main

import (
	"context"
	"fmt"
	"os"

	"github.com/visigoth/rampart/internal/proxy"
)

// proxySubsystem adapts a running *proxy.Proxy to the supervisor.Subsystem
// interface. The proxy listener is bound by the caller before Run so the
// allocated port is known and can be injected into the child Cmd's env.
// Run blocks until ctx is cancelled, then closes the proxy and removes any
// CA cert bundle written for the sandboxed process.
type proxySubsystem struct {
	p          *proxy.Proxy
	caCertPath string
}

func (ps *proxySubsystem) Name() string { return "proxy" }

func (ps *proxySubsystem) Run(ctx context.Context) error {
	<-ctx.Done()
	closeErr := ps.p.Close()
	if ps.caCertPath != "" {
		_ = os.Remove(ps.caCertPath)
	}
	if closeErr != nil {
		return fmt.Errorf("proxy close: %w", closeErr)
	}
	return nil
}
