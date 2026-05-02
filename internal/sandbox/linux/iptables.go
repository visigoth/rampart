//go:build linux

// This file implements CompileIptables (part of FT5): converts allowed domains
// in a ResolvedPolicy to iptables commands for the bwrap network namespace.
//
// Network isolation approach (TR64):
//   - Default DROP on OUTPUT chain (all outbound blocked unless explicitly allowed)
//   - Loopback always allowed (HTTP proxy runs on 127.0.0.1)
//   - Allowed domains resolved to IPs at compile time; each IP gets an ACCEPT rule
//   - DNS failures produce a warning but don't block compilation (TR14: proxy fallback)
//   - IPv6 addresses produce ip6tables rules in parallel
package linux

import (
	"fmt"
	"net"

	"github.com/visigoth/rampart/internal/policy"
)

// IPTablesRules holds the compiled iptables and ip6tables commands.
type IPTablesRules struct {
	// IPv4 holds iptables commands for the network namespace.
	IPv4 [][]string
	// IPv6 holds ip6tables commands for the network namespace.
	IPv6 [][]string
	// Warnings holds domain names that could not be resolved.
	Warnings []string
}

// CompileIptables converts a ResolvedPolicy to iptables/ip6tables rule lists.
// The rules are meant to be applied inside a bwrap network namespace.
//
// Callers apply rules by executing each command with the iptables / ip6tables
// CLI tool, e.g.:
//
//	exec.Command("iptables", rules.IPv4[0]...).Run()
func CompileIptables(rp *policy.ResolvedPolicy) IPTablesRules {
	result := IPTablesRules{}

	// --- Default DROP on OUTPUT (TR64.1) ---
	result.IPv4 = append(result.IPv4, []string{"-P", "OUTPUT", "DROP"})
	result.IPv6 = append(result.IPv6, []string{"-P", "OUTPUT", "DROP"})

	// --- Allow loopback for proxy access (TR64.2) ---
	result.IPv4 = append(result.IPv4, []string{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"})
	result.IPv6 = append(result.IPv6, []string{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"})

	// Short-circuit: no network or nothing to allow.
	if rp.NetworkMode == "none" || len(rp.AllowedDomains) == 0 {
		return result
	}

	// --- Resolve domains to IPs (TR7) ---
	seen := make(map[string]bool)
	for _, domain := range rp.AllowedDomains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("DNS resolution failed for %q: %v (rule skipped, proxy handles domain)", domain, err))
			continue
		}
		for _, ipStr := range ips {
			if seen[ipStr] {
				continue
			}
			seen[ipStr] = true

			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}

			rule := []string{"-A", "OUTPUT", "-d", ipStr, "-j", "ACCEPT"}
			if ip.To4() != nil {
				result.IPv4 = append(result.IPv4, rule)
			} else {
				result.IPv6 = append(result.IPv6, rule)
			}
		}
	}

	return result
}

// IPTablesCommand returns a command invocation for an iptables or ip6tables
// rule, for use as a direct exec argument list (no shell interpolation needed).
// family is "iptables" or "ip6tables".
func IPTablesCommand(family string, rule []string) []string {
	return append([]string{family}, rule...)
}
