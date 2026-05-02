//go:build linux

package linux

import (
	"testing"

	"github.com/visigoth/rampart/internal/policy"
)

func minimalNetPolicy(networkMode string, allowedDomains []string) *policy.ResolvedPolicy {
	return &policy.ResolvedPolicy{
		Mode:           "enforcing",
		ProfileName:    "test",
		NetworkMode:    networkMode,
		AllowedDomains: allowedDomains,
	}
}

// hasIPTablesRule checks that a specific iptables rule is present in the list.
func hasIPTablesRule(rules [][]string, args ...string) bool {
	for _, rule := range rules {
		if len(rule) != len(args) {
			continue
		}
		match := true
		for i, a := range args {
			if rule[i] != a {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// --- Baseline rules ---

func TestCompileIptables_DefaultDropIPv4(t *testing.T) {
	rp := minimalNetPolicy("none", nil)
	result := CompileIptables(rp)

	if !hasIPTablesRule(result.IPv4, "-P", "OUTPUT", "DROP") {
		t.Errorf("missing -P OUTPUT DROP in IPv4 rules: %v", result.IPv4)
	}
}

func TestCompileIptables_DefaultDropIPv6(t *testing.T) {
	rp := minimalNetPolicy("none", nil)
	result := CompileIptables(rp)

	if !hasIPTablesRule(result.IPv6, "-P", "OUTPUT", "DROP") {
		t.Errorf("missing -P OUTPUT DROP in IPv6 rules: %v", result.IPv6)
	}
}

func TestCompileIptables_LoopbackAllowedIPv4(t *testing.T) {
	rp := minimalNetPolicy("none", nil)
	result := CompileIptables(rp)

	if !hasIPTablesRule(result.IPv4, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT") {
		t.Errorf("missing loopback ACCEPT in IPv4 rules: %v", result.IPv4)
	}
}

func TestCompileIptables_LoopbackAllowedIPv6(t *testing.T) {
	rp := minimalNetPolicy("none", nil)
	result := CompileIptables(rp)

	if !hasIPTablesRule(result.IPv6, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT") {
		t.Errorf("missing loopback ACCEPT in IPv6 rules: %v", result.IPv6)
	}
}

// --- Empty domain list ---

func TestCompileIptables_EmptyDomains_OnlyBaseline(t *testing.T) {
	rp := minimalNetPolicy("filtered", []string{})
	result := CompileIptables(rp)

	// Only the 2 baseline rules (DROP + loopback) for each family.
	if len(result.IPv4) != 2 {
		t.Errorf("IPv4 rules: got %d, want 2 (drop + loopback): %v", len(result.IPv4), result.IPv4)
	}
	if len(result.IPv6) != 2 {
		t.Errorf("IPv6 rules: got %d, want 2 (drop + loopback): %v", len(result.IPv6), result.IPv6)
	}
}

// --- Network mode none ---

func TestCompileIptables_NetworkNone_NoExtraRules(t *testing.T) {
	rp := minimalNetPolicy("none", []string{"api.anthropic.com"})
	result := CompileIptables(rp)

	// Even with domains listed, network=none means no domain resolution.
	if len(result.IPv4) != 2 {
		t.Errorf("network=none should produce only baseline rules; got: %v", result.IPv4)
	}
}

// --- DNS resolution for well-known domains ---

func TestCompileIptables_AllowedDomain_Localhost(t *testing.T) {
	// Use "localhost" as a domain — guaranteed to resolve to 127.0.0.1 and/or ::1.
	rp := minimalNetPolicy("filtered", []string{"localhost"})
	result := CompileIptables(rp)

	// Should have DROP + loopback + at least one ACCEPT for resolved IP.
	hasAccept := false
	for _, rule := range result.IPv4 {
		if len(rule) == 6 && rule[0] == "-A" && rule[1] == "OUTPUT" && rule[2] == "-d" && rule[4] == "-j" && rule[5] == "ACCEPT" {
			hasAccept = true
			break
		}
	}
	// Also check IPv6 ::1.
	for _, rule := range result.IPv6 {
		if len(rule) == 6 && rule[0] == "-A" && rule[1] == "OUTPUT" && rule[2] == "-d" && rule[4] == "-j" && rule[5] == "ACCEPT" {
			hasAccept = true
			break
		}
	}
	if !hasAccept {
		t.Errorf("expected at least one ACCEPT rule for localhost; IPv4=%v IPv6=%v", result.IPv4, result.IPv6)
	}
}

// --- Unresolvable domain ---

func TestCompileIptables_UnresolvableDomain_Warns(t *testing.T) {
	rp := minimalNetPolicy("filtered", []string{"this-domain-definitely-does-not-exist.invalid"})
	result := CompileIptables(rp)

	if len(result.Warnings) == 0 {
		t.Error("expected warning for unresolvable domain")
	}
	// Despite the failure, baseline rules should still be present.
	if !hasIPTablesRule(result.IPv4, "-P", "OUTPUT", "DROP") {
		t.Error("DROP rule missing after DNS failure")
	}
}

// --- Deduplication ---

func TestCompileIptables_DuplicateDomains_NoDupRules(t *testing.T) {
	// "localhost" resolves the same both times.
	rp := minimalNetPolicy("filtered", []string{"localhost", "localhost"})
	result := CompileIptables(rp)

	// Count ACCEPT rules: should not be doubled.
	countAccept := func(rules [][]string) int {
		n := 0
		for _, r := range rules {
			if len(r) > 0 && r[len(r)-1] == "ACCEPT" && r[0] == "-A" {
				n++
			}
		}
		return n
	}

	ipv4Accepts := countAccept(result.IPv4)
	// loopback ACCEPT + one for 127.0.0.1 (if both entries resolve the same IPs)
	// The exact count depends on DNS, but it must not be doubled from the second entry.
	// We test that the total is sane by checking it's ≤ the single-entry count.
	rp1 := minimalNetPolicy("filtered", []string{"localhost"})
	single := CompileIptables(rp1)
	singleAccepts := countAccept(single.IPv4) + countAccept(single.IPv6)
	doubleAccepts := ipv4Accepts + countAccept(result.IPv6)

	if doubleAccepts > singleAccepts {
		t.Errorf("duplicate domains produced more rules: single=%d, double=%d", singleAccepts, doubleAccepts)
	}
}

// --- Table-driven ---

func TestCompileIptables_TableDriven(t *testing.T) {
	cases := []struct {
		name           string
		rp             *policy.ResolvedPolicy
		wantDropIPv4   bool
		wantDropIPv6   bool
		wantLoIPv4     bool
		wantLoIPv6     bool
		wantMinIPv4Len int
		wantMinIPv6Len int
	}{
		{
			name:           "none_mode_baseline",
			rp:             minimalNetPolicy("none", nil),
			wantDropIPv4:   true,
			wantDropIPv6:   true,
			wantLoIPv4:     true,
			wantLoIPv6:     true,
			wantMinIPv4Len: 2,
			wantMinIPv6Len: 2,
		},
		{
			name:           "filtered_empty_domains",
			rp:             minimalNetPolicy("filtered", []string{}),
			wantDropIPv4:   true,
			wantDropIPv6:   true,
			wantLoIPv4:     true,
			wantLoIPv6:     true,
			wantMinIPv4Len: 2,
			wantMinIPv6Len: 2,
		},
		{
			name:           "none_with_domains_still_no_resolv",
			rp:             minimalNetPolicy("none", []string{"localhost"}),
			wantDropIPv4:   true,
			wantLoIPv4:     true,
			wantMinIPv4Len: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := CompileIptables(tc.rp)

			if tc.wantDropIPv4 && !hasIPTablesRule(result.IPv4, "-P", "OUTPUT", "DROP") {
				t.Errorf("missing IPv4 DROP: %v", result.IPv4)
			}
			if tc.wantDropIPv6 && !hasIPTablesRule(result.IPv6, "-P", "OUTPUT", "DROP") {
				t.Errorf("missing IPv6 DROP: %v", result.IPv6)
			}
			if tc.wantLoIPv4 && !hasIPTablesRule(result.IPv4, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT") {
				t.Errorf("missing IPv4 loopback: %v", result.IPv4)
			}
			if tc.wantLoIPv6 && !hasIPTablesRule(result.IPv6, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT") {
				t.Errorf("missing IPv6 loopback: %v", result.IPv6)
			}
			if len(result.IPv4) < tc.wantMinIPv4Len {
				t.Errorf("IPv4 len: got %d, want >= %d", len(result.IPv4), tc.wantMinIPv4Len)
			}
			if len(result.IPv6) < tc.wantMinIPv6Len {
				t.Errorf("IPv6 len: got %d, want >= %d", len(result.IPv6), tc.wantMinIPv6Len)
			}
		})
	}
}

// --- IPTablesCommand helper ---

func TestIPTablesCommand_IPv4Family(t *testing.T) {
	rule := []string{"-P", "OUTPUT", "DROP"}
	cmd := IPTablesCommand("iptables", rule)

	if cmd[0] != "iptables" {
		t.Errorf("first element should be 'iptables', got %q", cmd[0])
	}
	if len(cmd) != 4 {
		t.Errorf("cmd len: got %d, want 4", len(cmd))
	}
}

func TestIPTablesCommand_IPv6Family(t *testing.T) {
	rule := []string{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}
	cmd := IPTablesCommand("ip6tables", rule)

	if cmd[0] != "ip6tables" {
		t.Errorf("first element should be 'ip6tables', got %q", cmd[0])
	}
}
