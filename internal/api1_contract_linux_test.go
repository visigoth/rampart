//go:build linux

package rampart_test

// Linux-specific API1 contract tests.
// API1.5 (CompileSeccomp), API1.6 (CompileBwrapFlags), API1.7 (CompileIptables).
// See .plans/rampart/contracts/api1-internal.org.

import (
	"testing"

	"github.com/visigoth/rampart/internal/policy"
	linux "github.com/visigoth/rampart/internal/sandbox/linux"
)

// --------------------------------------------------------------------------
// API1.6: CompileBwrapFlags — linux.CompileBwrapFlags
// --------------------------------------------------------------------------

// Compile-time assertion: CompileBwrapFlags(*ResolvedPolicy) []string.
var _ = func(rp *policy.ResolvedPolicy) []string {
	return linux.CompileBwrapFlags(rp)
}

func TestContractAPI16_CompileBwrapFlags_Signature(t *testing.T) {
	rp := &policy.ResolvedPolicy{
		FilesystemMode: "read-only",
		NetworkMode:    "none",
	}
	flags := linux.CompileBwrapFlags(rp)
	if len(flags) == 0 {
		t.Error("CompileBwrapFlags should return non-empty flags for any policy")
	}
}

func TestContractAPI16_CompileBwrapFlags_ReturnsStringSlice(t *testing.T) {
	rp := minimalPolicy()
	flags := linux.CompileBwrapFlags(rp)
	// Every element must be a string (compile-time) — runtime check for baseline flags.
	hasUnshare := false
	for _, f := range flags {
		if f == "--unshare-all" {
			hasUnshare = true
		}
	}
	if !hasUnshare {
		t.Error("bwrap flags should contain --unshare-all (FR25 baseline)")
	}
}

func TestContractAPI16_CompileBwrapFlags_WritePaths_UsesBindMount(t *testing.T) {
	rp := minimalPolicy()
	rp.Write = []string{"/workspace"}
	flags := linux.CompileBwrapFlags(rp)
	// Write paths get --bind, not --ro-bind.
	found := false
	for i, f := range flags {
		if f == "--bind" && i+1 < len(flags) && flags[i+1] == "/workspace" {
			found = true
		}
	}
	if !found {
		t.Error("write path /workspace should appear as --bind in bwrap flags")
	}
}

// --------------------------------------------------------------------------
// API1.5: CompileSeccomp — linux.CompileSeccomp
// --------------------------------------------------------------------------

// Compile-time assertion: CompileSeccomp(SeccompOptions) ([]byte, error).
var _ = func(opts linux.SeccompOptions) ([]byte, error) {
	return linux.CompileSeccomp(opts)
}

func TestContractAPI15_CompileSeccomp_Signature(t *testing.T) {
	bpf, err := linux.CompileSeccomp(linux.SeccompOptions{})
	if err != nil {
		t.Fatalf("CompileSeccomp: %v", err)
	}
	if len(bpf) == 0 {
		t.Error("CompileSeccomp should return non-empty BPF bytes")
	}
}

func TestContractAPI15_SeccompOptions_TestREPLMode_FieldExists(t *testing.T) {
	// Compile-time: SeccompOptions.TestREPLMode must exist as bool.
	opts := linux.SeccompOptions{
		TestREPLMode: false,
	}
	_, err := linux.CompileSeccomp(opts)
	_ = err
}

func TestContractAPI15_CompileSeccomp_TestREPLMode_ProducesFilter(t *testing.T) {
	bpf, err := linux.CompileSeccomp(linux.SeccompOptions{TestREPLMode: true})
	if err != nil {
		t.Fatalf("CompileSeccomp(TestREPLMode): %v", err)
	}
	if len(bpf) == 0 {
		t.Error("TestREPLMode should still produce a BPF filter")
	}
}

// --------------------------------------------------------------------------
// API1.7: CompileIptables — linux.CompileIptables
// --------------------------------------------------------------------------

// Compile-time assertion: CompileIptables(*ResolvedPolicy) IPTablesRules.
var _ = func(rp *policy.ResolvedPolicy) linux.IPTablesRules {
	return linux.CompileIptables(rp)
}

func TestContractAPI17_CompileIptables_Signature(t *testing.T) {
	rp := minimalPolicy()
	rules := linux.CompileIptables(rp)
	// IPTablesRules must have IPv4, IPv6, Warnings fields.
	_ = rules.IPv4     // [][]string
	_ = rules.IPv6     // [][]string
	_ = rules.Warnings // []string
}

func TestContractAPI17_CompileIptables_DefaultDrop_IsPresent(t *testing.T) {
	rp := minimalPolicy()
	rp.NetworkMode = "filtered"
	rules := linux.CompileIptables(rp)
	// Default DROP on OUTPUT must be the first rule (TR64.1).
	if len(rules.IPv4) == 0 {
		t.Fatal("IPv4 rules should not be empty")
	}
	first := rules.IPv4[0]
	hasPolicy := false
	for i, tok := range first {
		if tok == "OUTPUT" && i > 0 && first[i-1] == "-P" {
			hasPolicy = true
		}
	}
	if !hasPolicy {
		t.Errorf("first IPv4 rule should set OUTPUT chain policy: %v", first)
	}
}

func TestContractAPI17_CompileIptables_NetworkModeNone_EmitsDropOnly(t *testing.T) {
	rp := minimalPolicy()
	rp.NetworkMode = "none"
	rp.AllowedDomains = []string{"api.example.com"}
	rules := linux.CompileIptables(rp)
	// network_mode=none means no domain-specific ACCEPT rules.
	// Only DROP baseline + loopback ACCEPT should be present.
	for _, rule := range rules.IPv4 {
		for _, tok := range rule {
			if tok == "ACCEPT" {
				// loopback accept is fine; domain ACCEPT would be a bug
				isLoopback := false
				for _, t := range rule {
					if t == "lo" {
						isLoopback = true
					}
				}
				if !isLoopback {
					t.Errorf("network_mode=none should not produce non-loopback ACCEPT rules: %v", rule)
				}
			}
		}
	}
}

func TestContractAPI17_IPTablesRules_CommandStructure(t *testing.T) {
	rp := minimalPolicy()
	rules := linux.CompileIptables(rp)
	// Each rule must be a non-empty string slice ([]string, suitable for exec).
	for i, rule := range rules.IPv4 {
		if len(rule) == 0 {
			t.Errorf("IPv4 rule[%d] is empty", i)
		}
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func minimalPolicy() *policy.ResolvedPolicy {
	return &policy.ResolvedPolicy{
		AgentName:      "test-agent",
		ProfileName:    "test/default",
		FilesystemMode: "read-only",
		NetworkMode:    "none",
		Mode:           "enforcing",
	}
}
