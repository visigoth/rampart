// Package rampart_test contains API1 contract tests for the rampart internal
// Go pipeline. API1 is the cross-package boundary between COMP1 (CLI) and
// COMP2 (sandbox supervisor). See .plans/rampart/contracts/api1-internal.org.
//
// Contract tests serve two purposes:
//  1. Compile-time: type-assertion variables catch signature regressions
//     before they reach callers.
//  2. Smoke-test: minimal runtime checks verify the pipeline produces output
//     of the right shape for valid inputs.
package rampart_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/visigoth/rampart/internal/config"
	"github.com/visigoth/rampart/internal/policy"
	"github.com/visigoth/rampart/internal/proxy"
)

// --------------------------------------------------------------------------
// API1.1: LoadConfigs — config.NewRegistry + Registry.ResolveAgent/Profile
// --------------------------------------------------------------------------

// Compile-time assertion: NewRegistry(string, string) (*Registry, error).
var _ = func(gitRoot, globalDir string) (*config.Registry, error) {
	return config.NewRegistry(gitRoot, globalDir)
}

// Compile-time assertion: Registry.ResolveAgent(string) (*AgentConfig, error).
var _ = func(r *config.Registry, name string) (*config.AgentConfig, error) {
	return r.ResolveAgent(name)
}

// Compile-time assertion: Registry.ResolveProfile(string) (*ProfileConfig, error).
var _ = func(r *config.Registry, name string) (*config.ProfileConfig, error) {
	return r.ResolveProfile(name)
}

func TestContractAPI11_NewRegistry_ReturnsTypedPair(t *testing.T) {
	// Calling with a nonexistent tree is fine — we care about return types, not success.
	reg, err := config.NewRegistry(t.TempDir(), "")
	// reg is *config.Registry (or nil on error)
	_ = reg
	_ = err
}

func TestContractAPI11_ResolveAgent_UnknownName_ReturnsError(t *testing.T) {
	reg, err := api1Fixture(t)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	_, err = reg.ResolveAgent("nonexistent-agent")
	if err == nil {
		t.Error("ResolveAgent(unknown) should return an error")
	}
}

func TestContractAPI11_ResolveProfile_UnknownName_ReturnsError(t *testing.T) {
	reg, err := api1Fixture(t)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	_, err = reg.ResolveProfile("nonexistent/profile")
	if err == nil {
		t.Error("ResolveProfile(unknown) should return an error")
	}
}

func TestContractAPI11_ResolveAgent_KnownName_ReturnsAgentConfig(t *testing.T) {
	reg, err := api1Fixture(t)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	agent, err := reg.ResolveAgent("coding")
	if err != nil {
		t.Fatalf("ResolveAgent: %v", err)
	}
	// ENT1 fields must be populated.
	if agent.Name == "" {
		t.Error("AgentConfig.Name should be populated")
	}
	if agent.Filesystem == "" {
		t.Error("AgentConfig.Filesystem should be populated (ENT1)")
	}
	if agent.NetworkMode == "" {
		t.Error("AgentConfig.NetworkMode should be populated (ENT1)")
	}
}

// --------------------------------------------------------------------------
// API1.2: ResolvePolicy — policy.MergePolicy
// --------------------------------------------------------------------------

// Compile-time assertion: MergePolicy(AgentConfig, ProfileConfig, MergeOptions) → (ResolvedPolicy, error).
var _ = func(a *config.AgentConfig, p *config.ProfileConfig, opts policy.MergeOptions) (*policy.ResolvedPolicy, error) {
	return policy.MergePolicy(a, p, opts)
}

func TestContractAPI12_MergePolicy_ReturnsResolvedPolicyENT3(t *testing.T) {
	agent := minimalAgent()
	profile := minimalProfile()
	rp, err := policy.MergePolicy(agent, profile, policy.MergeOptions{})
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	// Verify ENT3 identity fields are set.
	if rp.AgentName != agent.Name {
		t.Errorf("ResolvedPolicy.AgentName = %q, want %q", rp.AgentName, agent.Name)
	}
	if rp.ProfileName != profile.Name {
		t.Errorf("ResolvedPolicy.ProfileName = %q, want %q", rp.ProfileName, profile.Name)
	}
	// Compile-time: verify all ENT3 field types are accessible.
	_ = rp.FilesystemMode // string
	_ = rp.NetworkMode    // string
	_ = rp.Read           // []string
	_ = rp.Write          // []string
	_ = rp.Exec           // []string
	_ = rp.Toolchains     // []string
	_ = rp.Warnings       // []string
	_ = rp.ProxyACLs      // []config.DomainConfig
	_ = rp.MitmDomains    // []string
	_ = rp.CLIExtraPaths   // []string
	_ = rp.CLIExtraDomains // []string
}

func TestContractAPI12_MergeOptions_FieldsMatchSpec(t *testing.T) {
	// Compile-time: MergeOptions must have Mode, ExtraPaths, ExtraDomains, Strict.
	opts := policy.MergeOptions{
		Mode:         "permissive",
		ExtraPaths:   []string{"/tmp"},
		ExtraDomains: []string{"api.example.com"},
		Strict:       true,
	}
	rp, err := policy.MergePolicy(minimalAgent(), minimalProfile(), opts)
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.Mode != "permissive" {
		t.Errorf("Mode = %q, want permissive", rp.Mode)
	}
}

func TestContractAPI12_MergePolicy_NoError_ForValidInputs(t *testing.T) {
	// API1.2 spec: "Errors: none (always produces a valid policy)"
	// for valid agent+profile. Verify no error for minimal valid input.
	_, err := policy.MergePolicy(minimalAgent(), minimalProfile(), policy.MergeOptions{})
	if err != nil {
		t.Errorf("MergePolicy should not error for valid inputs: %v", err)
	}
}

// --------------------------------------------------------------------------
// API1.3: ResolvePaths — path handling in NewRegistry and MergePolicy
// --------------------------------------------------------------------------
// ResolvePaths is not a standalone exported function; physical-path resolution
// runs inside config.NewRegistry (physicalPath) and profile workdir is
// propagated via MergePolicy. This test documents that contract.

func TestContractAPI13_WorkdirPropagatedFromProfile(t *testing.T) {
	agent := minimalAgent()
	profile := minimalProfile()
	profile.Workdir = "/tmp"

	rp, err := policy.MergePolicy(agent, profile, policy.MergeOptions{})
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.Workdir != "/tmp" {
		t.Errorf("Workdir = %q, want /tmp (ResolvePaths contract)", rp.Workdir)
	}
}

func TestContractAPI13_FindGitRoot_ReturnsStringOrEmpty(t *testing.T) {
	// FindGitRoot is part of the path-resolution pipeline.
	// Compile-time assertion: returns string.
	var _ = func(start string) string {
		return config.FindGitRoot(start)
	}

	// In a non-git directory, FindGitRoot returns "".
	result := config.FindGitRoot(t.TempDir())
	_ = result // "" is acceptable; type is string
}

// --------------------------------------------------------------------------
// API1.8: CompileProxyACLs — proxy.CompileACLRules
// --------------------------------------------------------------------------

// Compile-time: CompileACLRules([]DomainConfig, []string) []ProxyACLRule.
var _ = func(domains []config.DomainConfig, mitm []string) []proxy.ProxyACLRule {
	return proxy.CompileACLRules(domains, mitm)
}

func TestContractAPI18_CompileProxyACLs_EmptyInput_NoError(t *testing.T) {
	rules := proxy.CompileACLRules(nil, nil)
	// nil input → empty (not nil-panic) result.
	_ = rules
}

func TestContractAPI18_CompileProxyACLs_ProxyACLRule_Fields(t *testing.T) {
	domain := config.DomainConfig{
		Pattern: "api.example.com",
		Allow:   []config.RuleConfig{{Method: "*", Paths: []string{"/**"}}},
	}
	rules := proxy.CompileACLRules([]config.DomainConfig{domain}, nil)
	if len(rules) == 0 {
		t.Fatal("expected at least one ProxyACLRule")
	}
	r := rules[0]
	// Compile-time: verify ENT8 fields.
	_ = r.Domain // string
	_ = r.Items  // []proxy.ACLItem
	_ = r.MITM   // bool
	if r.Domain == "" {
		t.Error("ProxyACLRule.Domain should be non-empty")
	}
}

func TestContractAPI18_VerdictEnum_ValuesExist(t *testing.T) {
	// Compile-time check: these enum values must exist with these names.
	var _ proxy.Verdict = proxy.VerdictAllow
	var _ proxy.Verdict = proxy.VerdictDeny
	var _ proxy.Verdict = proxy.VerdictNoMatch
}

// --------------------------------------------------------------------------
// Entity type assertions (ENT1, ENT2, ENT3)
// --------------------------------------------------------------------------

// TestContractENT1_AgentConfig_Fields verifies all contract-specified fields
// of AgentConfig are accessible with the expected types.
func TestContractENT1_AgentConfig_Fields(t *testing.T) {
	a := &config.AgentConfig{}
	// Compile-time field type checks.
	_ = a.Name        // string
	_ = a.Filesystem  // string
	_ = a.NetworkMode // string
	_ = a.Read        // []string
	_ = a.Write       // []string
	_ = a.Exec        // []string
	_ = a.Toolchains  // []string
	_ = a.Domains     // []string
	_ = a.SourceFile  // string
	_ = a.Network     // *config.NetworkConfig
}

// TestContractENT2_ProfileConfig_Fields verifies ProfileConfig fields.
func TestContractENT2_ProfileConfig_Fields(t *testing.T) {
	p := &config.ProfileConfig{}
	_ = p.Name           // string
	_ = p.Workdir        // string
	_ = p.Read           // []string
	_ = p.Write          // []string
	_ = p.Exec           // []string
	_ = p.AllowedDomains // []string
	_ = p.MitmDomains    // []string
	_ = p.Toolchains     // []string
	_ = p.SourceFile     // string
	_ = p.Network        // *config.NetworkConfig
}

// TestContractENT3_ResolvedPolicy_Fields verifies ResolvedPolicy (ENT3).
func TestContractENT3_ResolvedPolicy_Fields(t *testing.T) {
	rp := &policy.ResolvedPolicy{}
	_ = rp.AgentName      // string
	_ = rp.ProfileName    // string
	_ = rp.Mode           // string
	_ = rp.FilesystemMode // string
	_ = rp.NetworkMode    // string
	_ = rp.Read           // []string
	_ = rp.Write          // []string
	_ = rp.Exec           // []string
	_ = rp.Workdir        // string
	_ = rp.AllowedDomains // []string
	_ = rp.ProxyACLs      // []config.DomainConfig
	_ = rp.MitmDomains    // []string
	_ = rp.Toolchains     // []string
	_ = rp.CLIExtraPaths   // []string
	_ = rp.CLIExtraDomains // []string
	_ = rp.Warnings       // []string
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// minimalAgent returns an AgentConfig with the minimum valid fields per ENT1.
func minimalAgent() *config.AgentConfig {
	return &config.AgentConfig{
		Name:        "test-agent",
		Filesystem:  "read-write",
		NetworkMode: "none",
	}
}

// minimalProfile returns a ProfileConfig with the minimum valid fields per ENT2.
func minimalProfile() *config.ProfileConfig {
	return &config.ProfileConfig{
		Name:    "test/default",
		Workdir: ".",
	}
}

// api1Fixture creates a minimal registry with a "coding" agent.
// The registry looks for global agents in <globalDir>/agents/<name>.hcl.
func api1Fixture(t *testing.T) (*config.Registry, error) {
	t.Helper()
	gitRoot := t.TempDir()
	globalDir := t.TempDir()

	// NewRegistry.indexGlobal → indexAgentDir(globalDir) → reads globalDir/agents/<name>.hcl
	agentsSubdir := filepath.Join(globalDir, "agents")
	if err := os.MkdirAll(agentsSubdir, 0o755); err != nil {
		return nil, err
	}
	hcl := `agent "coding" {
  filesystem   = "read-write"
  network_mode = "full"
  toolchains   = ["go"]
}
`
	if err := os.WriteFile(filepath.Join(agentsSubdir, "coding.hcl"), []byte(hcl), 0o644); err != nil {
		return nil, err
	}
	return config.NewRegistry(gitRoot, globalDir)
}
