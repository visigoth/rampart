package policy

import (
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/config"
)

// --- helpers ---

func agent(name, filesystem, networkMode string) *config.AgentConfig {
	return &config.AgentConfig{
		Name:        name,
		Filesystem:  filesystem,
		NetworkMode: networkMode,
	}
}

func agentWith(name, filesystem, networkMode string, modify func(*config.AgentConfig)) *config.AgentConfig {
	a := agent(name, filesystem, networkMode)
	modify(a)
	return a
}

func profile(name, workdir string) *config.ProfileConfig {
	return &config.ProfileConfig{
		Name:    name,
		Workdir: workdir,
	}
}

func profileWith(name, workdir string, modify func(*config.ProfileConfig)) *config.ProfileConfig {
	p := profile(name, workdir)
	modify(p)
	return p
}

func defaultOpts() MergeOptions { return MergeOptions{} }

// --- Filesystem mode intersection ---

func TestMerge_FilesystemMode_BothReadWrite(t *testing.T) {
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Write = []string{"/tmp"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Write = []string{"/tmp", "/var"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.FilesystemMode != "read-write" {
		t.Errorf("FilesystemMode: got %q, want %q", rp.FilesystemMode, "read-write")
	}
}

func TestMerge_FilesystemMode_AgentMoreRestrictive(t *testing.T) {
	// Agent read-write + profile read-only → most restrictive wins (read-only).
	a := agent("planning", "read-only", "none")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Write = []string{"/tmp"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.FilesystemMode != "read-only" {
		t.Errorf("FilesystemMode: got %q, want %q", rp.FilesystemMode, "read-only")
	}
}

func TestMerge_FilesystemMode_ProfileMoreRestrictive(t *testing.T) {
	// Agent read-write + profile only has read paths → profile limits to read-only.
	a := agent("coding", "read-write", "none")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/etc"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.FilesystemMode != "read-only" {
		t.Errorf("FilesystemMode: got %q, want %q", rp.FilesystemMode, "read-only")
	}
}

func TestMerge_FilesystemMode_None(t *testing.T) {
	a := agent("minimal", "none", "none")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Write = []string{"/tmp"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.FilesystemMode != "none" {
		t.Errorf("FilesystemMode: got %q, want %q", rp.FilesystemMode, "none")
	}
}

// --- Concrete path intersection ---

func TestMerge_ConcreteRead_AgentSpecificWithinProfileBroad(t *testing.T) {
	// Agent specific, profile broader → include agent's specific path.
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Read = []string{"/etc/ssh"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/etc"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Read) != 1 || rp.Read[0] != "/etc/ssh" {
		t.Errorf("Read: got %v, want [/etc/ssh]", rp.Read)
	}
}

func TestMerge_ConcreteRead_ProfileMoreSpecificThanAgent(t *testing.T) {
	// Agent broader (/home/user), profile more specific (/home/user/code) → include profile's path.
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Read = []string{"/home/user"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/home/user/code"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Read) != 1 || rp.Read[0] != "/home/user/code" {
		t.Errorf("Read: got %v, want [/home/user/code]", rp.Read)
	}
}

func TestMerge_ConcreteRead_NoOverlap(t *testing.T) {
	// Agent requests /etc/ssh, profile grants /home/user → no overlap.
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Read = []string{"/etc/ssh"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/home/user"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Read) != 0 {
		t.Errorf("Read: got %v, want []", rp.Read)
	}
}

func TestMerge_ConcreteRead_AbstractAgentUsesProfilePaths(t *testing.T) {
	// Agent has abstract mode (no concrete paths) → use profile's paths.
	a := agent("coding", "read-only", "none") // no concrete Read
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/etc", "/usr/share"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Read) != 2 {
		t.Errorf("Read: got %v, want 2 paths from profile", rp.Read)
	}
}

// --- Capability hierarchy (FR1.12) ---

func TestMerge_CapabilityHierarchy_WriteImpliesRead(t *testing.T) {
	// Profile grants write → agent can request read for the same path (write implies read).
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Read = []string{"/build"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Write = []string{"/build"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Read) != 1 || rp.Read[0] != "/build" {
		t.Errorf("Read: got %v (write should imply read)", rp.Read)
	}
}

func TestMerge_CapabilityHierarchy_ExecImpliesRead(t *testing.T) {
	// Profile grants exec → agent can request read for the same path (exec implies read).
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Read = []string{"/usr/bin/git"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Exec = []string{"/usr/bin/git"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Read) != 1 || rp.Read[0] != "/usr/bin/git" {
		t.Errorf("Read: got %v (exec should imply read)", rp.Read)
	}
}

func TestMerge_CapabilityHierarchy_ExecDoesNotImplyWrite(t *testing.T) {
	// Profile grants exec but NOT write → agent cannot get write.
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Write = []string{"/usr/bin/git"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Exec = []string{"/usr/bin/git"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Write) != 0 {
		t.Errorf("Write: got %v (exec should NOT imply write)", rp.Write)
	}
}

// --- Network (TR16: profile is sole source) ---

func TestMerge_Network_ProfileIsSource(t *testing.T) {
	// Agent requests "full" network; profile has specific domains.
	// Result uses profile's domains — agent network block is NOT runtime rules.
	a := agentWith("coding", "none", "full", func(a *config.AgentConfig) {
		a.Domains = []string{"*"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.AllowedDomains = []string{"api.anthropic.com", "*.npmjs.org"}
		p.Network = &config.NetworkConfig{
			Domains: []config.DomainConfig{
				{Pattern: "api.anthropic.com"},
			},
		}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.AllowedDomains) != 2 {
		t.Errorf("AllowedDomains: got %v", rp.AllowedDomains)
	}
	if len(rp.ProxyACLs) != 1 || rp.ProxyACLs[0].Pattern != "api.anthropic.com" {
		t.Errorf("ProxyACLs: got %v", rp.ProxyACLs)
	}
}

func TestMerge_Network_AgentNoneBlocksNetwork(t *testing.T) {
	// Agent requests no network → NetworkMode=none even if profile grants.
	a := agent("minimal", "none", "none")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.AllowedDomains = []string{"api.anthropic.com"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "none" {
		t.Errorf("NetworkMode: got %q, want %q", rp.NetworkMode, "none")
	}
}

func TestMerge_Network_EmptyProfile_AgentGetsNothing(t *testing.T) {
	// Agent wants full network, profile has no network config → agent gets nothing.
	a := agent("coding", "none", "full")
	p := profile("default", ".")
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "none" {
		t.Errorf("NetworkMode: got %q, want none", rp.NetworkMode)
	}
	if len(rp.AllowedDomains) != 0 {
		t.Errorf("AllowedDomains: got %v, want empty", rp.AllowedDomains)
	}
}

// --- CLI overrides ---

func TestMerge_CLIExtraPaths_BypassIntersection(t *testing.T) {
	// Agent doesn't request /secret, profile doesn't grant it, but CLI --allow-path adds it.
	a := agent("coding", "read-only", "none")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/home/user"}
	})
	opts := MergeOptions{ExtraPaths: []string{"/secret"}}
	rp, err := MergePolicy(a, p, opts)
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.CLIExtraPaths) != 1 || rp.CLIExtraPaths[0] != "/secret" {
		t.Errorf("CLIExtraPaths: got %v", rp.CLIExtraPaths)
	}
}

func TestMerge_CLIExtraDomains_BypassIntersection(t *testing.T) {
	a := agent("coding", "none", "filtered")
	p := profile("default", ".")
	opts := MergeOptions{ExtraDomains: []string{"custom.internal"}}
	rp, err := MergePolicy(a, p, opts)
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.CLIExtraDomains) != 1 || rp.CLIExtraDomains[0] != "custom.internal" {
		t.Errorf("CLIExtraDomains: got %v", rp.CLIExtraDomains)
	}
}

// --- Compile-time validation ---

func TestMerge_Validation_AgentRequestNotGranted_Warning(t *testing.T) {
	// Agent requests /etc/passwd write, profile doesn't grant it → warning.
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Write = []string{"/etc/passwd"}
	})
	p := profile("default", ".")
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Warnings) == 0 {
		t.Error("expected warning for unsatisfied agent request")
	}
}

func TestMerge_Validation_AgentRequestNotGranted_StrictError(t *testing.T) {
	// Same scenario with --strict → error instead of warning.
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Write = []string{"/etc/passwd"}
	})
	p := profile("default", ".")
	opts := MergeOptions{Strict: true}
	_, err := MergePolicy(a, p, opts)
	if err == nil {
		t.Fatal("expected error with --strict")
	}
	if !strings.Contains(err.Error(), "strict") {
		t.Errorf("error should mention strict: %v", err)
	}
}

func TestMerge_Validation_AllSatisfied_NoWarnings(t *testing.T) {
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Read = []string{"/etc/ssh"}
		a.Write = []string{"/tmp"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/etc"}
		p.Write = []string{"/tmp"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", rp.Warnings)
	}
}

// --- Edge cases ---

func TestMerge_EmptyAgent(t *testing.T) {
	a := agent("empty", "none", "none")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Read = []string{"/etc"}
		p.AllowedDomains = []string{"api.anthropic.com"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.FilesystemMode != "none" {
		t.Errorf("FilesystemMode: got %q, want none", rp.FilesystemMode)
	}
	if rp.NetworkMode != "none" {
		t.Errorf("NetworkMode: got %q, want none", rp.NetworkMode)
	}
	if len(rp.Read) != 0 {
		t.Errorf("Read: expected empty, got %v", rp.Read)
	}
}

func TestMerge_EmptyProfile(t *testing.T) {
	a := agentWith("coding", "read-write", "filtered", func(a *config.AgentConfig) {
		a.Read = []string{"/home/user"}
		a.Domains = []string{"api.anthropic.com"}
	})
	p := profile("empty", ".")
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.FilesystemMode != "none" {
		t.Errorf("FilesystemMode: got %q, want none (profile grants nothing)", rp.FilesystemMode)
	}
	if len(rp.Read) != 0 {
		t.Errorf("Read: expected empty (profile grants nothing), got %v", rp.Read)
	}
}

func TestMerge_DefaultMode_IsEnforcing(t *testing.T) {
	rp, err := MergePolicy(agent("a", "none", "none"), profile("p", "."), defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	if rp.Mode != "enforcing" {
		t.Errorf("Mode: got %q, want %q", rp.Mode, "enforcing")
	}
}

func TestMerge_ExplicitMode_Preserved(t *testing.T) {
	rp, err := MergePolicy(agent("a", "none", "none"), profile("p", "."), MergeOptions{Mode: "permissive"})
	if err != nil {
		t.Fatal(err)
	}
	if rp.Mode != "permissive" {
		t.Errorf("Mode: got %q, want %q", rp.Mode, "permissive")
	}
}

func TestMerge_WorkdirFromProfile(t *testing.T) {
	p := profile("dev", "/home/user/project")
	rp, err := MergePolicy(agent("a", "none", "none"), p, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	if rp.Workdir != "/home/user/project" {
		t.Errorf("Workdir: got %q", rp.Workdir)
	}
}

// --- no_tls_mitm ---

func TestMerge_NoTLSMITM_ProfileTrue_PathRulesWarn(t *testing.T) {
	a := agent("admin", "read-write", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.NoTLSMITM = true
		p.Network = &config.NetworkConfig{
			Domains: []config.DomainConfig{
				{
					Pattern: "*",
					Allow: []config.RuleConfig{
						{Method: "GET", Paths: []string{"/**"}},
					},
				},
			},
		}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if !rp.NoTLSMITM {
		t.Error("NoTLSMITM: got false, want true (from profile)")
	}
	found := false
	for _, w := range rp.Warnings {
		if strings.Contains(w, "no_tls_mitm") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about no_tls_mitm; got: %v", rp.Warnings)
	}
}

func TestMerge_NoTLSMITM_ClearsMitmDomains(t *testing.T) {
	a := agent("admin", "read-write", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.NoTLSMITM = true
		p.MitmDomains = []string{"api.anthropic.com"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.MitmDomains) != 0 {
		t.Errorf("MitmDomains should be cleared when NoTLSMITM=true; got %v", rp.MitmDomains)
	}
	found := false
	for _, w := range rp.Warnings {
		if strings.Contains(w, "no_tls_mitm") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning when MitmDomains is cleared; got: %v", rp.Warnings)
	}
}

func TestMerge_NoTLSMITM_NoWarningWithoutPathRulesOrMitmDomains(t *testing.T) {
	// With no_tls_mitm=true but neither path rules nor mitm_domains, there's
	// nothing being silently suppressed — no warning should fire.
	a := agent("admin", "read-write", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.NoTLSMITM = true
		p.AllowedDomains = []string{"api.anthropic.com"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	for _, w := range rp.Warnings {
		if strings.Contains(w, "no_tls_mitm") {
			t.Errorf("no_tls_mitm warning should NOT fire here; got: %v", rp.Warnings)
		}
	}
}

func TestMerge_NoTLSMITM_CLIOverridesProfile(t *testing.T) {
	a := agent("admin", "read-write", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.NoTLSMITM = false
	})
	tru := true
	rp, err := MergePolicy(a, p, MergeOptions{NoTLSMITM: &tru})
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if !rp.NoTLSMITM {
		t.Error("CLI override should set NoTLSMITM=true even when profile is false")
	}
}

func TestMerge_NoTLSMITM_NilCLILeavesProfileAlone(t *testing.T) {
	a := agent("admin", "read-write", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.NoTLSMITM = true
	})
	// MergeOptions.NoTLSMITM nil — flag wasn't passed.
	rp, err := MergePolicy(a, p, MergeOptions{})
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if !rp.NoTLSMITM {
		t.Error("nil CLI override should leave profile NoTLSMITM=true intact")
	}
}

// --- network mode inference (incl. wildcard → full) ---

func TestMerge_NetworkMode_WildcardAllowedDomain_IsFull(t *testing.T) {
	// `allowed_domains = ["*"]` opts the profile into "full" mode — the
	// proxy can be skipped entirely. : this is the explicit
	// "I want unrestricted network" knob.
	a := agent("admin", "none", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.AllowedDomains = []string{"*"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "full" {
		t.Errorf("NetworkMode = %q, want %q", rp.NetworkMode, "full")
	}
}

func TestMerge_NetworkMode_EmptyWildcardDomainBlock_IsFull(t *testing.T) {
	// `network { domain "*" {} }` (no methods/rules) is also the explicit
	// full-mode opt-in form.
	a := agent("admin", "none", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.Network = &config.NetworkConfig{
			Domains: []config.DomainConfig{
				{Pattern: "*"},
			},
		}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "full" {
		t.Errorf("NetworkMode = %q, want %q", rp.NetworkMode, "full")
	}
}

func TestMerge_NetworkMode_WildcardWithRules_StaysFiltered(t *testing.T) {
	// network/any-style: wildcard with methods AND paths is a filtering
	// declaration, not a full-mode opt-in. The proxy should stay in path.
	a := agent("admin", "none", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.Network = &config.NetworkConfig{
			Domains: []config.DomainConfig{
				{
					Pattern: "*",
					Allow: []config.RuleConfig{
						{Method: "GET", Paths: []string{"/**"}},
					},
				},
			},
		}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "filtered" {
		t.Errorf("NetworkMode = %q, want %q (rules present)", rp.NetworkMode, "filtered")
	}
}

func TestMerge_NetworkMode_WildcardPlusSpecific_StaysFiltered(t *testing.T) {
	// Mixing "*" with a specific allowlist entry is treated as filtering —
	// the user is hedging, so don't silently elevate to full mode.
	a := agent("admin", "none", "full")
	p := profileWith("permissive", ".", func(p *config.ProfileConfig) {
		p.AllowedDomains = []string{"*", "example.com"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "filtered" {
		t.Errorf("NetworkMode = %q, want %q (specific entry present)", rp.NetworkMode, "filtered")
	}
}

func TestMerge_NetworkMode_NoNetwork_IsNone(t *testing.T) {
	a := agent("admin", "none", "full")
	p := profile("permissive", ".")
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "none" {
		t.Errorf("NetworkMode = %q, want %q", rp.NetworkMode, "none")
	}
}

// --- pathCovers helper tests ---

func TestPathCovers(t *testing.T) {
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/etc", "/etc/ssh", true},
		{"/etc", "/etc", true},
		{"/etc/ssh", "/etc", false},
		{"/home/user", "/home/user/code/", true},
		{"/home/user/code", "/home/user", false},
		{"/usr/bin/git", "/usr/bin/gitk", false},
		{"/usr/bin", "/usr/bin/git", true},
	}
	for _, c := range cases {
		got := pathCovers(c.parent, c.child)
		if got != c.want {
			t.Errorf("pathCovers(%q, %q) = %v, want %v", c.parent, c.child, got, c.want)
		}
	}
}
