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

// TestMerge_Network_ProfileStarOptsIntoFull pins the convention that
// allowed_domains = ["*"] is the profile-side opt-in to "full" network.
// Without this signal the merge clamps the agent's "full" request to at
// most "filtered" because profile mode is otherwise inferred only as
// "filtered" or "none".
func TestMerge_Network_ProfileStarOptsIntoFull(t *testing.T) {
	a := agent("coding", "none", "full")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.AllowedDomains = []string{"*"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "full" {
		t.Errorf("NetworkMode: got %q, want %q", rp.NetworkMode, "full")
	}
}

// TestMerge_Network_ProfileStarMixedWithSpecific keeps the "full" verdict
// when "*" is present alongside specific domains. The presence of "*" is
// the controlling signal — specific entries become moot when the proxy is
// out of the path.
func TestMerge_Network_ProfileStarMixedWithSpecific(t *testing.T) {
	a := agent("coding", "none", "full")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.AllowedDomains = []string{"api.anthropic.com", "*"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "full" {
		t.Errorf("NetworkMode: got %q, want %q", rp.NetworkMode, "full")
	}
}

// TestMerge_Network_ProfileStarClampedByAgent ensures the agent's mode
// still caps the merged result. A profile that opts into "full" cannot
// elevate an agent that explicitly requested "filtered".
func TestMerge_Network_ProfileStarClampedByAgent(t *testing.T) {
	a := agent("scoped", "none", "filtered")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.AllowedDomains = []string{"*"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "filtered" {
		t.Errorf("NetworkMode: got %q, want %q (clamped by agent)", rp.NetworkMode, "filtered")
	}
}

// TestMerge_Network_NetworkBlockStarStaysFiltered documents the
// deliberate split: a network { domain "*" {} } block is NOT the full
// opt-in. That form is for structured ACLs matching all domains (e.g.
// "any domain, GET only") — the proxy stays in the path.
func TestMerge_Network_NetworkBlockStarStaysFiltered(t *testing.T) {
	a := agent("coding", "none", "full")
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Network = &config.NetworkConfig{
			Domains: []config.DomainConfig{{Pattern: "*"}},
		}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if rp.NetworkMode != "filtered" {
		t.Errorf("NetworkMode: got %q, want %q (network block does not opt into full)",
			rp.NetworkMode, "filtered")
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

// --- Toolchains ---

func TestMerge_Toolchains_Intersection(t *testing.T) {
	a := agentWith("coding", "none", "none", func(a *config.AgentConfig) {
		a.Toolchains = []string{"node", "python", "go"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Toolchains = []string{"node", "python"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Toolchains) != 2 {
		t.Errorf("Toolchains: got %v, want [node python]", rp.Toolchains)
	}
	for _, tc := range rp.Toolchains {
		if tc != "node" && tc != "python" {
			t.Errorf("unexpected toolchain: %q", tc)
		}
	}
}

func TestMerge_Toolchains_NoOverlap(t *testing.T) {
	a := agentWith("coding", "none", "none", func(a *config.AgentConfig) {
		a.Toolchains = []string{"go"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Toolchains = []string{"node"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	if len(rp.Toolchains) != 0 {
		t.Errorf("Toolchains: got %v, want []", rp.Toolchains)
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
