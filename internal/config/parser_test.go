package config

import (
	"strings"
	"testing"
)

// --- Agent parsing tests ---

func TestParseAgentFile_HappyPath(t *testing.T) {
	src := []byte(`
agent "coding" {
  description = "A coding agent"
  filesystem  = "read-write"
  read        = ["/home/user", "/etc/ssh"]
  write       = ["/tmp"]
  exec        = ["/usr/bin/git"]
  network_mode = "filtered"
  domains     = ["api.anthropic.com"]
  toolchains  = ["node", "python"]

  network {
    domain "api.anthropic.com" {
      allow "POST" {
        paths = ["/v1/messages"]
      }
    }
    domain "*.npmjs.org" {}
  }
}
`)
	agents, err := ParseAgentFile("test.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	a := agents[0]
	if a.Name != "coding" {
		t.Errorf("name: got %q, want %q", a.Name, "coding")
	}
	if a.Description != "A coding agent" {
		t.Errorf("description: got %q", a.Description)
	}
	if a.Filesystem != "read-write" {
		t.Errorf("filesystem: got %q", a.Filesystem)
	}
	if len(a.Read) != 2 {
		t.Errorf("read: got %d paths", len(a.Read))
	}
	if a.NetworkMode != "filtered" {
		t.Errorf("network_mode: got %q", a.NetworkMode)
	}
	if len(a.Toolchains) != 2 {
		t.Errorf("toolchains: got %v", a.Toolchains)
	}
	if a.Network == nil {
		t.Fatal("expected network block")
	}
	if len(a.Network.Domains) != 2 {
		t.Errorf("network domains: got %d", len(a.Network.Domains))
	}
	if a.SourceFile != "test.hcl" {
		t.Errorf("SourceFile: got %q", a.SourceFile)
	}
}

func TestParseAgentFile_MultiAgent(t *testing.T) {
	src := []byte(`
agent "coding" {
  filesystem   = "read-write"
  network_mode = "filtered"
}
agent "planning" {
  filesystem   = "read-only"
  network_mode = "none"
}
`)
	agents, err := ParseAgentFile("agents.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
	names := []string{agents[0].Name, agents[1].Name}
	if names[0] != "coding" || names[1] != "planning" {
		t.Errorf("names: got %v", names)
	}
}

func TestParseAgentFile_EmptyAgentBlock(t *testing.T) {
	// Empty agent block: no capabilities declared — still valid per acceptance criteria.
	src := []byte(`
agent "minimal" {
  filesystem   = "none"
  network_mode = "none"
}
`)
	agents, err := ParseAgentFile("test.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
}

func TestParseAgentFile_MissingFilesystem(t *testing.T) {
	src := []byte(`
agent "bad" {
  network_mode = "none"
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for missing required field 'filesystem'")
	}
	if !strings.Contains(err.Error(), "filesystem") {
		t.Errorf("error should mention 'filesystem': %v", err)
	}
}

func TestParseAgentFile_MissingNetworkMode(t *testing.T) {
	src := []byte(`
agent "bad" {
  filesystem = "none"
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for missing required field 'network_mode'")
	}
	if !strings.Contains(err.Error(), "network_mode") {
		t.Errorf("error should mention 'network_mode': %v", err)
	}
}

func TestParseAgentFile_InvalidFilesystemMode(t *testing.T) {
	src := []byte(`
agent "bad" {
  filesystem   = "writable"
  network_mode = "none"
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for invalid filesystem mode")
	}
}

func TestParseAgentFile_InvalidNetworkMode(t *testing.T) {
	src := []byte(`
agent "bad" {
  filesystem   = "none"
  network_mode = "open"
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for invalid network mode")
	}
}

func TestParseAgentFile_UnparsableHCL(t *testing.T) {
	src := []byte(`agent "bad" { filesystem = `)
	_, err := ParseAgentFile("broken.hcl", src)
	if err == nil {
		t.Fatal("expected parse error for malformed HCL")
	}
	// Error should include file and line info.
	if !strings.Contains(err.Error(), "broken.hcl") {
		t.Errorf("error should include filename: %v", err)
	}
}

func TestParseAgentFile_UnknownAttributesCapturedInRemain(t *testing.T) {
	// Unknown attributes are captured in Remain for forward compatibility — not an error.
	src := []byte(`
agent "forward-compat" {
  filesystem   = "none"
  network_mode = "none"
  future_field = "ignored"
}
`)
	agents, err := ParseAgentFile("myfile.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error (unknown attrs should be tolerated): %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent")
	}
}

// --- Profile parsing tests ---

func TestParseProfileFile_HappyPath(t *testing.T) {
	src := []byte(`
profile "default" {
  workdir = "."
  read    = ["/etc", "/usr"]
  write   = ["/tmp"]
  exec    = ["/usr/bin"]
  allowed_domains = ["api.anthropic.com"]
  mitm_domains    = ["api.anthropic.com"]
  toolchains      = ["node"]

  network {
    domain "api.anthropic.com" {
      allow "POST" {
        paths = ["/v1/**"]
      }
    }
    domain "*.npmjs.org" {}
  }
}
`)
	profiles, err := ParseProfileFile("profile.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	p := profiles[0]
	if p.Name != "default" {
		t.Errorf("name: got %q", p.Name)
	}
	if p.Workdir != "." {
		t.Errorf("workdir: got %q", p.Workdir)
	}
	if len(p.Read) != 2 {
		t.Errorf("read: got %v", p.Read)
	}
	if p.Network == nil || len(p.Network.Domains) != 2 {
		t.Error("expected 2 network domains")
	}
}

func TestParseProfileFile_NoTLSMITM(t *testing.T) {
	// Round-trips when the attribute is set.
	src := []byte(`
profile "permissive" {
  workdir     = "."
  no_tls_mitm = true
  network {
    domain "*" {
      allow "GET" { paths = ["/**"] }
    }
  }
}
`)
	profiles, err := ParseProfileFile("p.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !profiles[0].NoTLSMITM {
		t.Errorf("NoTLSMITM: got false, want true")
	}

	// Defaults to false when omitted.
	src2 := []byte(`
profile "default" {
  workdir = "."
}
`)
	profiles2, err := ParseProfileFile("p.hcl", src2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profiles2[0].NoTLSMITM {
		t.Errorf("NoTLSMITM should default to false when omitted")
	}
}

func TestParseProfileFile_MissingWorkdir(t *testing.T) {
	src := []byte(`
profile "bad" {
}
`)
	_, err := ParseProfileFile("p.hcl", src)
	if err == nil {
		t.Fatal("expected error for missing workdir")
	}
	if !strings.Contains(err.Error(), "workdir") {
		t.Errorf("error should mention workdir: %v", err)
	}
}

func TestParseProfileFile_EmptyDomainBlock(t *testing.T) {
	// Empty domain block is valid (allow-all-on-domain semantics).
	src := []byte(`
profile "dev" {
  workdir = "."
  network {
    domain "*.npmjs.org" {}
  }
}
`)
	profiles, err := ParseProfileFile("p.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profiles[0].Network.Domains[0].Pattern != "*.npmjs.org" {
		t.Errorf("unexpected domain pattern: %v", profiles[0].Network.Domains[0].Pattern)
	}
	if len(profiles[0].Network.Domains[0].Allow) != 0 {
		t.Error("expected no allow rules for empty domain block")
	}
}

func TestParseProfileFile_DomainWithOnlyDenyRules(t *testing.T) {
	src := []byte(`
profile "restricted" {
  workdir = "."
  network {
    domain "api.anthropic.com" {
      deny "DELETE" {
        paths = ["/**"]
      }
    }
  }
}
`)
	profiles, err := ParseProfileFile("p.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := profiles[0].Network.Domains[0]
	if len(d.Allow) != 0 || len(d.Deny) != 1 {
		t.Errorf("expected 0 allow, 1 deny; got %d allow, %d deny", len(d.Allow), len(d.Deny))
	}
}

// --- Defaults parsing tests ---

func TestParseDefaultsFile_HappyPath(t *testing.T) {
	src := []byte(`
defaults {
  default_agent   = "coding"
  default_profile = "myproject/default"
}
`)
	d, err := ParseDefaultsFile("defaults.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d == nil {
		t.Fatal("expected non-nil DefaultsConfig")
	}
	if d.DefaultAgent != "coding" {
		t.Errorf("default_agent: got %q", d.DefaultAgent)
	}
	if d.DefaultProfile != "myproject/default" {
		t.Errorf("default_profile: got %q", d.DefaultProfile)
	}
}

func TestParseDefaultsFile_NoBlock(t *testing.T) {
	src := []byte(``)
	d, err := ParseDefaultsFile("defaults.hcl", src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != nil {
		t.Fatal("expected nil for empty file")
	}
}

// --- Glob pattern validation tests ---

func TestValidateGlobPattern_Valid(t *testing.T) {
	cases := []struct {
		pat string
		sep byte
	}{
		{"api.anthropic.com", '.'},
		{"*.npmjs.org", '.'},
		{"**.example.com", '.'},
		{"api.*.com", '.'},
		{"/v1/messages", '/'},
		{"/v1/*", '/'},
		{"/v1/**", '/'},
		{"/v1/*/cache", '/'},
		{"*", '.'},
		{"**", '/'},
		{"/etc/ssh", '/'},
	}
	for _, c := range cases {
		if err := ValidateGlobPattern(c.pat, c.sep); err != nil {
			t.Errorf("ValidateGlobPattern(%q, %q): unexpected error: %v", c.pat, string(c.sep), err)
		}
	}
}

func TestValidateGlobPattern_EmptyPattern(t *testing.T) {
	if err := ValidateGlobPattern("", '/'); err == nil {
		t.Error("expected error for empty pattern")
	}
}

func TestValidateGlobPattern_MixedLiteralWildcard(t *testing.T) {
	cases := []string{"foo*", "*bar", "foo*bar", "api*com"}
	for _, c := range cases {
		if err := ValidateGlobPattern(c, '.'); err == nil {
			t.Errorf("expected error for mixed segment %q", c)
		}
	}
}

func TestValidateGlobPattern_ConsecutiveSeparators(t *testing.T) {
	// Domain with consecutive dots.
	if err := ValidateGlobPattern("api..anthropic.com", '.'); err == nil {
		t.Error("expected error for consecutive dots in domain")
	}
	// Path with double slash (internal).
	if err := ValidateGlobPattern("/v1//messages", '/'); err == nil {
		t.Error("expected error for consecutive slashes in path")
	}
}

func TestValidateGlobPattern_UnsupportedWildcard(t *testing.T) {
	cases := []string{"?.example.com", "{a,b}.com", "foo[bar]"}
	for _, c := range cases {
		if err := ValidateGlobPattern(c, '.'); err == nil {
			t.Errorf("expected error for unsupported wildcard in %q", c)
		}
	}
}

func TestParseAgentFile_GlobValidationInRead(t *testing.T) {
	src := []byte(`
agent "bad" {
  filesystem   = "read-write"
  network_mode = "none"
  read         = ["foo*"]
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for mixed literal+wildcard segment in read path")
	}
}

func TestParseAgentFile_GlobValidationInDomains(t *testing.T) {
	src := []byte(`
agent "bad" {
  filesystem   = "read-write"
  network_mode = "filtered"
  domains      = ["api?anthropic.com"]
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for unsupported wildcard in domain")
	}
}

func TestParseAgentFile_GlobValidationInNetworkDomain(t *testing.T) {
	src := []byte(`
agent "bad" {
  filesystem   = "read-write"
  network_mode = "filtered"
  network {
    domain "api?.com" {}
  }
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for unsupported wildcard in network domain pattern")
	}
}

func TestParseAgentFile_GlobValidationInNetworkPathRules(t *testing.T) {
	src := []byte(`
agent "bad" {
  filesystem   = "read-write"
  network_mode = "filtered"
  network {
    domain "api.anthropic.com" {
      allow "POST" {
        paths = ["foo*bar"]
      }
    }
  }
}
`)
	_, err := ParseAgentFile("test.hcl", src)
	if err == nil {
		t.Fatal("expected error for mixed segment in path rule")
	}
}
