// Integration tests for the full FT1→FT2 pipeline: HCL parsing → MergePolicy.
// Each case parses real HCL text via the config package, then calls MergePolicy,
// then asserts the ResolvedPolicy structure. This exercises the full EP1 pipeline.
package policy

import (
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/config"
)

// parseAgent / parseProfile parse raw HCL for use in integration tests.
func parseAgent(t *testing.T, src string) *config.AgentConfig {
	t.Helper()
	agents, err := config.ParseAgentFile("test-agent.hcl", []byte(src))
	if err != nil {
		t.Fatalf("ParseAgentFile: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	return agents[0]
}

func parseProfile(t *testing.T, src string) *config.ProfileConfig {
	t.Helper()
	profiles, err := config.ParseProfileFile("test-profile.hcl", []byte(src))
	if err != nil {
		t.Fatalf("ParseProfileFile: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	return profiles[0]
}

// integrationCase is one row in the table-driven test below.
type integrationCase struct {
	name        string
	agentHCL    string
	profileHCL  string
	opts        MergeOptions
	wantFS      string
	wantNet     string
	wantRead    []string // nil means "don't check"; empty means "must be empty"
	wantWrite   []string
	wantExec    []string
	wantWarn    int // minimum number of warnings expected
	wantErr     bool
}

func TestMergePolicy_Integration(t *testing.T) {
	cases := []integrationCase{
		{
			name: "01_coding_agent_read_write_full_overlap",
			agentHCL: `
agent "coding" {
  filesystem   = "read-write"
  network_mode = "filtered"
  read  = ["/home/user/code"]
  write = ["/home/user/code", "/tmp"]
}`,
			profileHCL: `
profile "default" {
  workdir = "/home/user/code"
  read    = ["/home/user/code", "/etc/ssl"]
  write   = ["/home/user/code", "/tmp"]
  allowed_domains = ["api.anthropic.com"]
}`,
			wantFS:  "read-write",
			wantNet: "filtered",
			wantRead: []string{"/home/user/code"},
			wantWrite: []string{"/home/user/code", "/tmp"},
		},
		{
			name: "02_profile_restricts_filesystem_mode",
			agentHCL: `
agent "coder" {
  filesystem   = "read-write"
  network_mode = "none"
  write = ["/home/user/project"]
}`,
			profileHCL: `
profile "readonly-sandbox" {
  workdir = "/home/user/project"
  read    = ["/home/user/project"]
}`,
			// profile inferred mode is "read-only", agent wants "read-write" → min = "read-only"
			wantFS:  "read-only",
			wantNet: "none",
			// agent requests write but profile only grants read → empty write
			wantWrite: []string{},
		},
		{
			name: "03_capability_hierarchy_write_grants_read",
			agentHCL: `
agent "builder" {
  filesystem   = "read-write"
  network_mode = "none"
  read  = ["/build/output"]
  write = ["/build/output"]
}`,
			profileHCL: `
profile "ci" {
  workdir = "/build"
  write   = ["/build/output"]
}`,
			// profile.Write covers /build/output → read is approved via hierarchy
			wantFS:   "read-write",
			wantRead: []string{"/build/output"},
			wantWrite: []string{"/build/output"},
		},
		{
			name: "04_capability_hierarchy_exec_grants_read_not_write",
			agentHCL: `
agent "runner" {
  filesystem   = "read-write"
  network_mode = "none"
  read  = ["/usr/bin/node"]
  write = ["/usr/bin/node"]
  exec  = ["/usr/bin/node"]
}`,
			profileHCL: `
profile "nodejs" {
  workdir = "/project"
  exec    = ["/usr/bin/node"]
}`,
			// exec implies read but NOT write
			wantRead:  []string{"/usr/bin/node"},
			wantWrite: []string{},
			wantExec:  []string{"/usr/bin/node"},
		},
		{
			name: "05_abstract_agent_inherits_profile_paths",
			agentHCL: `
agent "analyst" {
  filesystem   = "read-only"
  network_mode = "none"
}`,
			profileHCL: `
profile "analytics" {
  workdir = "/data"
  read    = ["/data/raw", "/data/processed"]
}`,
			// abstract agent (no concrete paths) → inherits all profile read paths
			wantFS:   "read-only",
			wantRead: []string{"/data/raw", "/data/processed"},
		},
		{
			name: "06_no_overlap_in_paths",
			agentHCL: `
agent "sre" {
  filesystem   = "read-write"
  network_mode = "none"
  read  = ["/etc/nginx"]
  write = ["/etc/nginx"]
}`,
			profileHCL: `
profile "app-sandbox" {
  workdir = "/app"
  read    = ["/app/config"]
  write   = ["/app/logs"]
}`,
			// No path overlap → nothing granted
			wantRead:  []string{},
			wantWrite: []string{},
		},
		{
			name: "07_network_profile_sole_authority",
			agentHCL: `
agent "browser" {
  filesystem   = "none"
  network_mode = "full"
  domains      = ["*.example.com", "api.github.com"]
}`,
			profileHCL: `
profile "restricted-net" {
  workdir = "/workspace"
  allowed_domains = ["api.github.com", "registry.npmjs.org"]
  network {
    domain "api.github.com" {}
  }
}`,
			wantFS:  "none",
			wantNet: "filtered",
		},
		{
			name: "08_agent_none_blocks_network",
			agentHCL: `
agent "isolated" {
  filesystem   = "none"
  network_mode = "none"
}`,
			profileHCL: `
profile "open-net" {
  workdir         = "/workspace"
  allowed_domains = ["api.anthropic.com", "github.com"]
}`,
			// agent mode=none overrides profile's filtered
			wantNet: "none",
		},
		{
			name: "10_cli_extra_paths_bypass_intersection",
			agentHCL: `
agent "debug" {
  filesystem   = "read-only"
  network_mode = "none"
}`,
			profileHCL: `
profile "sandbox" {
  workdir = "/sandbox"
  read    = ["/sandbox"]
}`,
			opts: MergeOptions{
				ExtraPaths:   []string{"/tmp/debug", "/proc/self"},
				ExtraDomains: []string{"internal.corp"},
			},
			// CLI extras appear in CLIExtraPaths/CLIExtraDomains regardless of grants
		},
		{
			name: "11_strict_mode_unsatisfied_request_errors",
			agentHCL: `
agent "eager" {
  filesystem   = "read-write"
  network_mode = "filtered"
  write = ["/etc/passwd"]
  domains = ["*.evil.com"]
}`,
			profileHCL: `
profile "strict-sandbox" {
  workdir = "/workspace"
  read    = ["/workspace"]
}`,
			opts:    MergeOptions{Strict: true},
			wantErr: true,
		},
		{
			name: "12_non_strict_unsatisfied_produces_warnings",
			agentHCL: `
agent "eager" {
  filesystem   = "read-write"
  network_mode = "none"
  write = ["/etc/passwd"]
}`,
			profileHCL: `
profile "sandbox" {
  workdir = "/workspace"
  read    = ["/workspace"]
}`,
			wantWarn: 1,
		},
		{
			name: "13_workdir_preserved_from_profile",
			agentHCL: `
agent "dev" {
  filesystem   = "read-only"
  network_mode = "none"
}`,
			profileHCL: `
profile "project" {
  workdir = "/home/user/my-project"
  read    = ["/home/user/my-project"]
}`,
		},
		{
			name: "14_agent_broader_path_gets_profile_specific",
			agentHCL: `
agent "explorer" {
  filesystem   = "read-write"
  network_mode = "none"
  read  = ["/home"]
  write = ["/home"]
}`,
			profileHCL: `
profile "single-user" {
  workdir = "/home/alice"
  read    = ["/home/alice/docs"]
  write   = ["/home/alice/workspace"]
}`,
			// agent path /home is broader → include the more-specific profile paths
			wantRead:  []string{"/home/alice/docs", "/home/alice/workspace"},
			wantWrite: []string{"/home/alice/workspace"},
		},
		{
			name: "15_permissive_mode_from_cli",
			agentHCL: `
agent "dev" {
  filesystem   = "none"
  network_mode = "none"
}`,
			profileHCL: `
profile "sandbox" {
  workdir = "/workspace"
}`,
			opts: MergeOptions{Mode: "permissive"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := parseAgent(t, tc.agentHCL)
			p := parseProfile(t, tc.profileHCL)

			rp, err := MergePolicy(a, p, tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("MergePolicy: %v", err)
			}

			if tc.wantFS != "" && rp.FilesystemMode != tc.wantFS {
				t.Errorf("FilesystemMode: got %q, want %q", rp.FilesystemMode, tc.wantFS)
			}
			if tc.wantNet != "" && rp.NetworkMode != tc.wantNet {
				t.Errorf("NetworkMode: got %q, want %q", rp.NetworkMode, tc.wantNet)
			}
			if tc.wantRead != nil {
				assertPathsEqual(t, "Read", rp.Read, tc.wantRead)
			}
			if tc.wantWrite != nil {
				assertPathsEqual(t, "Write", rp.Write, tc.wantWrite)
			}
			if tc.wantExec != nil {
				assertPathsEqual(t, "Exec", rp.Exec, tc.wantExec)
			}
			if tc.wantWarn > 0 && len(rp.Warnings) < tc.wantWarn {
				t.Errorf("Warnings: got %d, want at least %d: %v", len(rp.Warnings), tc.wantWarn, rp.Warnings)
			}
			if tc.name == "10_cli_extra_paths_bypass_intersection" {
				if len(rp.CLIExtraPaths) != 2 {
					t.Errorf("CLIExtraPaths: got %v, want 2 entries", rp.CLIExtraPaths)
				}
				if len(rp.CLIExtraDomains) != 1 || rp.CLIExtraDomains[0] != "internal.corp" {
					t.Errorf("CLIExtraDomains: got %v", rp.CLIExtraDomains)
				}
			}
			if tc.name == "13_workdir_preserved_from_profile" {
				if rp.Workdir != "/home/user/my-project" {
					t.Errorf("Workdir: got %q, want /home/user/my-project", rp.Workdir)
				}
			}
			if tc.name == "15_permissive_mode_from_cli" {
				if rp.Mode != "permissive" {
					t.Errorf("Mode: got %q, want permissive", rp.Mode)
				}
			}
		})
	}
}

// assertPathsEqual verifies two path slices contain the same elements (order-insensitive for
// multi-element results, but asserts length matches).
func assertPathsEqual(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s length: got %d (%v), want %d (%v)", field, len(got), got, len(want), want)
		return
	}
	wantSet := make(map[string]bool, len(want))
	for _, p := range want {
		wantSet[p] = true
	}
	for _, p := range got {
		if !wantSet[p] {
			t.Errorf("%s: unexpected path %q (got %v, want %v)", field, p, got, want)
		}
	}
}


// TestMergePolicy_CapabilityHierarchy_TableDriven verifies the three-level hierarchy
// (exec → read, write → read, exec ↛ write) with a single table-driven test.
// wantXLen of -1 means "don't check this field".
func TestMergePolicy_CapabilityHierarchy_TableDriven(t *testing.T) {
	type hierarchyCase struct {
		name         string
		agentRead    []string
		agentWrite   []string
		agentExec    []string
		profileRead  []string
		profileWrite []string
		profileExec  []string
		wantReadLen  int
		wantWriteLen int
		wantExecLen  int
	}

	const skip = -1

	cases := []hierarchyCase{
		{
			// Profile grants read directly → agent read request satisfied.
			name:        "read_granted_directly",
			agentRead:   []string{"/data"},
			profileRead: []string{"/data"},
			wantReadLen: 1,
			wantWriteLen: skip, wantExecLen: skip,
		},
		{
			// Profile grants write for same path → agent read request is satisfied
			// because write implies read (FR1.12). Agent didn't ask for write →
			// agent's abstract Write stays nil so abstract-mode grant applies and
			// profile.Write paths propagate as Write too. We only check Read here.
			name:         "read_via_profile_write_grant",
			agentRead:    []string{"/data"},
			profileWrite: []string{"/data"},
			wantReadLen:  1,
			wantWriteLen: skip, wantExecLen: skip,
		},
		{
			// Profile grants exec for same path → agent read request is satisfied
			// because exec implies read (FR1.12).
			name:        "read_via_profile_exec_grant",
			agentRead:   []string{"/usr/bin/tool"},
			profileExec: []string{"/usr/bin/tool"},
			wantReadLen: 1,
			wantWriteLen: skip, wantExecLen: skip,
		},
		{
			// Profile grants exec but NOT write. Agent requests write for exec path → denied.
			name:         "exec_does_not_grant_write",
			agentWrite:   []string{"/usr/bin/tool"},
			profileExec:  []string{"/usr/bin/tool"},
			wantWriteLen: 0,
			wantReadLen: skip, wantExecLen: skip,
		},
		{
			// Agent requests write only; profile only grants exec.
			// Read: agent has no agentRead and filesystem="read-write" so would inherit
			// all profile exec grants (exec→read implied). We only assert Write is empty.
			name:         "exec_does_not_grant_write_only_check",
			agentWrite:   []string{"/usr/bin/tool"},
			profileExec:  []string{"/usr/bin/tool"},
			wantWriteLen: 0,
			wantReadLen: skip, wantExecLen: skip,
		},
		{
			// Profile grants write directly for the exact path.
			name:         "write_granted_directly",
			agentWrite:   []string{"/tmp/work"},
			profileWrite: []string{"/tmp/work"},
			wantWriteLen: 1,
			wantReadLen: skip, wantExecLen: skip,
		},
		{
			// Profile grants exec directly for the exact path.
			name:        "exec_granted_directly",
			agentExec:   []string{"/usr/bin/go"},
			profileExec: []string{"/usr/bin/go"},
			wantExecLen: 1,
			wantReadLen: skip, wantWriteLen: skip,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &config.AgentConfig{
				Name:        "test-agent",
				Filesystem:  "read-write",
				NetworkMode: "none",
				Read:        tc.agentRead,
				Write:       tc.agentWrite,
				Exec:        tc.agentExec,
			}
			p := &config.ProfileConfig{
				Name:    "test-profile",
				Workdir: "/workspace",
				Read:    tc.profileRead,
				Write:   tc.profileWrite,
				Exec:    tc.profileExec,
			}

			rp, err := MergePolicy(a, p, MergeOptions{})
			if err != nil {
				t.Fatalf("MergePolicy: %v", err)
			}

			if tc.wantReadLen != skip && len(rp.Read) != tc.wantReadLen {
				t.Errorf("Read len: got %d (%v), want %d", len(rp.Read), rp.Read, tc.wantReadLen)
			}
			if tc.wantWriteLen != skip && len(rp.Write) != tc.wantWriteLen {
				t.Errorf("Write len: got %d (%v), want %d", len(rp.Write), rp.Write, tc.wantWriteLen)
			}
			if tc.wantExecLen != skip && len(rp.Exec) != tc.wantExecLen {
				t.Errorf("Exec len: got %d (%v), want %d", len(rp.Exec), rp.Exec, tc.wantExecLen)
			}
		})
	}
}

// TestMergePolicy_ValidationWarnings verifies compile-time validation scenarios.
func TestMergePolicy_ValidationWarnings(t *testing.T) {
	cases := []struct {
		name      string
		agentHCL  string
		profileHCL string
		opts      MergeOptions
		wantWarn  int
		wantErr   bool
		errSubstr string
	}{
		{
			name: "read_not_granted_warns",
			agentHCL: `
agent "a" {
  filesystem   = "read-only"
  network_mode = "none"
  read         = ["/secret"]
}`,
			profileHCL: `
profile "p" {
  workdir = "/w"
  read    = ["/public"]
}`,
			wantWarn: 1,
		},
		{
			name: "write_not_granted_warns",
			agentHCL: `
agent "a" {
  filesystem   = "read-write"
  network_mode = "none"
  write        = ["/etc/passwd"]
}`,
			profileHCL: `
profile "p" {
  workdir = "/w"
  write   = ["/tmp"]
}`,
			wantWarn: 1,
		},
		{
			name: "exec_not_granted_warns",
			agentHCL: `
agent "a" {
  filesystem   = "read-write"
  network_mode = "none"
  exec         = ["/usr/sbin/useradd"]
}`,
			profileHCL: `
profile "p" {
  workdir = "/w"
  exec    = ["/usr/bin/node"]
}`,
			wantWarn: 1,
		},
		{
			name: "all_satisfied_no_warnings",
			agentHCL: `
agent "a" {
  filesystem   = "read-write"
  network_mode = "none"
  read         = ["/app"]
  write        = ["/app/logs"]
  exec         = ["/usr/bin/node"]
}`,
			profileHCL: `
profile "p" {
  workdir = "/app"
  read    = ["/app"]
  write   = ["/app/logs"]
  exec    = ["/usr/bin/node"]
}`,
			wantWarn: 0,
		},
		{
			name: "strict_read_not_granted_errors",
			agentHCL: `
agent "a" {
  filesystem   = "read-only"
  network_mode = "none"
  read         = ["/secret"]
}`,
			profileHCL: `
profile "p" {
  workdir = "/w"
  read    = ["/public"]
}`,
			opts:      MergeOptions{Strict: true},
			wantErr:   true,
			errSubstr: "strict",
		},
		{
			name: "domain_not_granted_warns",
			agentHCL: `
agent "a" {
  filesystem   = "none"
  network_mode = "filtered"
  network {
    domain "private.corp" {}
  }
}`,
			profileHCL: `
profile "p" {
  workdir         = "/w"
  allowed_domains = ["api.anthropic.com"]
}`,
			wantWarn: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agents, err := config.ParseAgentFile("agent.hcl", []byte(tc.agentHCL))
			if err != nil {
				t.Fatalf("ParseAgentFile: %v", err)
			}
			profiles, err := config.ParseProfileFile("profile.hcl", []byte(tc.profileHCL))
			if err != nil {
				t.Fatalf("ParseProfileFile: %v", err)
			}
			rp, err := MergePolicy(agents[0], profiles[0], tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rp.Warnings) < tc.wantWarn {
				t.Errorf("warnings: got %d, want at least %d: %v", len(rp.Warnings), tc.wantWarn, rp.Warnings)
			}
			if tc.wantWarn == 0 && len(rp.Warnings) > 0 {
				t.Errorf("expected no warnings, got: %v", rp.Warnings)
			}
		})
	}
}
