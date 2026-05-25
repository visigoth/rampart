package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/config"
)

// --- envPatternMatches ---

func TestEnvPatternMatches(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"EDITOR", "EDITOR", true},
		{"EDITOR", "VISUAL", false},
		{"LC_*", "LC_ALL", true},
		{"LC_*", "LC_TIME", true},
		{"LC_*", "LCALL", false},
		{"LC_*", "PATH", false},
		{"XDG_*", "XDG_CACHE_HOME", true},
		{"XDG_*", "XDG_RUNTIME_DIR", true},
	}
	for _, c := range cases {
		if got := envPatternMatches(c.pattern, c.name); got != c.want {
			t.Errorf("envPatternMatches(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// --- envPatternCovers ---

func TestEnvPatternCovers(t *testing.T) {
	cases := []struct {
		grant, req string
		want       bool
	}{
		{"EDITOR", "EDITOR", true},
		{"LC_*", "LC_ALL", true},
		{"LC_*", "LC_*", true},
		{"LC_*", "LC_T*", true},
		{"LC_T*", "LC_*", false}, // grant narrower than request
		{"EDITOR", "VISUAL", false},
		{"EDITOR", "LC_*", false}, // literal grant can't cover a glob
	}
	for _, c := range cases {
		if got := envPatternCovers(c.grant, c.req); got != c.want {
			t.Errorf("envPatternCovers(grant=%q, req=%q) = %v, want %v", c.grant, c.req, got, c.want)
		}
	}
}

// --- intersectEnvPatterns ---

func TestIntersectEnvPatterns(t *testing.T) {
	agentP := []string{"EDITOR", "VISUAL", "LC_*"}
	profileP := []string{"EDITOR", "LC_*", "PATH"}
	got := intersectEnvPatterns(agentP, profileP)
	want := map[string]bool{"EDITOR": true, "LC_*": true}
	if len(got) != len(want) {
		t.Fatalf("intersect: got %v, want keys %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("intersect: unexpected %q in %v", g, got)
		}
	}
}

// --- ${VAR} reference extraction ---

func TestReferencedEnvVars(t *testing.T) {
	in := []string{
		"${EDITOR}",
		"/usr/bin/git",
		"${VISUAL}",
		"${EDITOR}", // duplicate
	}
	got := referencedEnvVars(in)
	if len(got) != 2 || got[0] != "EDITOR" || got[1] != "VISUAL" {
		t.Errorf("referencedEnvVars: got %v, want [EDITOR VISUAL]", got)
	}
}

// --- splitExecEnvPlaceholders ---

func TestSplitExecEnvPlaceholders(t *testing.T) {
	literals, placeholders := splitExecEnvPlaceholders([]string{
		"/usr/bin/git",
		"${EDITOR}",
		"/usr/bin/make",
		"${VISUAL}",
	})
	if len(literals) != 2 || literals[0] != "/usr/bin/git" || literals[1] != "/usr/bin/make" {
		t.Errorf("literals: %v", literals)
	}
	if len(placeholders) != 2 || placeholders[0] != "${EDITOR}" || placeholders[1] != "${VISUAL}" {
		t.Errorf("placeholders: %v", placeholders)
	}
}

// --- merge-time validation: ${VAR} not in agent env ---

func TestMerge_ExecRefMissingFromAgentEnv_Warns(t *testing.T) {
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Exec = []string{"${EDITOR}"}
		// EDITOR is not in a.Env — should produce a warning.
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Exec = []string{"/usr/bin"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	found := false
	for _, w := range rp.Warnings {
		if strings.Contains(w, "${EDITOR}") && strings.Contains(w, "not declared in agent env") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about ${EDITOR} not in env; got %v", rp.Warnings)
	}
}

// --- merge-time validation: agent.Env not granted by profile ---

func TestMerge_AgentEnvNotInProfile_Warns(t *testing.T) {
	a := agentWith("coding", "none", "none", func(a *config.AgentConfig) {
		a.Env = []string{"EDITOR"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Env = []string{"PATH"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	found := false
	for _, w := range rp.Warnings {
		if strings.Contains(w, "EDITOR") && strings.Contains(w, "does not grant") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about EDITOR not granted; got %v", rp.Warnings)
	}
	if len(rp.Env) != 0 {
		t.Errorf("rp.Env: got %v, want []", rp.Env)
	}
}

// --- merge: env intersected, ${VAR} validates clean when env covers it ---

func TestMerge_ExecRefWithEnv_NoWarning(t *testing.T) {
	a := agentWith("coding", "read-write", "none", func(a *config.AgentConfig) {
		a.Env = []string{"EDITOR"}
		a.Exec = []string{"${EDITOR}"}
	})
	p := profileWith("default", ".", func(p *config.ProfileConfig) {
		p.Env = []string{"EDITOR"}
		p.Exec = []string{"/usr/bin"}
	})
	rp, err := MergePolicy(a, p, defaultOpts())
	if err != nil {
		t.Fatalf("MergePolicy: %v", err)
	}
	for _, w := range rp.Warnings {
		if strings.Contains(w, "${EDITOR}") || strings.Contains(w, "EDITOR") {
			t.Errorf("unexpected warning: %v", w)
		}
	}
}

// --- ResolveExecEnvRefs: happy path ---

func TestResolveExecEnvRefs_HappyPath(t *testing.T) {
	// Use /bin/sh as a stable target on both macOS and Linux.
	os.Setenv("RAMPART_TEST_EDITOR", "/bin/sh")
	defer os.Unsetenv("RAMPART_TEST_EDITOR")

	rp := &ResolvedPolicy{
		execPlaceholders:  []string{"${RAMPART_TEST_EDITOR}"},
		profileExecGrants: []string{"/bin"},
	}
	refs := ResolveExecEnvRefs(rp)
	if len(refs) != 1 || refs[0] != "RAMPART_TEST_EDITOR" {
		t.Errorf("refs: got %v, want [RAMPART_TEST_EDITOR]", refs)
	}
	if len(rp.Exec) != 1 || rp.Exec[0] != "/bin/sh" {
		t.Errorf("rp.Exec: got %v, want [/bin/sh]", rp.Exec)
	}
	for _, w := range rp.Warnings {
		if strings.Contains(w, "RAMPART_TEST_EDITOR") {
			t.Errorf("unexpected warning: %v", w)
		}
	}
}

// --- ResolveExecEnvRefs: unset env var ---

func TestResolveExecEnvRefs_UnsetVar_Warns(t *testing.T) {
	os.Unsetenv("RAMPART_TEST_DEFINITELY_UNSET")

	rp := &ResolvedPolicy{
		execPlaceholders:  []string{"${RAMPART_TEST_DEFINITELY_UNSET}"},
		profileExecGrants: []string{"/usr/bin"},
	}
	ResolveExecEnvRefs(rp)
	if len(rp.Exec) != 0 {
		t.Errorf("rp.Exec: got %v, want []", rp.Exec)
	}
	found := false
	for _, w := range rp.Warnings {
		if strings.Contains(w, "is unset") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'unset' warning; got %v", rp.Warnings)
	}
}

// --- ResolveExecEnvRefs: profile doesn't cover resolved path ---

func TestResolveExecEnvRefs_ProfileDoesNotCoverResolved_Warns(t *testing.T) {
	os.Setenv("RAMPART_TEST_OUTSIDE", "/bin/sh")
	defer os.Unsetenv("RAMPART_TEST_OUTSIDE")

	rp := &ResolvedPolicy{
		execPlaceholders:  []string{"${RAMPART_TEST_OUTSIDE}"},
		profileExecGrants: []string{"/opt/only"},
	}
	ResolveExecEnvRefs(rp)
	if len(rp.Exec) != 0 {
		t.Errorf("rp.Exec: got %v, want [] (not covered by profile)", rp.Exec)
	}
	found := false
	for _, w := range rp.Warnings {
		if strings.Contains(w, "not granted by profile") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'not granted by profile' warning; got %v", rp.Warnings)
	}
}
