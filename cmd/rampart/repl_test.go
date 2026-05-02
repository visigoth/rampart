package main

import (
	"strings"
	"testing"

	"github.com/visigoth/rampart/internal/proxy"
	"github.com/visigoth/rampart/internal/policy"
)

// buildTestPolicy returns a minimal ResolvedPolicy for REPL tests.
func buildTestPolicy() *policy.ResolvedPolicy {
	return &policy.ResolvedPolicy{
		AgentName:      "test-agent",
		ProfileName:    "test-profile",
		Mode:           "enforcing",
		FilesystemMode: "read-write",
		Read:           []string{"/home/user", "/tmp"},
		Write:          []string{"/tmp"},
		Exec:           []string{"/usr/bin"},
		NetworkMode:    "filtered",
		AllowedDomains: []string{"api.example.com"},
	}
}

// buildTestACLRules returns ACL rules matching buildTestPolicy.
func buildTestACLRules() []proxy.ProxyACLRule {
	return []proxy.ProxyACLRule{
		{
			Domain: "api.example.com",
			Items: []proxy.ACLItem{
				{Allow: true, Method: "GET", Paths: []string{"/v1/*"}},
				{Allow: true, Method: "POST", Paths: []string{"/v1/*"}},
			},
		},
		{
			Domain: "blocked.example.com",
			Items: []proxy.ACLItem{
				{Allow: false},
			},
		},
	}
}

func runREPLLines(t *testing.T, lines []string) string {
	t.Helper()
	rp := buildTestPolicy()
	aclRules := buildTestACLRules()
	input := strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out strings.Builder
	if err := RunREPL(rp, aclRules, input, &out); err != nil {
		t.Fatalf("RunREPL error: %v", err)
	}
	return out.String()
}

func TestREPL_Exit(t *testing.T) {
	out := runREPLLines(t, []string{"exit"})
	if !strings.Contains(out, "bye") {
		t.Errorf("expected 'bye' on exit, got: %q", out)
	}
}

func TestREPL_Quit(t *testing.T) {
	out := runREPLLines(t, []string{"quit"})
	if !strings.Contains(out, "bye") {
		t.Errorf("expected 'bye' on quit, got: %q", out)
	}
}

func TestREPL_EmptyLinesSkipped(t *testing.T) {
	out := runREPLLines(t, []string{"", "  ", "exit"})
	if !strings.Contains(out, "bye") {
		t.Errorf("expected 'bye' after empty lines, got: %q", out)
	}
}

func TestREPL_UnknownCommand(t *testing.T) {
	out := runREPLLines(t, []string{"bogus", "exit"})
	if !strings.Contains(out, "unknown command") {
		t.Errorf("expected 'unknown command' error, got: %q", out)
	}
}

// Filesystem read tests.

func TestREPL_ReadAllowed(t *testing.T) {
	out := runREPLLines(t, []string{"read /home/user/file.txt", "exit"})
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED for /home/user/file.txt, got: %q", out)
	}
	if !strings.Contains(out, "/home/user") {
		t.Errorf("expected rule /home/user in output, got: %q", out)
	}
}

func TestREPL_ReadDenied(t *testing.T) {
	out := runREPLLines(t, []string{"read /etc/passwd", "exit"})
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED for /etc/passwd, got: %q", out)
	}
}

func TestREPL_ReadAllowedByWriteGrant(t *testing.T) {
	// Read is satisfied by write grant (capability hierarchy).
	out := runREPLLines(t, []string{"read /tmp/foo.txt", "exit"})
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED for /tmp/foo.txt (write grant), got: %q", out)
	}
}

func TestREPL_ReadMissingArg(t *testing.T) {
	out := runREPLLines(t, []string{"read", "exit"})
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected usage message, got: %q", out)
	}
}

// Filesystem write tests.

func TestREPL_WriteAllowed(t *testing.T) {
	out := runREPLLines(t, []string{"write /tmp/output.txt", "exit"})
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED for /tmp/output.txt, got: %q", out)
	}
}

func TestREPL_WriteDenied_ReadOnlyPath(t *testing.T) {
	// /home/user is only in Read, not Write.
	out := runREPLLines(t, []string{"write /home/user/file.txt", "exit"})
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED for write to read-only path, got: %q", out)
	}
}

func TestREPL_WriteDenied_Unlisted(t *testing.T) {
	out := runREPLLines(t, []string{"write /etc/hosts", "exit"})
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED for write /etc/hosts, got: %q", out)
	}
}

func TestREPL_WriteMissingArg(t *testing.T) {
	out := runREPLLines(t, []string{"write", "exit"})
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected usage message, got: %q", out)
	}
}

// Filesystem exec tests.

func TestREPL_ExecAllowed(t *testing.T) {
	out := runREPLLines(t, []string{"exec /usr/bin/python3", "exit"})
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED for /usr/bin/python3, got: %q", out)
	}
}

func TestREPL_ExecDenied(t *testing.T) {
	out := runREPLLines(t, []string{"exec /home/user/script.sh", "exit"})
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED for exec outside Exec list, got: %q", out)
	}
}

func TestREPL_ExecMissingArg(t *testing.T) {
	out := runREPLLines(t, []string{"exec", "exit"})
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected usage message, got: %q", out)
	}
}

// HTTP tests.

func TestREPL_HTTPAllowed(t *testing.T) {
	out := runREPLLines(t, []string{"http GET https://api.example.com/v1/items", "exit"})
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED for GET api.example.com/v1/items, got: %q", out)
	}
}

func TestREPL_HTTPDenied_BlockedDomain(t *testing.T) {
	out := runREPLLines(t, []string{"http GET https://blocked.example.com/v1/items", "exit"})
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED for blocked.example.com, got: %q", out)
	}
}

func TestREPL_HTTPDenied_UnlistedDomain(t *testing.T) {
	out := runREPLLines(t, []string{"http GET https://other.example.com/v1/items", "exit"})
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED for unlisted domain, got: %q", out)
	}
}

func TestREPL_HTTPDenied_WrongPath(t *testing.T) {
	out := runREPLLines(t, []string{"http GET https://api.example.com/v2/items", "exit"})
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED for /v2 path (only /v1 allowed), got: %q", out)
	}
}

func TestREPL_HTTPNetworkModeNone(t *testing.T) {
	rp := buildTestPolicy()
	rp.NetworkMode = "none"
	aclRules := buildTestACLRules()
	input := strings.NewReader("http GET https://api.example.com/v1/items\nexit\n")
	var out strings.Builder
	if err := RunREPL(rp, aclRules, input, &out); err != nil {
		t.Fatalf("RunREPL error: %v", err)
	}
	if !strings.Contains(out.String(), "DENIED") {
		t.Errorf("expected DENIED in network_mode=none, got: %q", out.String())
	}
}

func TestREPL_HTTPNetworkModeFull(t *testing.T) {
	rp := buildTestPolicy()
	rp.NetworkMode = "full"
	aclRules := buildTestACLRules()
	input := strings.NewReader("http GET https://anything.example.com/path\nexit\n")
	var out strings.Builder
	if err := RunREPL(rp, aclRules, input, &out); err != nil {
		t.Fatalf("RunREPL error: %v", err)
	}
	if !strings.Contains(out.String(), "ALLOWED") {
		t.Errorf("expected ALLOWED in network_mode=full, got: %q", out.String())
	}
}

func TestREPL_HTTPMissingArgs(t *testing.T) {
	out := runREPLLines(t, []string{"http GET", "exit"})
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected usage message for http with 1 arg, got: %q", out)
	}
}

// Policy command.

func TestREPL_Policy(t *testing.T) {
	out := runREPLLines(t, []string{"policy", "exit"})
	for _, want := range []string{"test-agent", "test-profile", "enforcing", "filtered"} {
		if !strings.Contains(out, want) {
			t.Errorf("policy output missing %q; got: %q", want, out)
		}
	}
}

// replPathCovers tests.

func TestReplPathCovers_ExactMatch(t *testing.T) {
	if !replPathCovers("/home/user", "/home/user") {
		t.Error("exact match should be covered")
	}
}

func TestReplPathCovers_SubdirMatch(t *testing.T) {
	if !replPathCovers("/home/user", "/home/user/docs/file.txt") {
		t.Error("subdir should be covered")
	}
}

func TestReplPathCovers_PrefixNoSep(t *testing.T) {
	// /home/user should NOT cover /home/username
	if replPathCovers("/home/user", "/home/username") {
		t.Error("/home/user should not cover /home/username")
	}
}

func TestReplPathCovers_NoMatch(t *testing.T) {
	if replPathCovers("/home/user", "/etc/passwd") {
		t.Error("/home/user should not cover /etc/passwd")
	}
}

func TestReplPathCovers_TrailingSep(t *testing.T) {
	if !replPathCovers("/home/user/", "/home/user/file.txt") {
		t.Error("trailing sep should still match subdir")
	}
}

// CLIExtraPaths tests.

func TestREPL_CLIExtraPathsAllowRead(t *testing.T) {
	rp := buildTestPolicy()
	rp.CLIExtraPaths = []string{"/opt/tools"}
	aclRules := buildTestACLRules()
	input := strings.NewReader("read /opt/tools/bin\nexit\n")
	var out strings.Builder
	if err := RunREPL(rp, aclRules, input, &out); err != nil {
		t.Fatalf("RunREPL error: %v", err)
	}
	if !strings.Contains(out.String(), "ALLOWED") {
		t.Errorf("expected ALLOWED via CLIExtraPaths, got: %q", out.String())
	}
}
