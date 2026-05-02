package main

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/visigoth/rampart/internal/policy"
	"github.com/visigoth/rampart/internal/proxy"
)

// REPLVerdict is the outcome of a policy check in the test REPL.
type REPLVerdict struct {
	Allowed bool
	Rule    string // matching pattern, or "" if no match
}

func (v REPLVerdict) String() string {
	if v.Allowed {
		if v.Rule != "" {
			return fmt.Sprintf("ALLOWED (rule: %s)", v.Rule)
		}
		return "ALLOWED"
	}
	return "DENIED"
}

// RunREPL reads commands from in and writes output to out.
// It evaluates each command against the resolved policy and ACL rules.
func RunREPL(rp *policy.ResolvedPolicy, aclRules []proxy.ProxyACLRule, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	for {
		fmt.Fprint(out, "rampart> ")
		if !scanner.Scan() {
			fmt.Fprintln(out)
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if exit := handleREPLLine(line, rp, aclRules, out); exit {
			return nil
		}
	}
}

// handleREPLLine dispatches one REPL input line. Returns true if the REPL should exit.
func handleREPLLine(line string, rp *policy.ResolvedPolicy, aclRules []proxy.ProxyACLRule, out io.Writer) bool {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false
	}
	cmd, args := parts[0], parts[1:]

	switch cmd {
	case "exit", "quit":
		fmt.Fprintln(out, "bye")
		return true
	case "policy":
		printREPLPolicySummary(rp, out)
	case "read":
		if len(args) == 0 {
			fmt.Fprintln(out, "usage: read <path>")
			return false
		}
		v := checkFilesystemOp(rp, "read", args[0])
		fmt.Fprintf(out, "%s %s: %s\n", cmd, args[0], v)
	case "write":
		if len(args) == 0 {
			fmt.Fprintln(out, "usage: write <path>")
			return false
		}
		v := checkFilesystemOp(rp, "write", args[0])
		fmt.Fprintf(out, "%s %s: %s\n", cmd, args[0], v)
	case "exec":
		if len(args) == 0 {
			fmt.Fprintln(out, "usage: exec <path>")
			return false
		}
		v := checkFilesystemOp(rp, "exec", args[0])
		fmt.Fprintf(out, "%s %s: %s\n", cmd, args[0], v)
	case "http":
		if len(args) < 2 {
			fmt.Fprintln(out, "usage: http <METHOD> <URL>")
			return false
		}
		v := checkHTTPOp(rp, aclRules, args[0], args[1])
		fmt.Fprintf(out, "http %s %s: %s\n", args[0], args[1], v)
	default:
		fmt.Fprintf(out, "unknown command %q — try: read write exec http policy exit\n", cmd)
	}
	return false
}

// checkFilesystemOp returns whether op (read/write/exec) on path is allowed by rp.
func checkFilesystemOp(rp *policy.ResolvedPolicy, op, path string) REPLVerdict {
	var lists [][]string
	switch op {
	case "read", "stat":
		// Read is satisfied by read, write, or exec grant (capability hierarchy).
		lists = [][]string{rp.Read, rp.Write, rp.Exec, rp.CLIExtraPaths}
	case "write":
		lists = [][]string{rp.Write, rp.CLIExtraPaths}
	case "exec":
		lists = [][]string{rp.Exec, rp.CLIExtraPaths}
	default:
		return REPLVerdict{}
	}
	for _, list := range lists {
		for _, pattern := range list {
			if replPathCovers(pattern, path) {
				return REPLVerdict{Allowed: true, Rule: pattern}
			}
		}
	}
	return REPLVerdict{Allowed: false}
}

// checkHTTPOp returns whether the given HTTP method+URL is allowed by rp.
func checkHTTPOp(rp *policy.ResolvedPolicy, aclRules []proxy.ProxyACLRule, method, rawURL string) REPLVerdict {
	switch rp.NetworkMode {
	case "none":
		return REPLVerdict{Allowed: false}
	case "full":
		return REPLVerdict{Allowed: true, Rule: "network_mode=full"}
	}

	// NetworkMode "filtered": evaluate against proxy ACL rules.
	u, err := url.Parse(rawURL)
	if err != nil {
		return REPLVerdict{Allowed: false}
	}
	host := u.Hostname()
	path := u.Path
	if path == "" {
		path = "/"
	}

	rule, ok := proxy.FindMatchingRule(aclRules, host)
	if !ok {
		return REPLVerdict{Allowed: false}
	}
	verdict := rule.EvalRequest(strings.ToUpper(method), path)
	if verdict == proxy.VerdictAllow {
		return REPLVerdict{Allowed: true, Rule: rule.Domain}
	}
	return REPLVerdict{Allowed: false}
}

// printREPLPolicySummary writes a compact policy summary for the REPL 'policy' command.
func printREPLPolicySummary(rp *policy.ResolvedPolicy, out io.Writer) {
	fmt.Fprintf(out, "agent:      %s\n", rp.AgentName)
	fmt.Fprintf(out, "profile:    %s\n", rp.ProfileName)
	fmt.Fprintf(out, "mode:       %s\n", rp.Mode)
	fmt.Fprintf(out, "filesystem: %s\n", rp.FilesystemMode)
	if len(rp.Read) > 0 {
		fmt.Fprintf(out, "read:       %s\n", strings.Join(rp.Read, ", "))
	}
	if len(rp.Write) > 0 {
		fmt.Fprintf(out, "write:      %s\n", strings.Join(rp.Write, ", "))
	}
	if len(rp.Exec) > 0 {
		fmt.Fprintf(out, "exec:       %s\n", strings.Join(rp.Exec, ", "))
	}
	fmt.Fprintf(out, "network:    %s\n", rp.NetworkMode)
	if len(rp.AllowedDomains) > 0 {
		fmt.Fprintf(out, "domains:    %s\n", strings.Join(rp.AllowedDomains, ", "))
	}
}

// replPathCovers returns true if pattern is an ancestor directory of (or exactly
// equal to) path, using directory-prefix semantics.
func replPathCovers(pattern, path string) bool {
	if pattern == path {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(path, strings.TrimRight(pattern, sep)+sep)
}
