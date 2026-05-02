//go:build linux

package main

import (
	"fmt"
	"io"
	"strings"

	linux "github.com/visigoth/rampart/internal/sandbox/linux"
	"github.com/visigoth/rampart/internal/policy"
)

// printPlatformNativeRules writes Linux-specific sandbox rules to out:
// bwrap command-line flags, iptables rules, and a seccomp summary.
func printPlatformNativeRules(rp *policy.ResolvedPolicy, out io.Writer) {
	// bwrap flags.
	bwrapFlags := linux.CompileBwrapFlags(rp)
	fmt.Fprintln(out, "bwrap:")
	fmt.Fprintf(out, "  bwrap \\\n")
	for i, f := range bwrapFlags {
		if i < len(bwrapFlags)-1 {
			fmt.Fprintf(out, "    %s \\\n", f)
		} else {
			fmt.Fprintf(out, "    %s\n", f)
		}
	}

	// iptables rules.
	iptRules := linux.CompileIptables(rp)
	if len(iptRules.Warnings) > 0 {
		fmt.Fprintln(out, "\niptables-warnings:")
		for _, w := range iptRules.Warnings {
			fmt.Fprintf(out, "  ! %s\n", w)
		}
	}
	if len(iptRules.IPv4) > 0 {
		fmt.Fprintln(out, "\niptables:")
		for _, cmd := range iptRules.IPv4 {
			fmt.Fprintf(out, "  %s\n", strings.Join(cmd, " "))
		}
	}
	if len(iptRules.IPv6) > 0 {
		fmt.Fprintln(out, "\nip6tables:")
		for _, cmd := range iptRules.IPv6 {
			fmt.Fprintf(out, "  %s\n", strings.Join(cmd, " "))
		}
	}

	// seccomp summary (BPF compilation is architecture-specific; see sandbox/linux/seccomp.go).
	fmt.Fprintln(out, "\nseccomp: standard rampart filter")
	fmt.Fprintln(out, "  - path-taking syscalls (open, stat, exec, …) → supervisor notify")
	fmt.Fprintln(out, "  - privilege-escalation syscalls (ptrace, …) → SIGKILL")
	fmt.Fprintln(out, "  - all other syscalls → allow")
}
