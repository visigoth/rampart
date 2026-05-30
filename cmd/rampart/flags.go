package main

import (
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/visigoth/rampart/internal/policy"
)

// runFlags holds all CLI flags for the root "rampart -- <cmd>" invocation.
type runFlags struct {
	agent         string
	profile       string
	mode          string
	strict        bool
	verbose       bool
	dryRun        bool
	noEscapeHatch bool
	newSession    bool
	newWindow     bool
	noTmux        bool
	headless      bool
	extraPaths    []string
	extraDomains  []string
	envVars       []string
	noEnv         bool
	noTLSMITM     bool
	// flagSet is bound at attach time so toMergeOptions can ask whether
	// individual flags were explicitly passed (via cobra.Flags().Changed).
	flagSet *pflag.FlagSet
}

// attachRunFlags adds all run-mode flags to cmd and returns a pointer to the
// populated runFlags struct.
func attachRunFlags(cmd *cobra.Command) *runFlags {
	f := &runFlags{}

	cmd.Flags().StringVar(&f.agent, "agent", "", "Agent name or project/name (default: from .rampart/defaults.hcl)")
	cmd.Flags().StringVar(&f.profile, "profile", "", "Profile name or project/name (default: from .rampart/defaults.hcl)")
	cmd.Flags().StringVar(&f.mode, "mode", "enforcing", "Enforcement mode: enforcing or audit (was \"permissive\"; allow-default sandbox + fs_usage capture for policy authoring)")
	cmd.Flags().BoolVar(&f.strict, "strict", false, "Promote compile-time validation warnings to errors")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "Print policy compilation diagnostics")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "Compile policy and print sandbox flags without launching")
	cmd.Flags().BoolVar(&f.noEscapeHatch, "no-escape-hatch", false, "Disable interactive escalation (violations are hard kills)")
	cmd.Flags().BoolVar(&f.newSession, "new-session", false, "Start agent in a new tmux session")
	cmd.Flags().BoolVar(&f.newWindow, "new-window", false, "Start agent in a new tmux window")
	cmd.Flags().BoolVar(&f.noTmux, "no-tmux", false, "Force interactive-direct mode (skip tmux)")
	cmd.Flags().BoolVar(&f.headless, "headless", false, "Force headless mode")
	cmd.Flags().StringArrayVar(&f.extraPaths, "allow-path", nil, "Add a path to policy unconditionally (bypass intersection)")
	cmd.Flags().StringArrayVar(&f.extraDomains, "allow-domain", nil, "Add a domain to policy unconditionally (bypass intersection)")
	cmd.Flags().StringArrayVar(&f.envVars, "env", nil, "Augment env allowlist for this invocation (VAR or VAR=value)")
	cmd.Flags().BoolVar(&f.noEnv, "no-env", false, "Strip all user/repo env additions; pass only built-in vars")
	cmd.Flags().BoolVar(&f.noTLSMITM, "no-tls-mitm", false, "Skip TLS interception: tunnel HTTPS untouched, enforce domain-only filtering. HTTP path rules unaffected. No MITM CA required.")

	f.flagSet = cmd.Flags()
	return f
}

// toMergeOptions converts CLI flags to a policy.MergeOptions.
func (f *runFlags) toMergeOptions() policy.MergeOptions {
	// --env entries may be VAR or VAR=value. The merge layer cares about
	// the name half (for intersection); the value half stays with the
	// envVars slice and is consumed verbatim by BuildEnv.
	extraEnvNames := make([]string, 0, len(f.envVars))
	for _, spec := range f.envVars {
		name := spec
		if i := strings.IndexByte(spec, '='); i >= 0 {
			name = spec[:i]
		}
		if name != "" {
			extraEnvNames = append(extraEnvNames, name)
		}
	}
	opts := policy.MergeOptions{
		Mode:         f.mode,
		ExtraPaths:   f.extraPaths,
		ExtraDomains: f.extraDomains,
		ExtraEnv:     extraEnvNames,
		Strict:       f.strict,
	}
	// Only forward --no-tls-mitm when it was explicitly passed; an unpassed
	// false must not override a profile that opted in.
	if f.flagSet != nil && f.flagSet.Changed("no-tls-mitm") {
		v := f.noTLSMITM
		opts.NoTLSMITM = &v
	}
	return opts
}

// ExecutionMode is the detected or forced execution context.
type ExecutionMode int

const (
	ModeInteractiveTmux   ExecutionMode = iota // TTY + tmux present
	ModeInteractiveDirect                      // TTY, no tmux
	ModeHeadless                               // non-TTY or $CI
)

func (m ExecutionMode) String() string {
	switch m {
	case ModeInteractiveTmux:
		return "interactive-tmux"
	case ModeInteractiveDirect:
		return "interactive-direct"
	case ModeHeadless:
		return "headless"
	default:
		return "unknown"
	}
}

// DetectMode determines the execution mode based on environment and flags
// (TR99-TR100).
//
// Priority (highest first):
//  1. --headless flag → headless
//  2. --no-tmux flag  → interactive-direct
//  3. $CI env set     → headless
//  4. Non-TTY stdin   → headless
//  5. $TMUX env set   → interactive-tmux
//  6. default         → interactive-direct
func DetectMode(flags *runFlags) ExecutionMode {
	if flags.headless {
		return ModeHeadless
	}
	if flags.noTmux {
		return ModeInteractiveDirect
	}
	if os.Getenv("CI") != "" {
		return ModeHeadless
	}
	if !isTTY(os.Stdin) {
		return ModeHeadless
	}
	if os.Getenv("TMUX") != "" {
		return ModeInteractiveTmux
	}
	return ModeInteractiveDirect
}

// isTTY returns true if f is connected to a terminal.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// BuildEnv builds the environment variable list for the sandboxed
// process from the resolved policy's Env patterns plus the CLI's
// --env additions. Every concrete VAR=value in the result must match
// at least one pattern in either set (no implicit passthrough).
//
// Patterns may be literal names ("EDITOR") or globs ("LC_*"); globs
// are expanded against os.Environ() at call time. The --env flag may
// pass either VAR or VAR=value:
//   - VAR        → look up the value in the parent env and pass it.
//   - VAR=value  → use the given value verbatim.
//
// --no-env strips the --env additions only; policy.Env still applies,
// since the agent and profile authored those declarations.
func BuildEnv(rp *policy.ResolvedPolicy, envVars []string, noEnv bool) []string {
	var result []string
	patterns := append([]string(nil), rp.Env...)
	patterns = append(patterns, rp.CLIExtraEnv...)
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if envNameMatchesAny(name, patterns) {
			result = append(result, kv)
		}
	}

	if noEnv {
		return dedupEnv(result)
	}

	// --env additions: VAR=value entries override; VAR entries pull
	// from the parent process env. These bypass the pattern match
	// (the CLI knob is the explicit override).
	for _, spec := range envVars {
		if strings.Contains(spec, "=") {
			result = append(result, spec)
			continue
		}
		if val, ok := os.LookupEnv(spec); ok {
			result = append(result, spec+"="+val)
		}
	}

	return dedupEnv(result)
}

// envNameMatchesAny reports whether a concrete env-var name matches
// any pattern in the list. Patterns are either a literal name
// ("EDITOR") or a trailing-`*` prefix glob ("LC_*"). Mirrors
// policy.envPatternMatches but stays in the cmd/rampart package.
func envNameMatchesAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if p == name {
			return true
		}
		if strings.HasSuffix(p, "*") && strings.HasPrefix(name, p[:len(p)-1]) {
			return true
		}
	}
	return false
}

// dedupEnv removes duplicate VAR= entries, keeping last occurrence.
func dedupEnv(env []string) []string {
	seen := make(map[string]int, len(env))
	result := make([]string, 0, len(env))
	for _, kv := range env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if prev, ok := seen[k]; ok {
			result[prev] = kv
		} else {
			seen[k] = len(result)
			result = append(result, kv)
		}
	}
	return result
}

// currentPlatform returns the backend platform name for use in diagnostics.
func currentPlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos-seatbelt"
	case "linux":
		return "linux-bwrap+seccomp"
	default:
		return runtime.GOOS
	}
}
