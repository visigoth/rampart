package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/visigoth/rampart/internal/config"
	"github.com/visigoth/rampart/internal/paths"
	"github.com/visigoth/rampart/internal/policy"
)

// compiledPolicy holds the result of policy loading + merging.
type compiledPolicy struct {
	Policy      *policy.ResolvedPolicy
	AgentName   string
	ProfileName string
}

// loadPolicy locates the git root from startDir, loads the config registry,
// resolves the agent and profile from flags, and returns the merged policy.
func loadPolicy(flags *runFlags, startDir string) (*compiledPolicy, error) {
	gitRoot := config.FindGitRoot(startDir)

	reg, err := config.NewRegistryFromDirs(gitRoot, libraryGlobalDirs())
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	agentName := flags.agent
	if agentName == "" {
		agentName = reg.DefaultAgent()
	}
	if agentName == "" {
		agentName = "coding"
	}

	profileName := flags.profile
	if profileName == "" {
		profileName = reg.DefaultProfile()
	}
	if profileName == "" {
		return nil, fmt.Errorf("no profile specified: set --profile or add default_profile to .rampart/defaults.hcl")
	}

	agent, err := reg.ResolveAgent(agentName)
	if err != nil {
		return nil, fmt.Errorf("resolving agent %q: %w", agentName, err)
	}
	profile, err := reg.ResolveProfile(profileName)
	if err != nil {
		return nil, fmt.Errorf("resolving profile %q: %w", profileName, err)
	}

	// Resolve raw path strings (tildes, "." → gitRoot, relative paths,
	// symlinks) on the agent and profile BEFORE merge. The merge layer
	// performs string-based intersection via pathCovers; if one side is
	// "/" (absolute) and the other is "~/.claude.json" (tilde-relative),
	// the prefix match fails — silently dropping module-declared writes
	// from the resolved policy. Canonicalising both sides to absolute
	// physical paths first makes the intersection do what users expect.
	base := gitRoot
	if base == "" {
		base = startDir
	}
	pctx := paths.Context{GitRoot: base}
	if err := resolveConfigPaths(agent, profile, pctx); err != nil {
		return nil, fmt.Errorf("resolving config paths: %w", err)
	}

	rp, err := policy.MergePolicy(agent, profile, flags.toMergeOptions())
	if err != nil {
		return nil, fmt.Errorf("compiling policy: %w", err)
	}

	// Expand ${VAR} placeholders in rp.Exec to concrete absolute paths.
	// Must run before resolvePolicyPaths so the post-expansion strings
	// flow through the normal path normalizer.
	policy.ResolveExecEnvRefs(rp)

	// Final pass for any post-merge artifacts that weren't pre-resolved
	// (workdir, CLI extras) and to canonicalise the workdir.
	if err := resolvePolicyPaths(rp, gitRoot, startDir); err != nil {
		return nil, fmt.Errorf("resolving policy paths: %w", err)
	}

	return &compiledPolicy{
		Policy:      rp,
		AgentName:   agentName,
		ProfileName: profileName,
	}, nil
}

// resolveConfigPaths canonicalises every path entry in the agent and
// the (already-extends-merged) profile in place. Runs BEFORE
// MergePolicy so the intersection sees physical absolute paths on
// both sides. Without this, declarations like `write = ["~/.claude.json"]`
// in modules don't intersect agent declarations like `write = ["/"]` —
// the tilde never gets expanded, the string prefix match fails, and
// the user's broad ask silently drops the module's specific grant.
//
// Symlinks are resolved to their physical targets so the kernel
// sandbox sees the same paths it grants.
func resolveConfigPaths(agent *config.AgentConfig, profile *config.ProfileConfig, ctx paths.Context) error {
	resolve := func(list []string, label string) ([]string, error) {
		out, err := paths.ResolveAll(list, ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		return out, nil
	}

	var err error
	if agent.Read, err = resolve(agent.Read, "agent.read"); err != nil {
		return err
	}
	if agent.Write, err = resolve(agent.Write, "agent.write"); err != nil {
		return err
	}
	// agent.Exec may contain ${VAR} placeholders that paths.Resolve must
	// not interpret. Pass literal entries through resolve; pass
	// placeholders through unchanged.
	resolvedExec := make([]string, 0, len(agent.Exec))
	for _, e := range agent.Exec {
		if strings.HasPrefix(e, "${") && strings.HasSuffix(e, "}") {
			resolvedExec = append(resolvedExec, e)
			continue
		}
		r, rerr := paths.Resolve(e, ctx)
		if rerr != nil {
			return fmt.Errorf("agent.exec: %w", rerr)
		}
		resolvedExec = append(resolvedExec, r)
	}
	agent.Exec = resolvedExec

	if profile.Read, err = resolve(profile.Read, "profile.read"); err != nil {
		return err
	}
	if profile.Write, err = resolve(profile.Write, "profile.write"); err != nil {
		return err
	}
	if profile.Exec, err = resolve(profile.Exec, "profile.exec"); err != nil {
		return err
	}
	return nil
}

// resolvePolicyPaths expands every path entry in rp (Workdir, Read, Write,
// Exec, CLIExtraPaths) using paths.Resolve. The base for plain relative
// paths is gitRoot if set, else the launch directory. ~/ expands to the
// user's home directory.
func resolvePolicyPaths(rp *policy.ResolvedPolicy, gitRoot, fallback string) error {
	base := gitRoot
	if base == "" {
		base = fallback
	}
	ctx := paths.Context{GitRoot: base}

	if rp.Workdir != "" {
		w, err := paths.Resolve(rp.Workdir, ctx)
		if err != nil {
			return fmt.Errorf("workdir: %w", err)
		}
		rp.Workdir = w
	}

	var err error
	if rp.Read, err = paths.ResolveAll(rp.Read, ctx); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if rp.Write, err = paths.ResolveAll(rp.Write, ctx); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if rp.Exec, err = paths.ResolveAll(rp.Exec, ctx); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if rp.CLIExtraPaths, err = paths.ResolveAll(rp.CLIExtraPaths, ctx); err != nil {
		return fmt.Errorf("cli extra paths: %w", err)
	}
	if rp.UnixSockets, err = paths.ResolveAll(rp.UnixSockets, ctx); err != nil {
		return fmt.Errorf("unix sockets: %w", err)
	}
	return nil
}

// runDryRun implements --dry-run: load+compile policy, print human-readable
// summary and platform-native rules, then exit without launching a child.
func runDryRun(flags *runFlags, out io.Writer) error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	cp, err := loadPolicy(flags, wd)
	if err != nil {
		return err
	}

	printHumanReadable(cp, out)

	fmt.Fprintln(out, "\n--- platform-native rules ---")
	printPlatformNativeRules(cp.Policy, out)
	return nil
}

// printHumanReadable writes the human-readable policy summary to out (FR57.1).
// Each section shows the source layer (agent/profile/CLI) for each grant.
func printHumanReadable(cp *compiledPolicy, out io.Writer) {
	rp := cp.Policy
	fmt.Fprintln(out, "=== rampart dry-run ===")
	fmt.Fprintf(out, "agent:   %s  [source: agent]\n", cp.AgentName)
	fmt.Fprintf(out, "profile: %s  [source: profile]\n", cp.ProfileName)
	fmt.Fprintf(out, "mode:    %s\n", rp.Mode)

	fmt.Fprintln(out, "\n--- filesystem ---")
	fmt.Fprintf(out, "mode: %s\n", rp.FilesystemMode)

	if len(rp.Read) > 0 {
		fmt.Fprintln(out, "read:  [source: policy intersection]")
		for _, p := range rp.Read {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}
	if len(rp.Write) > 0 {
		fmt.Fprintln(out, "write:  [source: policy intersection]")
		for _, p := range rp.Write {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}
	if len(rp.Exec) > 0 {
		fmt.Fprintln(out, "exec:  [source: policy intersection]")
		for _, p := range rp.Exec {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}
	if len(rp.CLIExtraPaths) > 0 {
		fmt.Fprintln(out, "extra paths:  [source: CLI --allow-path]")
		for _, p := range rp.CLIExtraPaths {
			fmt.Fprintf(out, "  %s\n", p)
		}
	}

	fmt.Fprintln(out, "\n--- network ---")
	fmt.Fprintf(out, "mode: %s\n", rp.NetworkMode)
	if rp.NoTLSMITM {
		fmt.Fprintln(out, "tls mitm: disabled (no_tls_mitm)")
	}
	if len(rp.AllowedDomains) > 0 {
		fmt.Fprintln(out, "domains:  [source: profile]")
		for _, d := range rp.AllowedDomains {
			fmt.Fprintf(out, "  %s\n", d)
		}
	}
	if len(rp.CLIExtraDomains) > 0 {
		fmt.Fprintln(out, "extra domains:  [source: CLI --allow-domain]")
		for _, d := range rp.CLIExtraDomains {
			fmt.Fprintf(out, "  %s\n", d)
		}
	}

	if len(rp.Env) > 0 || len(rp.CLIExtraEnv) > 0 {
		fmt.Fprintln(out, "\n--- env passthrough ---")
		if len(rp.Env) > 0 {
			fmt.Fprintln(out, "patterns:  [source: policy intersection]")
			for _, e := range rp.Env {
				fmt.Fprintf(out, "  %s\n", e)
			}
		}
		if len(rp.CLIExtraEnv) > 0 {
			fmt.Fprintln(out, "extra:  [source: CLI --env]")
			for _, e := range rp.CLIExtraEnv {
				fmt.Fprintf(out, "  %s\n", e)
			}
		}
	}

	if len(rp.Warnings) > 0 {
		fmt.Fprintln(out, "\n--- warnings ---")
		for _, w := range rp.Warnings {
			fmt.Fprintf(out, "  ! %s\n", w)
		}
	}
}
