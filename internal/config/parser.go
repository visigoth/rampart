package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// ParseAgentFile parses an HCL file containing one or more agent blocks.
// Returns all agents declared in the file. Each agent's SourceFile is set to path.
func ParseAgentFile(path string, src []byte) ([]*AgentConfig, error) {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	var af agentFile
	if diags = gohcl.DecodeBody(file.Body, nil, &af); diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	agents := make([]*AgentConfig, 0, len(af.Agents))
	for i := range af.Agents {
		a := &af.Agents[i]
		a.SourceFile = path
		if err := validateAgentConfig(a, path); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// ParseProfileFile parses an HCL file containing one or more profile blocks.
// Returns all profiles declared in the file. Each profile's SourceFile is set to path.
//
// After the gohcl decode, a second-pass partial-content extraction reads
// any `use "<module>" { ... }` blocks from the profile's Remain body so
// the module expander can resolve them later (see module.go).
func ParseProfileFile(path string, src []byte) ([]*ProfileConfig, error) {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	var pf profileFile
	if diags = gohcl.DecodeBody(file.Body, nil, &pf); diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	profiles := make([]*ProfileConfig, 0, len(pf.Profiles))
	for i := range pf.Profiles {
		p := &pf.Profiles[i]
		p.SourceFile = path
		if err := validateProfileConfig(p, path); err != nil {
			return nil, err
		}
		uses, err := extractUseBlocks(p.Remain)
		if err != nil {
			return nil, err
		}
		p.Use = uses
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// extractUseBlocks performs a second-pass partial-content decode against a
// remain body to surface any `use "<path>" { ... }` blocks. The use
// blocks' bodies are held verbatim for later evaluation in the module
// expander, where the consumer's EvalContext is known.
//
// Returns nil for both result and error when remain is nil (no surfaced
// remain body — applies to constructions that don't capture it).
func extractUseBlocks(remain hcl.Body) ([]*UseBlock, error) {
	if remain == nil {
		return nil, nil
	}
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "use", LabelNames: []string{"path"}},
		},
	}
	content, _, diags := remain.PartialContent(schema)
	if diags.HasErrors() {
		return nil, diagsToError(diags)
	}
	out := make([]*UseBlock, 0, len(content.Blocks))
	for _, blk := range content.Blocks {
		out = append(out, &UseBlock{
			ModulePath: blk.Labels[0],
			ArgBody:    blk.Body,
			DeclRange:  blk.DefRange,
		})
	}
	return out, nil
}

// ParseDefaultsFile parses a defaults.hcl file.
// Returns nil if the file contains no defaults block.
func ParseDefaultsFile(path string, src []byte) (*DefaultsConfig, error) {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	var df defaultsFile
	if diags = gohcl.DecodeBody(file.Body, nil, &df); diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	if len(df.Defaults) == 0 {
		return nil, nil
	}
	if len(df.Defaults) > 1 {
		return nil, fmt.Errorf("%s: only one defaults block is allowed", path)
	}
	return &df.Defaults[0], nil
}

// validateAgentConfig validates required fields and glob patterns in an AgentConfig.
func validateAgentConfig(a *AgentConfig, path string) error {
	if a.Name == "" {
		return fmt.Errorf("%s: agent block label (name) must not be empty", path)
	}
	if err := validateFilesystemMode(a.Filesystem, path, "agent", a.Name); err != nil {
		return err
	}
	if err := validateNetworkMode(a.NetworkMode, path, "agent", a.Name); err != nil {
		return err
	}
	if err := validatePathGlobs(a.Read, path, "agent", a.Name, "read"); err != nil {
		return err
	}
	if err := validatePathGlobs(a.Write, path, "agent", a.Name, "write"); err != nil {
		return err
	}
	if err := validatePathGlobs(a.Exec, path, "agent", a.Name, "exec"); err != nil {
		return err
	}
	if err := validateDomainGlobs(a.Domains, path, "agent", a.Name, "domains"); err != nil {
		return err
	}
	if err := validateEnvGlobs(a.Env, path, "agent", a.Name, "env"); err != nil {
		return err
	}
	if a.Network != nil {
		if err := validateNetworkConfig(a.Network, path, "agent", a.Name); err != nil {
			return err
		}
	}
	return nil
}

// validateProfileConfig validates required fields and glob patterns in a ProfileConfig.
func validateProfileConfig(p *ProfileConfig, path string) error {
	if p.Name == "" {
		return fmt.Errorf("%s: profile block label (name) must not be empty", path)
	}
	// workdir is required at parse time UNLESS the profile inherits from
	// another via `extends`, in which case the parent supplies it. Final
	// validation happens after extends merging in the registry.
	if p.Workdir == "" && p.Extends == "" {
		return fmt.Errorf("%s: profile %q: workdir is required (or set extends)", path, p.Name)
	}
	if err := validatePathGlobs(p.Read, path, "profile", p.Name, "read"); err != nil {
		return err
	}
	if err := validatePathGlobs(p.Write, path, "profile", p.Name, "write"); err != nil {
		return err
	}
	if err := validatePathGlobs(p.Exec, path, "profile", p.Name, "exec"); err != nil {
		return err
	}
	if err := validateDomainGlobs(p.AllowedDomains, path, "profile", p.Name, "allowed_domains"); err != nil {
		return err
	}
	if err := validateDomainGlobs(p.MitmDomains, path, "profile", p.Name, "mitm_domains"); err != nil {
		return err
	}
	if err := validateEnvGlobs(p.Env, path, "profile", p.Name, "env"); err != nil {
		return err
	}
	if p.Network != nil {
		if err := validateNetworkConfig(p.Network, path, "profile", p.Name); err != nil {
			return err
		}
	}
	return nil
}

func validateFilesystemMode(mode, path, kind, name string) error {
	switch mode {
	case "none", "read-only", "read-write":
		return nil
	}
	return fmt.Errorf("%s: %s %q: filesystem must be one of none, read-only, read-write; got %q", path, kind, name, mode)
}

func validateNetworkMode(mode, path, kind, name string) error {
	switch mode {
	case "none", "filtered", "full":
		return nil
	}
	return fmt.Errorf("%s: %s %q: network_mode must be one of none, filtered, full; got %q", path, kind, name, mode)
}

func validatePathGlobs(paths []string, file, kind, name, field string) error {
	for _, p := range paths {
		if err := ValidateGlobPattern(p, '/'); err != nil {
			return fmt.Errorf("%s: %s %q: %s: %w", file, kind, name, field, err)
		}
	}
	return nil
}

func validateDomainGlobs(domains []string, file, kind, name, field string) error {
	for _, d := range domains {
		if err := ValidateGlobPattern(d, '.'); err != nil {
			return fmt.Errorf("%s: %s %q: %s: %w", file, kind, name, field, err)
		}
	}
	return nil
}

// validateEnvGlobs validates env-var passthrough patterns. Env names
// are flat (a `_` is part of the name, not a meaningful separator),
// so the supported forms are minimal:
//
//   - "EDITOR"   — exact name match.
//   - "LC_*"     — prefix match: trailing `*` only, with a non-empty
//                  literal prefix.
//
// A bare wildcard, leading wildcard, or anything fancier is rejected
// so the env surface stays auditable.
func validateEnvGlobs(names []string, file, kind, name, field string) error {
	for _, n := range names {
		if n == "" {
			return fmt.Errorf("%s: %s %q: %s: empty env pattern", file, kind, name, field)
		}
		if strings.ContainsAny(n, "?{}[]") {
			return fmt.Errorf("%s: %s %q: %s: pattern %q contains unsupported wildcards", file, kind, name, field, n)
		}
		starIdx := strings.IndexByte(n, '*')
		if starIdx < 0 {
			// Pure literal — must look like a valid env var name.
			if !isValidEnvName(n) {
				return fmt.Errorf("%s: %s %q: %s: %q is not a valid env-var name", file, kind, name, field, n)
			}
			continue
		}
		// Globbed — must be trailing `*` only, with a non-empty prefix.
		if starIdx == 0 {
			return fmt.Errorf("%s: %s %q: %s: pattern %q has no literal prefix; use PREFIX_* form", file, kind, name, field, n)
		}
		if starIdx != len(n)-1 {
			return fmt.Errorf("%s: %s %q: %s: pattern %q must end in `*`; only trailing wildcards are supported", file, kind, name, field, n)
		}
		prefix := n[:starIdx]
		if !isValidEnvName(prefix) {
			return fmt.Errorf("%s: %s %q: %s: prefix %q in pattern %q is not a valid env-var name", file, kind, name, field, prefix, n)
		}
	}
	return nil
}

// isValidEnvName reports whether s could be a real env-var name —
// starts with letter or underscore, continues with letters, digits,
// or underscores. POSIX conventionally uses uppercase, but
// `_special` and lowercase names are also valid environment names
// in practice, so we accept the broader character set.
func isValidEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validateNetworkConfig(nc *NetworkConfig, file, kind, name string) error {
	for _, d := range nc.Domains {
		if err := ValidateGlobPattern(d.Pattern, '.'); err != nil {
			return fmt.Errorf("%s: %s %q: network domain: %w", file, kind, name, err)
		}
		for _, rule := range d.Allow {
			if err := validateRuleConfig(&rule, file, kind, name, d.Pattern, "allow"); err != nil {
				return err
			}
		}
		for _, rule := range d.Deny {
			if err := validateRuleConfig(&rule, file, kind, name, d.Pattern, "deny"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRuleConfig(r *RuleConfig, file, kind, name, domain, ruleType string) error {
	if r.Method == "" {
		return fmt.Errorf("%s: %s %q: network domain %q: %s rule method must not be empty", file, kind, name, domain, ruleType)
	}
	if err := validatePathGlobs(r.Paths, file, kind, name, fmt.Sprintf("network domain %q %s %q paths", domain, ruleType, r.Method)); err != nil {
		return err
	}
	return nil
}

// diagsToError converts HCL diagnostics to a Go error with file:line context.
func diagsToError(diags hcl.Diagnostics) error {
	var sb strings.Builder
	for i, d := range diags {
		if i > 0 {
			sb.WriteString("; ")
		}
		if d.Subject != nil {
			sb.WriteString(d.Subject.Filename)
			sb.WriteString(":")
			sb.WriteString(fmt.Sprintf("%d", d.Subject.Start.Line))
			sb.WriteString(":")
			sb.WriteString(fmt.Sprintf("%d", d.Subject.Start.Column))
			sb.WriteString(": ")
		}
		sb.WriteString(d.Summary)
		if d.Detail != "" {
			sb.WriteString(": ")
			sb.WriteString(d.Detail)
		}
	}
	return fmt.Errorf("%s", sb.String())
}

// absPath resolves path relative to base, cleaning the result.
// Used by the loader when constructing registry paths.
func absPath(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(base, path))
}
