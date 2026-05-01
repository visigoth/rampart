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
		profiles = append(profiles, p)
	}
	return profiles, nil
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
	if p.Workdir == "" {
		return fmt.Errorf("%s: profile %q: workdir is required", path, p.Name)
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
