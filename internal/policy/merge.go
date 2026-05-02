package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/visigoth/rampart/internal/config"
)

// filesystemLevel assigns a numeric rank to abstract filesystem modes.
// Higher rank = more permissive. Used to compute min().
var filesystemLevel = map[string]int{
	"none":       0,
	"read-only":  1,
	"read-write": 2,
}

// networkLevel assigns a numeric rank to abstract network modes.
var networkLevel = map[string]int{
	"none":     0,
	"filtered": 1,
	"full":     2,
}

// MergePolicy produces a ResolvedPolicy from an AgentConfig and a ProfileConfig.
//
// Filesystem mode: min(agent, profile_inferred_mode) — most restrictive wins.
// Network rules: profile is the sole source of runtime rules (TR16).
// Toolchains: intersection.
// CLI overrides in opts bypass intersection unconditionally (FR17).
func MergePolicy(agent *config.AgentConfig, profile *config.ProfileConfig, opts MergeOptions) (*ResolvedPolicy, error) {
	rp := &ResolvedPolicy{
		AgentName:       agent.Name,
		ProfileName:     profile.Name,
		Mode:            opts.Mode,
		Workdir:         profile.Workdir,
		MitmDomains:     profile.MitmDomains,
		CLIExtraPaths:   append([]string(nil), opts.ExtraPaths...),
		CLIExtraDomains: append([]string(nil), opts.ExtraDomains...),
	}
	if rp.Mode == "" {
		rp.Mode = "enforcing"
	}

	// --- Filesystem mode: min(agent, profile inferred) ---
	profileFSMode := inferProfileFilesystemMode(profile)
	rp.FilesystemMode = minFilesystemMode(agent.Filesystem, profileFSMode)

	// --- Concrete paths: intersection with capability hierarchy ---
	// Profile write/exec grants imply read (FR1.12).
	profileReadGrants := dedupe(append(append(append([]string(nil), profile.Read...), profile.Write...), profile.Exec...))
	rp.Read = intersectFilesystemPaths(agent.Read, profileReadGrants, agent.Filesystem, "read-only")
	rp.Write = intersectFilesystemPaths(agent.Write, profile.Write, agent.Filesystem, "read-write")
	rp.Exec = intersectFilesystemPaths(agent.Exec, profile.Exec, agent.Filesystem, "read-write")

	// --- Network: profile is sole runtime authority (TR16) ---
	profileNetMode := inferProfileNetworkMode(profile)
	rp.NetworkMode = minNetworkMode(agent.NetworkMode, profileNetMode)
	if profile.Network != nil {
		rp.ProxyACLs = profile.Network.Domains
	}
	rp.AllowedDomains = append([]string(nil), profile.AllowedDomains...)

	// --- Toolchains: intersection ---
	rp.Toolchains = intersectStrings(agent.Toolchains, profile.Toolchains)

	// --- Compile-time validation ---
	warnings, err := validateAgentVsProfile(agent, profile, opts.Strict)
	if err != nil {
		return nil, err
	}
	rp.Warnings = warnings

	return rp, nil
}

// inferProfileFilesystemMode derives the profile's abstract filesystem mode
// from its concrete path grants.
func inferProfileFilesystemMode(profile *config.ProfileConfig) string {
	if len(profile.Write) > 0 || len(profile.Exec) > 0 {
		return "read-write"
	}
	if len(profile.Read) > 0 {
		return "read-only"
	}
	return "none"
}

// inferProfileNetworkMode returns "filtered" if the profile has any network
// configuration, "none" otherwise.
func inferProfileNetworkMode(profile *config.ProfileConfig) string {
	if len(profile.AllowedDomains) > 0 {
		return "filtered"
	}
	if profile.Network != nil && len(profile.Network.Domains) > 0 {
		return "filtered"
	}
	return "none"
}

// minFilesystemMode returns the less permissive of two filesystem modes.
func minFilesystemMode(a, b string) string {
	la, lb := filesystemLevel[a], filesystemLevel[b]
	if la <= lb {
		return a
	}
	return b
}

// minNetworkMode returns the less permissive of two network modes.
func minNetworkMode(a, b string) string {
	la, lb := networkLevel[a], networkLevel[b]
	if la <= lb {
		return a
	}
	return b
}

// intersectFilesystemPaths computes the paths to include in the ResolvedPolicy
// for a given access type. agentMode is the agent's abstract filesystem mode;
// requiredMode is the minimum mode needed for this access type.
//
// If the agent has no concrete paths but its abstract mode permits the access,
// the profile's granted paths are used. If the agent has concrete paths, those
// are filtered to only include paths covered by the grants.
func intersectFilesystemPaths(agentPaths, grantedPaths []string, agentMode, requiredMode string) []string {
	if filesystemLevel[agentMode] < filesystemLevel[requiredMode] {
		return nil // agent doesn't request this access level
	}
	if len(grantedPaths) == 0 {
		return nil // profile grants nothing for this access type
	}
	if len(agentPaths) == 0 {
		// Agent has abstract mode, no concrete paths → use all profile grants.
		return append([]string(nil), grantedPaths...)
	}
	return intersectPaths(agentPaths, grantedPaths)
}

// intersectPaths returns paths that are "covered by" counterparts in the
// other list, using directory-prefix semantics.
//
// For each (agentPath, grantPath) pair:
//   - If grantPath covers agentPath (grant is broader or equal): include agentPath
//   - If agentPath covers grantPath (agent is broader): include grantPath
func intersectPaths(requested, granted []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, req := range requested {
		for _, grant := range granted {
			if pathCovers(grant, req) {
				// Grant is at least as broad as request → include request.
				if !seen[req] {
					result = append(result, req)
					seen[req] = true
				}
				break
			}
			if pathCovers(req, grant) {
				// Request is broader → include the more specific grant.
				if !seen[grant] {
					result = append(result, grant)
					seen[grant] = true
				}
			}
		}
	}
	return result
}

// pathCovers returns true if parent is a directory-ancestor of (or equal to) child.
// Both paths should be absolute or both relative for this to be meaningful.
func pathCovers(parent, child string) bool {
	p := filepath.Clean(parent)
	c := filepath.Clean(child)
	if p == c {
		return true
	}
	return strings.HasPrefix(c, p+string(filepath.Separator))
}

// intersectStrings returns the set intersection of two string slices.
func intersectStrings(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	var result []string
	for _, s := range a {
		if set[s] {
			result = append(result, s)
		}
	}
	return result
}

// dedupe removes duplicate strings while preserving order.
func dedupe(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// validateAgentVsProfile checks that the agent's declared capabilities are
// satisfied by the profile's grants, producing warnings (or errors if strict).
// This implements compile-time validation (stage [7] of the pipeline).
func validateAgentVsProfile(agent *config.AgentConfig, profile *config.ProfileConfig, strict bool) ([]string, error) {
	var warnings []string

	warn := func(msg string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(msg, args...))
	}

	// Validate filesystem paths: check agent's concrete requests against profile grants.
	// Profile write/exec imply read (FR1.12).
	allProfileReads := dedupe(append(append(append([]string(nil), profile.Read...), profile.Write...), profile.Exec...))

	for _, p := range agent.Read {
		if !isCoveredByAny(p, allProfileReads) {
			warn("agent %q requests read access to %q but profile %q does not grant it",
				agent.Name, p, profile.Name)
		}
	}
	for _, p := range agent.Write {
		if !isCoveredByAny(p, profile.Write) {
			warn("agent %q requests write access to %q but profile %q does not grant it",
				agent.Name, p, profile.Name)
		}
	}
	for _, p := range agent.Exec {
		if !isCoveredByAny(p, profile.Exec) {
			warn("agent %q requests exec access to %q but profile %q does not grant it",
				agent.Name, p, profile.Name)
		}
	}

	// Validate network: check agent's requested domains against profile grants.
	if agent.Network != nil {
		for _, d := range agent.Network.Domains {
			if !isDomainGranted(d.Pattern, profile) {
				warn("agent %q requests access to domain %q but profile %q does not grant it",
					agent.Name, d.Pattern, profile.Name)
			}
		}
	}

	if strict && len(warnings) > 0 {
		return nil, fmt.Errorf("compile-time validation failed (--strict): %s", strings.Join(warnings, "; "))
	}
	return warnings, nil
}

// isCoveredByAny returns true if path is covered by at least one path in grants.
func isCoveredByAny(path string, grants []string) bool {
	for _, g := range grants {
		if pathCovers(g, path) {
			return true
		}
	}
	return false
}

// isDomainGranted returns true if the domain pattern is covered by the profile's
// network grants (AllowedDomains or network block).
func isDomainGranted(pattern string, profile *config.ProfileConfig) bool {
	for _, d := range profile.AllowedDomains {
		if domainCovers(d, pattern) {
			return true
		}
	}
	if profile.Network != nil {
		for _, d := range profile.Network.Domains {
			if domainCovers(d.Pattern, pattern) {
				return true
			}
		}
	}
	return false
}

// domainCovers returns true if grantPattern covers requestPattern.
// This is a simple prefix/glob check for domain names.
func domainCovers(grant, request string) bool {
	if grant == request || grant == "*" || grant == "**" {
		return true
	}
	// "*.npmjs.org" covers "registry.npmjs.org"
	if strings.HasPrefix(grant, "*.") {
		suffix := grant[1:] // ".npmjs.org"
		return strings.HasSuffix(request, suffix) && !strings.Contains(strings.TrimSuffix(request, suffix), ".")
	}
	// "**.example.com" covers any depth
	if strings.HasPrefix(grant, "**.") {
		suffix := grant[2:] // ".example.com"
		return strings.HasSuffix(request, suffix)
	}
	return false
}
