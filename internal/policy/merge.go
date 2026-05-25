package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
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
// CLI overrides in opts bypass intersection unconditionally (FR17).
func MergePolicy(agent *config.AgentConfig, profile *config.ProfileConfig, opts MergeOptions) (*ResolvedPolicy, error) {
	rp := &ResolvedPolicy{
		AgentName:       agent.Name,
		ProfileName:     profile.Name,
		Mode:            opts.Mode,
		Workdir:         profile.Workdir,
		MitmDomains:     profile.MitmDomains,
		NoTLSMITM:       profile.NoTLSMITM,
		CLIExtraPaths:   append([]string(nil), opts.ExtraPaths...),
		CLIExtraDomains: append([]string(nil), opts.ExtraDomains...),
		CLIExtraEnv:     append([]string(nil), opts.ExtraEnv...),
	}
	if opts.NoTLSMITM != nil {
		rp.NoTLSMITM = *opts.NoTLSMITM
	}
	if rp.Mode == "" {
		rp.Mode = "enforcing"
	}

	// --- Filesystem mode: min(agent inferred, profile inferred) ---
	agentFSMode := inferAgentFilesystemMode(agent)
	profileFSMode := inferProfileFilesystemMode(profile)
	rp.FilesystemMode = minFilesystemMode(agentFSMode, profileFSMode)

	// --- Concrete paths: intersection with capability hierarchy ---
	// Profile write/exec grants imply read (FR1.12).
	profileReadGrants := dedupe(append(append(append([]string(nil), profile.Read...), profile.Write...), profile.Exec...))
	rp.Read = intersectFilesystemPaths(agent.Read, profileReadGrants, agentFSMode, "read-only")
	rp.Write = intersectFilesystemPaths(agent.Write, profile.Write, agentFSMode, "read-write")
	// Exec: split off ${VAR} placeholders — they get resolved against
	// the parent env at launch time by ResolveExecEnvRefs and then
	// coverage-checked against profile.Exec.
	execLiterals, execPlaceholders := splitExecEnvPlaceholders(agent.Exec)
	rp.Exec = intersectFilesystemPaths(execLiterals, profile.Exec, agentFSMode, "read-write")
	rp.execPlaceholders = execPlaceholders
	rp.profileExecGrants = append([]string(nil), profile.Exec...)

	// --- Network: profile is sole runtime authority (TR16) ---
	agentNetMode := inferAgentNetworkMode(agent)
	profileNetMode := inferProfileNetworkMode(profile)
	rp.NetworkMode = minNetworkMode(agentNetMode, profileNetMode)
	if profile.Network != nil {
		rp.ProxyACLs = profile.Network.Domains
	}
	rp.AllowedDomains = append([]string(nil), profile.AllowedDomains...)
	rp.UnixSockets = append([]string(nil), profile.UnixSockets...)

	// --- Env passthrough: agent⇄profile intersection with glob matching ---
	rp.Env = intersectEnvPatterns(agent.Env, profile.Env)

	// --- Compile-time validation ---
	warnings, err := validateAgentVsProfile(agent, profile, opts.Strict)
	if err != nil {
		return nil, err
	}
	rp.Warnings = warnings

	// --- no_tls_mitm: clear MitmDomains and warn if rules would be ignored ---
	if rp.NoTLSMITM {
		hadMitmDomains := len(rp.MitmDomains) > 0
		hadPathRules := profileHasPathRules(profile)
		rp.MitmDomains = nil
		if hadMitmDomains || hadPathRules {
			rp.Warnings = append(rp.Warnings, fmt.Sprintf(
				"profile %q: no_tls_mitm disables TLS interception; path rules and mitm_domains will not be enforced on HTTPS (HTTP is unaffected)",
				profile.Name))
		}
	}

	return rp, nil
}

// profileHasPathRules reports whether the profile's network block contains
// any allow/deny rule with a non-empty paths list. Such rules would otherwise
// auto-promote a domain to MITM in CompileACLRules; with no_tls_mitm they
// are silently dropped on HTTPS, so callers warn the user.
func profileHasPathRules(profile *config.ProfileConfig) bool {
	if profile.Network == nil {
		return false
	}
	for _, d := range profile.Network.Domains {
		for _, r := range d.Allow {
			if len(r.Paths) > 0 {
				return true
			}
		}
		for _, r := range d.Deny {
			if len(r.Paths) > 0 {
				return true
			}
		}
	}
	return false
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

// inferAgentFilesystemMode derives the agent's abstract filesystem mode
// from its concrete path requests. Symmetric with the profile rule —
// presence of any write/exec request infers read-write; presence of
// only reads infers read-only; nothing declared infers none.
//
// ${VAR} placeholders in Exec count as exec requests for mode
// inference even though they're not literal paths — the agent is
// still asking for an exec capability, just with deferred resolution.
func inferAgentFilesystemMode(agent *config.AgentConfig) string {
	if len(agent.Write) > 0 || len(agent.Exec) > 0 {
		return "read-write"
	}
	if len(agent.Read) > 0 {
		return "read-only"
	}
	return "none"
}

// inferProfileNetworkMode derives the profile's abstract network mode from
// its declarations:
//
//   - A bare wildcard ("*" or "**") with no path rules in either
//     allowed_domains or a network { domain "*" {} } block opts the profile
//     into "full" mode — the proxy can be skipped entirely on the platform
//     backend. This is the explicit "I want unrestricted network" knob.
//   - Any other allowed_domains entry, or any network { domain ... } block
//     (including a wildcard with method/path rules), produces "filtered" —
//     the proxy stays in the path and ACLs apply.
//   - Empty or no network config produces "none".
//
// "full" is honoured by the sandbox backends (Seatbelt and bwrap) by
// skipping the proxy injection step entirely; the agent's inferred
// mode can still be clamped down by the profile's mode.
func inferProfileNetworkMode(profile *config.ProfileConfig) string {
	hasFullDomain := false
	hasFilteredDomain := false

	for _, d := range profile.AllowedDomains {
		if d == "*" || d == "**" {
			hasFullDomain = true
		} else {
			hasFilteredDomain = true
		}
	}
	if profile.Network != nil {
		for _, d := range profile.Network.Domains {
			isWildcard := d.Pattern == "*" || d.Pattern == "**"
			hasRules := false
			for _, r := range d.Allow {
				if len(r.Paths) > 0 || r.Method != "" {
					hasRules = true
					break
				}
			}
			if !hasRules {
				for _, r := range d.Deny {
					if len(r.Paths) > 0 || r.Method != "" {
						hasRules = true
						break
					}
				}
			}
			if isWildcard && !hasRules {
				hasFullDomain = true
			} else {
				hasFilteredDomain = true
			}
		}
	}

	switch {
	case hasFilteredDomain:
		return "filtered"
	case hasFullDomain:
		return "full"
	default:
		return "none"
	}
}

// inferAgentNetworkMode derives the agent's abstract network mode from
// its declarations, with the same lattice as profiles:
//
//   - A bare wildcard ("*" or "**") in either `domains` or a
//     `network { domain "*" {} }` block (no path/method rules) opts
//     the agent into "full" — saying "I want unrestricted egress."
//   - Any other concrete domain entry (or a wildcard with method/path
//     rules) infers "filtered" — proxy in path, ACLs apply.
//   - Nothing declared infers "none".
func inferAgentNetworkMode(agent *config.AgentConfig) string {
	hasFullDomain := false
	hasFilteredDomain := false

	for _, d := range agent.Domains {
		if d == "*" || d == "**" {
			hasFullDomain = true
		} else {
			hasFilteredDomain = true
		}
	}
	if agent.Network != nil {
		for _, d := range agent.Network.Domains {
			isWildcard := d.Pattern == "*" || d.Pattern == "**"
			hasRules := false
			for _, r := range d.Allow {
				if len(r.Paths) > 0 || r.Method != "" {
					hasRules = true
					break
				}
			}
			if !hasRules {
				for _, r := range d.Deny {
					if len(r.Paths) > 0 || r.Method != "" {
						hasRules = true
						break
					}
				}
			}
			if isWildcard && !hasRules {
				hasFullDomain = true
			} else {
				hasFilteredDomain = true
			}
		}
	}

	switch {
	case hasFilteredDomain:
		return "filtered"
	case hasFullDomain:
		return "full"
	default:
		return "none"
	}
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
// The root path "/" covers every absolute path.
func pathCovers(parent, child string) bool {
	p := filepath.Clean(parent)
	c := filepath.Clean(child)
	if p == c {
		return true
	}
	// Root is parent of every absolute path. Filtering on
	// p+"/" would produce "//" which never prefix-matches.
	if p == string(filepath.Separator) && strings.HasPrefix(c, string(filepath.Separator)) {
		return true
	}
	return strings.HasPrefix(c, p+string(filepath.Separator))
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
		if execEnvPlaceholderRegex.MatchString(p) {
			// ${VAR} placeholders are coverage-checked at resolution
			// time (when we know the literal value), not here.
			continue
		}
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

	// Validate env: every var referenced in agent.Exec via ${VAR} must
	// appear in agent.Env, and the agent's Env requests must be permitted
	// by profile.Env. Two failure modes, distinct messages.
	for _, ref := range referencedEnvVars(agent.Exec) {
		if !envPatternListMatches(agent.Env, ref) {
			warn("agent %q exec entry references ${%s} but %s is not declared in agent env",
				agent.Name, ref, ref)
		}
	}
	for _, e := range agent.Env {
		if !envPatternListCovers(profile.Env, e) {
			warn("agent %q requests env passthrough for %q but profile %q does not grant it",
				agent.Name, e, profile.Name)
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

// envPatternRegex matches a `${VAR}` reference in an exec entry. VAR
// must follow shell conventions: start with letter or underscore,
// continue with letters/digits/underscores.
var envPatternRegex = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// execEnvPlaceholderRegex matches an exec entry whose entire value
// is a single `${VAR}` reference. The ResolveExecEnvRefs step
// recognises these as deferred lookups; everything else is a literal
// path that flows through path intersection at merge time.
var execEnvPlaceholderRegex = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

// splitExecEnvPlaceholders separates literal exec entries from
// `${VAR}` placeholders, preserving order within each bucket.
func splitExecEnvPlaceholders(execEntries []string) (literals, placeholders []string) {
	for _, e := range execEntries {
		if execEnvPlaceholderRegex.MatchString(e) {
			placeholders = append(placeholders, e)
		} else {
			literals = append(literals, e)
		}
	}
	return
}

// referencedEnvVars returns the deduplicated names of env vars
// referenced via ${VAR} in any of the given exec entries. Preserves
// first-occurrence order so warning output is deterministic.
func referencedEnvVars(execEntries []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, entry := range execEntries {
		for _, match := range envPatternRegex.FindAllStringSubmatch(entry, -1) {
			name := match[1]
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// envPatternListMatches reports whether some pattern in `patterns`
// matches the concrete env-var name `name`. Used for "is this VAR
// declared in agent.Env" checks.
func envPatternListMatches(patterns []string, name string) bool {
	for _, p := range patterns {
		if envPatternMatches(p, name) {
			return true
		}
	}
	return false
}

// envPatternListCovers reports whether some pattern in `grants`
// covers the request pattern `req`. "Cover" means: every concrete
// var name that matches `req` would also match the grant. The two
// directions used here:
//   - exact equality of patterns ("EDITOR" covers "EDITOR";
//     "LC_*" covers "LC_*");
//   - a grant glob covers a more-specific request: "LC_*" covers
//     "LC_ALL"; "LC_*" covers "LC_TIME_*" (because every name
//     matching the request would also match the grant).
func envPatternListCovers(grants []string, req string) bool {
	for _, g := range grants {
		if envPatternCovers(g, req) {
			return true
		}
	}
	return false
}

// envPatternMatches reports whether a concrete env-var `name` matches
// `pattern`. Env names are flat; the grammar is "exact literal" or
// "literal prefix followed by trailing `*`" (e.g. "LC_*" matches any
// name starting with "LC_"). The validator at parse time guarantees
// this shape.
func envPatternMatches(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(name, prefix)
	}
	return false
}

// envPatternCovers reports whether grant-pattern `g` covers
// request-pattern `r`. Both may be literal or `PREFIX*` form.
func envPatternCovers(g, r string) bool {
	if g == r {
		return true
	}
	gIsGlob := strings.HasSuffix(g, "*")
	rIsGlob := strings.HasSuffix(r, "*")
	switch {
	case !rIsGlob:
		// Literal request: grant must match it directly.
		return envPatternMatches(g, r)
	case gIsGlob:
		// Both globs: grant covers request iff grant's prefix is a
		// prefix of request's prefix ("LC_*" covers "LC_T*").
		return strings.HasPrefix(r[:len(r)-1], g[:len(g)-1])
	default:
		// Glob request, literal grant: not covered — the request is
		// broader than the grant.
		return false
	}
}

// intersectEnvPatterns returns the set intersection of two env pattern
// lists with glob coverage semantics. An agent pattern is kept iff it
// is covered by some profile pattern; a profile glob that matches an
// agent literal is kept under the agent's literal form (more specific
// representation wins).
func intersectEnvPatterns(agentPatterns, profilePatterns []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range agentPatterns {
		if envPatternListCovers(profilePatterns, a) {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}
