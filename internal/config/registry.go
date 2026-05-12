package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Registry indexes agent and profile configs across global, repo-wide, and
// project-scoped directories. It implements FR8-FR12 name resolution semantics.
//
// Resolution scopes, in precedence order (most-specific wins):
//   1. Per-repo               <gitRoot>/.rampart/
//   2. User-supplied global   first entry in globalDirs that exists
//      (typically ~/.local/share/rampart/) — rampart never writes here;
//      this is where the user puts custom or override modules
//   3. System-installed       remaining globalDirs entries, e.g.
//      /opt/shaheengandhi/share/rampart/ — the canonical install
//      location for the rampart-shipped library, populated by
//      `just install rampart`
//   4. Bundled (fs.FS)        last-resort fallback for `go install`
//      users who have no on-disk library; pulled directly from the
//      binary's embedded assets
type Registry struct {
	// agents maps qualified names ("project/name" or bare "name") to AgentConfig.
	// Bare names key on the simple name; qualified names key on "project/name".
	agents   map[string]*AgentConfig
	profiles map[string]*ProfileConfig
	defaults *DefaultsConfig

	gitRoot    string
	globalDirs []string
	rampartDir string

	// bundled is the binary's embedded library, used only when no entry
	// in globalDirs has the requested module/agent. Tests pass nil.
	bundled fs.FS
}

// NewRegistry builds a registry with a single user-global directory and no
// bundled fallback. Most callers should prefer NewRegistryWithBundled,
// which supports the full search chain.
func NewRegistry(gitRoot, globalDir string) (*Registry, error) {
	dirs := []string(nil)
	if globalDir != "" {
		dirs = []string{globalDir}
	}
	return NewRegistryFromDirs(gitRoot, dirs, nil)
}

// NewRegistryWithBundled is NewRegistry plus a fallback fs.FS for the
// rampart-shipped bundled library. Kept for callers that already pass a
// single globalDir; the search chain still uses just that one dir.
func NewRegistryWithBundled(gitRoot, globalDir string, bundled fs.FS) (*Registry, error) {
	dirs := []string(nil)
	if globalDir != "" {
		dirs = []string{globalDir}
	}
	return NewRegistryFromDirs(gitRoot, dirs, bundled)
}

// NewRegistryFromDirs builds a registry against an ordered list of
// global search directories plus an optional bundled fs.FS fallback.
// Order in globalDirs is precedence: earlier dirs shadow later ones.
// Typical production wiring (in priority order):
//
//	dirs := []string{
//	    "~/.local/share/rampart",                    // user overrides
//	    "/opt/shaheengandhi/share/rampart",          // system install
//	}
func NewRegistryFromDirs(gitRoot string, globalDirs []string, bundled fs.FS) (*Registry, error) {
	r := &Registry{
		agents:     make(map[string]*AgentConfig),
		profiles:   make(map[string]*ProfileConfig),
		gitRoot:    gitRoot,
		globalDirs: globalDirs,
		bundled:    bundled,
	}
	if gitRoot != "" {
		r.rampartDir = filepath.Join(gitRoot, ".rampart")
	}

	// Index in precedence order. registerAgent's "first to claim a bare
	// name at a given scope wins" rule means earlier indexers shadow
	// later ones at the same scope, so we walk globalDirs forward
	// (user override first, system install second), then fall through
	// to the bundled embed.FS. Repo runs last because scopeRepo
	// overrides scopeGlobal via the scope-comparison path.
	for _, dir := range r.globalDirs {
		if err := r.indexAgentDir(dir, "", scopeGlobal); err != nil {
			return nil, err
		}
	}
	if err := r.indexBundled(); err != nil {
		return nil, err
	}
	if err := r.indexRepo(); err != nil {
		return nil, err
	}
	if err := r.indexProjects(); err != nil {
		return nil, err
	}
	if err := r.loadDefaults(); err != nil {
		return nil, err
	}
	return r, nil
}

// ResolveAgent resolves an agent by name (bare or "project/name").
// Returns an error if not found; never falls through project scope to repo/global.
func (r *Registry) ResolveAgent(name string) (*AgentConfig, error) {
	if a, ok := r.agents[name]; ok {
		return a, nil
	}
	if strings.Contains(name, "/") {
		return nil, fmt.Errorf("agent %q not found in project scope (no fallthrough to repo or global)", name)
	}
	return nil, fmt.Errorf("agent %q not found in any scope", name)
}

// ResolveProfile resolves a profile by name ("project/name", "project/default",
// "project" as shorthand for "project/default", or bare "name"). When the
// resolved profile has an `extends` attribute, the parent profile is
// recursively resolved and its grants merged in. Cycles are rejected.
func (r *Registry) ResolveProfile(name string) (*ProfileConfig, error) {
	return r.resolveProfile(name, map[string]bool{})
}

// resolveProfile is the inner recursive form. visiting tracks the chain of
// profile names currently being resolved (to detect inheritance cycles).
func (r *Registry) resolveProfile(name string, visiting map[string]bool) (*ProfileConfig, error) {
	p, err := r.lookupProfile(name)
	if err != nil {
		return nil, err
	}
	if p.Extends == "" {
		return p, nil
	}
	if visiting[name] {
		return nil, fmt.Errorf("profile inheritance cycle through %q", name)
	}
	visiting[name] = true
	parent, err := r.resolveProfile(p.Extends, visiting)
	if err != nil {
		return nil, fmt.Errorf("resolving parent of %q (extends = %q): %w", name, p.Extends, err)
	}
	merged := mergeInheritedProfile(parent, p)
	if merged.Workdir == "" {
		return nil, fmt.Errorf("profile %q: workdir is required (parent %q did not supply one either)", name, p.Extends)
	}
	return merged, nil
}

// lookupProfile is the bare lookup that ResolveProfile / resolveProfile
// share — no extends handling.
func (r *Registry) lookupProfile(name string) (*ProfileConfig, error) {
	if p, ok := r.profiles[name]; ok {
		return p, nil
	}
	if !strings.Contains(name, "/") {
		if p, ok := r.profiles[name+"/default"]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("profile %q not found", name)
	}
	project, pname, _ := strings.Cut(name, "/")
	if pname == "default" {
		shorthandKey := "shorthand:" + project
		if p, ok := r.profiles[shorthandKey]; ok {
			return p, nil
		}
	}
	return nil, fmt.Errorf("profile %q not found in project scope", name)
}

// mergeInheritedProfile produces a new ProfileConfig that overlays child on
// top of parent. Child's identity (Name, SourceFile) is preserved; path
// lists are concatenated then deduped; workdir uses child if set else
// parent; no_tls_mitm is OR'd; network domains are concatenated.
func mergeInheritedProfile(parent, child *ProfileConfig) *ProfileConfig {
	merged := *child
	merged.Read = dedupAppend(parent.Read, child.Read)
	merged.Write = dedupAppend(parent.Write, child.Write)
	merged.Exec = dedupAppend(parent.Exec, child.Exec)
	merged.AllowedDomains = dedupAppend(parent.AllowedDomains, child.AllowedDomains)
	merged.MitmDomains = dedupAppend(parent.MitmDomains, child.MitmDomains)
	merged.Toolchains = dedupAppend(parent.Toolchains, child.Toolchains)
	if merged.Workdir == "" {
		merged.Workdir = parent.Workdir
	}
	merged.NoTLSMITM = parent.NoTLSMITM || child.NoTLSMITM
	if parent.Network != nil || child.Network != nil {
		merged.Network = &NetworkConfig{}
		if parent.Network != nil {
			merged.Network.Domains = append(merged.Network.Domains, parent.Network.Domains...)
		}
		if child.Network != nil {
			merged.Network.Domains = append(merged.Network.Domains, child.Network.Domains...)
		}
	}
	// Use blocks have already been expanded into the path lists at index
	// time, so there's nothing more to merge from `Use` itself.
	merged.Extends = "" // no longer relevant on the merged result
	return &merged
}

// AgentInfo describes a registered agent for listing/inspection. A single
// underlying AgentConfig may be reachable under multiple resolution names
// (e.g. a project agent registered as both "myproj/coding" and the bare
// "coding" alias) — those are reported together in Aliases.
type AgentInfo struct {
	Aliases    []string // all resolution names, sorted; Aliases[0] is the canonical display name
	SourceFile string
}

// ProfileInfo describes a registered profile. Internal shorthand keys
// (used by ResolveProfile to back the bare "project" form for shorthand
// .rampart/<project>.hcl files) are filtered out.
type ProfileInfo struct {
	Aliases    []string // all resolution names, sorted; Aliases[0] is the canonical display name
	SourceFile string
}

// ListAgents returns every registered agent, deduplicated by underlying
// config pointer. Aliases within an entry are sorted; the slice itself is
// sorted by the canonical (first) alias.
func (r *Registry) ListAgents() []AgentInfo {
	byPtr := map[*AgentConfig][]string{}
	for k, a := range r.agents {
		byPtr[a] = append(byPtr[a], k)
	}
	out := make([]AgentInfo, 0, len(byPtr))
	for a, keys := range byPtr {
		sort.Strings(keys)
		out = append(out, AgentInfo{Aliases: keys, SourceFile: a.SourceFile})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Aliases[0] < out[j].Aliases[0]
	})
	return out
}

// ListProfiles returns every registered profile, deduplicated by underlying
// config pointer. The internal "shorthand:<project>" keys are excluded.
func (r *Registry) ListProfiles() []ProfileInfo {
	byPtr := map[*ProfileConfig][]string{}
	for k, p := range r.profiles {
		if strings.HasPrefix(k, "shorthand:") {
			continue
		}
		byPtr[p] = append(byPtr[p], k)
	}
	out := make([]ProfileInfo, 0, len(byPtr))
	for p, keys := range byPtr {
		sort.Strings(keys)
		out = append(out, ProfileInfo{Aliases: keys, SourceFile: p.SourceFile})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Aliases[0] < out[j].Aliases[0]
	})
	return out
}

// DefaultAgent returns the default agent name from defaults.hcl (may be "").
func (r *Registry) DefaultAgent() string {
	if r.defaults != nil {
		return r.defaults.DefaultAgent
	}
	return ""
}

// DefaultProfile returns the default profile name from defaults.hcl (may be "").
func (r *Registry) DefaultProfile() string {
	if r.defaults != nil {
		return r.defaults.DefaultProfile
	}
	return ""
}

// --- internal indexing ---

// indexBundled scans the rampart-shipped embedded fs.FS for agents. These
// are the rampart-bundled defaults (e.g. coding/planning/reviewing); they
// can be shadowed by anything later in the indexing order. No-op when no
// bundled fs was supplied.
func (r *Registry) indexBundled() error {
	if r.bundled == nil {
		return nil
	}

	// Multi-agent file: assets/agents.hcl.
	if src, err := fs.ReadFile(r.bundled, "assets/agents.hcl"); err == nil {
		agents, err := ParseAgentFile("bundled:agents.hcl", src)
		if err != nil {
			return err
		}
		for _, a := range agents {
			r.registerAgent(a, "", scopeGlobal)
		}
	}

	// Individual agents under assets/agents/<name>.hcl.
	entries, err := fs.ReadDir(r.bundled, "assets/agents")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".hcl") {
				continue
			}
			rel := "assets/agents/" + e.Name()
			src, readErr := fs.ReadFile(r.bundled, rel)
			if readErr != nil {
				return fmt.Errorf("reading bundled %s: %w", rel, readErr)
			}
			agents, parseErr := ParseAgentFile("bundled:"+rel, src)
			if parseErr != nil {
				return parseErr
			}
			for _, a := range agents {
				r.registerAgent(a, "", scopeGlobal)
			}
		}
	}
	return nil
}

// indexGlobal is a legacy no-op kept so existing test fixtures and any
// out-of-tree callers don't break. The actual global-dir indexing is
// done in NewRegistryFromDirs, which walks globalDirs in reverse-
// precedence order so the user-override layer wins over the system-
// install layer.
func (r *Registry) indexGlobal() error { return nil }

// indexRepo scans <git-root>/.rampart/ for repo-wide agents and profiles.
func (r *Registry) indexRepo() error {
	if r.rampartDir == "" {
		return nil
	}
	if err := r.indexAgentDir(r.rampartDir, "", scopeRepo); err != nil {
		return err
	}
	return nil
}

// indexProjects scans each <git-root>/.rampart/profiles/<project>/ directory
// and shorthand .rampart/<project>.hcl files.
func (r *Registry) indexProjects() error {
	if r.rampartDir == "" {
		return nil
	}

	// Scan profiles/ subdirectories.
	profilesDir := filepath.Join(r.rampartDir, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading profiles dir %s: %w", profilesDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		project := e.Name()
		projectDir := filepath.Join(profilesDir, project)
		if err := r.indexAgentDir(projectDir, project, scopeProject); err != nil {
			return err
		}
		if err := r.indexProfileDir(projectDir, project); err != nil {
			return err
		}
	}

	// Scan shorthand profiles: .rampart/<project>.hcl
	shorthands, err := filepath.Glob(filepath.Join(r.rampartDir, "*.hcl"))
	if err != nil {
		return err
	}
	for _, path := range shorthands {
		base := filepath.Base(path)
		if base == "agents.hcl" || base == "defaults.hcl" {
			continue
		}
		project := strings.TrimSuffix(base, ".hcl")
		if err := r.indexProfileFile(path, project, "default", true); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) loadDefaults() error {
	if r.rampartDir == "" {
		return nil
	}
	path := filepath.Join(r.rampartDir, "defaults.hcl")
	src, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	d, err := ParseDefaultsFile(path, src)
	if err != nil {
		return err
	}
	r.defaults = d
	return nil
}

type scope int

const (
	scopeGlobal  scope = iota
	scopeRepo
	scopeProject
)

// indexAgentDir indexes agents.hcl and agents/<name>.hcl within dir.
// If project is "", agents are indexed by bare name. Otherwise by "project/name".
// Higher-scope calls index first and lower-scope calls overwrite (project wins over repo wins over global).
func (r *Registry) indexAgentDir(dir, project string, s scope) error {
	// Multi-agent file: agents.hcl in dir.
	multiFile := filepath.Join(dir, "agents.hcl")
	if src, err := os.ReadFile(multiFile); err == nil {
		agents, err := ParseAgentFile(multiFile, src)
		if err != nil {
			return err
		}
		for _, a := range agents {
			r.registerAgent(a, project, s)
		}
	}

	// Individual files: agents/<name>.hcl.
	agentsSubdir := filepath.Join(dir, "agents")
	entries, err := os.ReadDir(agentsSubdir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading agents dir %s: %w", agentsSubdir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".hcl") {
			continue
		}
		path := filepath.Join(agentsSubdir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		agents, err := ParseAgentFile(path, src)
		if err != nil {
			return err
		}
		for _, a := range agents {
			r.registerAgent(a, project, s)
		}
	}
	return nil
}

func (r *Registry) registerAgent(a *AgentConfig, project string, s scope) {
	if project == "" {
		// Bare name — repo-wide or global.
		// Higher scope overwrites lower scope (project > repo > global).
		if existing, ok := r.agents[a.Name]; ok {
			if agentScope(existing) >= s {
				return // existing is higher priority
			}
		}
		a.SourceFile = physicalPath(a.SourceFile)
		r.agents[a.Name] = a
	} else {
		// Qualified name — project-scoped only.
		key := project + "/" + a.Name
		a.SourceFile = physicalPath(a.SourceFile)
		r.agents[key] = a
		// Also register bare name only if not already claimed by repo/project scope.
		if _, ok := r.agents[a.Name]; !ok {
			r.agents[a.Name] = a
		}
	}
}

func agentScope(a *AgentConfig) scope {
	// Heuristic: project-scoped agents have qualified keys — this is called
	// only for bare-name collision resolution. In practice the caller guards.
	return scopeGlobal // lowest; repo/project already stored under their own key
}

// indexProfileDir scans a project directory for profile HCL files.
func (r *Registry) indexProfileDir(projectDir, project string) error {
	entries, err := os.ReadDir(projectDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading project dir %s: %w", projectDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".hcl") {
			continue
		}
		profileName := strings.TrimSuffix(e.Name(), ".hcl")
		path := filepath.Join(projectDir, e.Name())
		if err := r.indexProfileFile(path, project, profileName, false); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) indexProfileFile(path, project, profileName string, isShorthand bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	profiles, err := ParseProfileFile(path, src)
	if err != nil {
		return err
	}
	for _, p := range profiles {
		p.SourceFile = physicalPath(p.SourceFile)
		// Expand `use` blocks transitively against the module search path.
		// The expander concatenates contributions and dedups path lists.
		// Failure here is reported as a profile load error.
		if len(p.Use) > 0 {
			frag, err := ExpandUseBlocksFromDirs(p.Use, r.gitRoot, r.globalDirs, r.bundled, nil)
			if err != nil {
				return fmt.Errorf("%s: profile %q: %w", path, p.Name, err)
			}
			MergeFragmentIntoProfile(p, frag)
		}
		key := project + "/" + p.Name
		r.profiles[key] = p
		if isShorthand {
			// Shorthand .rampart/<project>.hcl → accessible as "project/default".
			r.profiles["shorthand:"+project] = p
		}
	}
	return nil
}

// physicalPath resolves symlinks in a file path to get the real path.
// Falls back to the original path if EvalSymlinks fails.
func physicalPath(path string) string {
	if path == "" {
		return path
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return real
}

// FindGitRoot walks parent directories from start until a .git entry is found.
// Returns the directory containing .git, or "" if not found.
func FindGitRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// GlobalShareDir returns ~/.local/share/rampart on Linux/macOS.
func GlobalShareDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "rampart")
}
