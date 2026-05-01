package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Registry indexes agent and profile configs across global, repo-wide, and
// project-scoped directories. It implements FR8-FR12 name resolution semantics.
type Registry struct {
	// agents maps qualified names ("project/name" or bare "name") to AgentConfig.
	// Bare names key on the simple name; qualified names key on "project/name".
	agents   map[string]*AgentConfig
	profiles map[string]*ProfileConfig
	defaults *DefaultsConfig

	gitRoot    string
	globalDir  string
	rampartDir string
}

// NewRegistry builds a registry by scanning all three scopes. Pass:
//   - gitRoot: path to the git repository root (may be "" if not in a repo)
//   - globalDir: path to ~/.local/share/rampart/ (may be "" to skip)
func NewRegistry(gitRoot, globalDir string) (*Registry, error) {
	r := &Registry{
		agents:     make(map[string]*AgentConfig),
		profiles:   make(map[string]*ProfileConfig),
		gitRoot:    gitRoot,
		globalDir:  globalDir,
	}
	if gitRoot != "" {
		r.rampartDir = filepath.Join(gitRoot, ".rampart")
	}

	if err := r.indexGlobal(); err != nil {
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
// "project" as shorthand for "project/default", or bare "name").
func (r *Registry) ResolveProfile(name string) (*ProfileConfig, error) {
	if p, ok := r.profiles[name]; ok {
		return p, nil
	}

	// "project" with no slash: try "project/default".
	if !strings.Contains(name, "/") {
		if p, ok := r.profiles[name+"/default"]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("profile %q not found", name)
	}

	// Qualified: "project/name" — if the name part is "default", we've already
	// tried the canonical key; try the shorthand file .rampart/<project>.hcl.
	project, pname, _ := strings.Cut(name, "/")
	if pname == "default" {
		shorthandKey := "shorthand:" + project
		if p, ok := r.profiles[shorthandKey]; ok {
			return p, nil
		}
	}
	return nil, fmt.Errorf("profile %q not found in project scope", name)
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

// indexGlobal scans ~/.local/share/rampart/ for agents. Bare name wins here
// only if not already claimed by repo-wide or project scope (repo/project
// are indexed after global, overwriting).
func (r *Registry) indexGlobal() error {
	if r.globalDir == "" {
		return nil
	}
	return r.indexAgentDir(r.globalDir, "", scopeGlobal)
}

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
