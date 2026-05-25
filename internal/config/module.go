package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// ModuleFile is the parsed top-level body of a module .hcl file. A module
// has zero or more variable declarations (parameters), zero or more nested
// `use` blocks (transitive composition), and the same path/network grant
// shape as a profile fragment.
type ModuleFile struct {
	// Path is the absolute filesystem path the module was loaded from.
	// Used for cycle detection and error messages.
	Path string

	// RelName is the relative path under the search root that resolved this
	// module (e.g. "lang/python"). Used in diagnostics.
	RelName string

	// Variables declared by `variable "name" { ... }` blocks at file scope.
	Variables []*ModuleVariable

	// Use blocks declared at file scope; resolved transitively by the
	// expander.
	Use []*UseBlock

	// fragmentBody is the remaining HCL body after `variable` and `use`
	// blocks are extracted. It contains the path lists and network block
	// and is decoded against the consumer's EvalContext at expansion time.
	fragmentBody hcl.Body

	// fragmentRange covers the source range of the file body, used for
	// diagnostics that don't have a more specific location.
	fragmentRange hcl.Range
}

// ModuleVariable is a `variable "name" { type = ..., default = ... }` block.
type ModuleVariable struct {
	// Name is the block's label.
	Name string

	// TypeExpr is the parsed type expression. Supported in v1: string,
	// list(string).
	TypeExpr cty.Type

	// HasDefault is true when the user wrote a default attribute.
	HasDefault bool

	// Default is the default value, already converted to TypeExpr. Only
	// valid when HasDefault is true.
	Default cty.Value

	// Description is the optional human-readable description.
	Description string

	// DeclRange is the source range of the variable block, for diagnostics.
	DeclRange hcl.Range
}

// UseBlock is a `use "<path>" { args }` declaration. Args are held as raw
// HCL bodies and evaluated against the *consumer's* EvalContext at
// expansion time, so values can flow from one module to another via
// `use "child" { foo = var.bar }`.
type UseBlock struct {
	// ModulePath is the relative path label of the use block.
	ModulePath string

	// ArgBody holds the use block's body for later attribute extraction.
	ArgBody hcl.Body

	// DeclRange is the use block's source range, used for diagnostics.
	DeclRange hcl.Range
}

// ModuleFragment is the result of expanding a single module instance.
// Multiple fragments concatenate into a host profile.
type ModuleFragment struct {
	Read           []string
	Write          []string
	Exec           []string
	AllowedDomains []string
	MitmDomains    []string
	UnixSockets    []string
	Env            []string
	NetworkDomains []DomainConfig
}

// isSupportedVariableType is the v1 allowlist of cty types that may appear
// in a `variable` block. Parsed from HCL via the typeexpr extension so
// `string`, `list(string)`, etc. read naturally. Other types parse cleanly
// but are rejected here so v1 stays narrow.
func isSupportedVariableType(t cty.Type) bool {
	if t == cty.String {
		return true
	}
	if t.IsListType() && t.ElementType() == cty.String {
		return true
	}
	return false
}

// ParseModuleFile parses a module HCL file and returns its ModuleFile.
// The relName argument is the module's relative path under its search root
// (e.g. "lang/python"); it is used in diagnostics. The absolute on-disk
// path goes in ModuleFile.Path for cycle detection.
func ParseModuleFile(absPath, relName string, src []byte) (*ModuleFile, error) {
	file, diags := hclsyntax.ParseConfig(src, absPath, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	mf := &ModuleFile{
		Path:          absPath,
		RelName:       relName,
		fragmentRange: hcl.Range{Filename: absPath, Start: hcl.Pos{Line: 1, Column: 1}, End: hcl.Pos{Line: 1, Column: 1}},
	}

	// First pass: extract `variable` and `use` blocks; everything else
	// (path attributes, network block, etc.) flows into `fragmentBody`
	// for later evaluation against an EvalContext.
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "variable", LabelNames: []string{"name"}},
			{Type: "use", LabelNames: []string{"path"}},
		},
	}
	content, fragmentBody, contentDiags := file.Body.PartialContent(schema)
	if contentDiags.HasErrors() {
		return nil, diagsToError(contentDiags)
	}
	mf.fragmentBody = fragmentBody

	for _, blk := range content.Blocks {
		switch blk.Type {
		case "variable":
			v, err := parseModuleVariable(blk)
			if err != nil {
				return nil, err
			}
			mf.Variables = append(mf.Variables, v)
		case "use":
			mf.Use = append(mf.Use, &UseBlock{
				ModulePath: blk.Labels[0],
				ArgBody:    blk.Body,
				DeclRange:  blk.DefRange,
			})
		}
	}

	if err := validateModuleVariables(mf); err != nil {
		return nil, err
	}

	return mf, nil
}

// parseModuleVariable decodes a single `variable "name" { ... }` block.
func parseModuleVariable(blk *hcl.Block) (*ModuleVariable, error) {
	v := &ModuleVariable{
		Name:      blk.Labels[0],
		DeclRange: blk.DefRange,
	}

	// Inner schema: type (required), default (optional), description (optional).
	innerSchema := &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "type", Required: true},
			{Name: "default", Required: false},
			{Name: "description", Required: false},
		},
	}
	content, diags := blk.Body.Content(innerSchema)
	if diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	// type — parsed via HCL's typeexpr extension so authors can write
	// `string`, `list(string)`, etc. naturally. v1 narrows the accepted
	// types via isSupportedVariableType so unsupported choices fail at
	// parse time rather than at use-site type conversion.
	typeAttr := content.Attributes["type"]
	t, typeDiags := typeexpr.TypeConstraint(typeAttr.Expr)
	if typeDiags.HasErrors() {
		return nil, diagsToError(typeDiags)
	}
	if !isSupportedVariableType(t) {
		return nil, fmt.Errorf("%s:%d: variable %q: unsupported type %s (v1 supports: string, list(string))",
			blk.DefRange.Filename, blk.DefRange.Start.Line, v.Name, typeexpr.TypeString(t))
	}
	v.TypeExpr = t

	if descAttr, ok := content.Attributes["description"]; ok {
		descVal, descDiags := descAttr.Expr.Value(nil)
		if descDiags.HasErrors() {
			return nil, diagsToError(descDiags)
		}
		if descVal.Type() != cty.String {
			return nil, fmt.Errorf("%s:%d: variable %q: description must be a string",
				blk.DefRange.Filename, blk.DefRange.Start.Line, v.Name)
		}
		v.Description = descVal.AsString()
	}

	if defAttr, ok := content.Attributes["default"]; ok {
		defVal, defDiags := defAttr.Expr.Value(nil)
		if defDiags.HasErrors() {
			return nil, diagsToError(defDiags)
		}
		converted, convErr := convert.Convert(defVal, v.TypeExpr)
		if convErr != nil {
			return nil, fmt.Errorf("%s:%d: variable %q: default does not match declared type %s: %v",
				blk.DefRange.Filename, blk.DefRange.Start.Line, v.Name, typeexpr.TypeString(v.TypeExpr), convErr)
		}
		v.HasDefault = true
		v.Default = converted
	}

	return v, nil
}

// validateModuleVariables checks for duplicate variable names within a
// module file.
func validateModuleVariables(mf *ModuleFile) error {
	seen := map[string]bool{}
	for _, v := range mf.Variables {
		if v.Name == "" {
			return fmt.Errorf("%s: variable block label must not be empty", mf.Path)
		}
		if seen[v.Name] {
			return fmt.Errorf("%s: duplicate variable %q", mf.Path, v.Name)
		}
		seen[v.Name] = true
	}
	return nil
}

// ResolveModulePath looks up a module name in the search-path list and
// returns the absolute path of the first match. Search order:
//
//  1. <gitRoot>/.rampart/modules/<name>.hcl  (when gitRoot != "")
//  2. <globalDir>/modules/<name>.hcl         (when globalDir != "")
//
// The returned absolute path is run through filepath.EvalSymlinks so cycle
// detection (which keys off absolute path) treats two symlinks to the same
// file as one.
func ResolveModulePath(name, gitRoot, globalDir string) (absPath, source string, err error) {
	if name == "" {
		return "", "", fmt.Errorf("module name must not be empty")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		return "", "", fmt.Errorf("module name %q must be a relative path without leading '..'", name)
	}
	rel := name
	if !strings.HasSuffix(rel, ".hcl") {
		rel += ".hcl"
	}

	var attempts []string
	if gitRoot != "" {
		attempts = append(attempts, filepath.Join(gitRoot, ".rampart", "modules", rel))
	}
	if globalDir != "" {
		attempts = append(attempts, filepath.Join(globalDir, "modules", rel))
	}

	for _, p := range attempts {
		if _, statErr := os.Stat(p); statErr == nil {
			abs, evalErr := filepath.EvalSymlinks(p)
			if evalErr != nil {
				abs = p
			}
			return abs, p, nil
		}
	}

	return "", "", fmt.Errorf("module %q not found in any search path: tried %s",
		name, strings.Join(attempts, ", "))
}

// ResolveModuleContent is the single-globalDir convenience wrapper around
// ResolveModuleContentFromDirs. Prefer the latter for production wiring
// that needs the full multi-dir search chain (user override + system
// install).
func ResolveModuleContent(name, gitRoot, globalDir string) (src []byte, origin string, err error) {
	dirs := []string(nil)
	if globalDir != "" {
		dirs = []string{globalDir}
	}
	return ResolveModuleContentFromDirs(name, gitRoot, dirs)
}

// ResolveModuleContentFromDirs looks up a module by name and returns its
// source bytes plus a human-readable origin string. The origin doubles
// as the cycle-detection key.
//
// Search order (first hit wins):
//  1. <gitRoot>/.rampart/modules/<name>.hcl                (per-repo)
//  2. globalDirs[i]/modules/<name>.hcl  for each i in order
//     (typical wiring: user override first, install share dir second)
//
// The origin is the resolved absolute path (with symlinks followed).
// rampart no longer ships an embedded fallback — modules must exist on
// disk in one of the search dirs.
func ResolveModuleContentFromDirs(name, gitRoot string, globalDirs []string) (src []byte, origin string, err error) {
	if name == "" {
		return nil, "", fmt.Errorf("module name must not be empty")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		return nil, "", fmt.Errorf("module name %q must be a relative path without leading '..'", name)
	}
	rel := name
	if !strings.HasSuffix(rel, ".hcl") {
		rel += ".hcl"
	}

	var attempts []string
	tryDisk := func(path string) ([]byte, string, bool) {
		attempts = append(attempts, path)
		if _, statErr := os.Stat(path); statErr != nil {
			return nil, "", false
		}
		abs, evalErr := filepath.EvalSymlinks(path)
		if evalErr != nil {
			abs = path
		}
		data, readErr := os.ReadFile(abs)
		if readErr != nil {
			return nil, "", false
		}
		return data, abs, true
	}

	if gitRoot != "" {
		if data, abs, ok := tryDisk(filepath.Join(gitRoot, ".rampart", "modules", rel)); ok {
			return data, abs, nil
		}
	}
	for _, dir := range globalDirs {
		if dir == "" {
			continue
		}
		if data, abs, ok := tryDisk(filepath.Join(dir, "modules", rel)); ok {
			return data, abs, nil
		}
	}

	return nil, "", fmt.Errorf("module %q not found in any search path: tried %s",
		name, strings.Join(attempts, ", "))
}

// ExpandUseBlocks recursively resolves and expands the use blocks rooted at
// `uses`. Returns a flat ModuleFragment that aggregates every transitive
// contribution. Cycle detection is keyed by the resolved origin string, so
// a module included twice via two different relative labels still cycles
// correctly.
//
// gitRoot and globalDir define the on-disk module search path. parentCtx
// is the EvalContext used to evaluate the args of the *outermost* use
// blocks (typically nil for a profile, since profiles don't have variables
// of their own in v1).
func ExpandUseBlocks(uses []*UseBlock, gitRoot, globalDir string, parentCtx *hcl.EvalContext) (*ModuleFragment, error) {
	dirs := []string(nil)
	if globalDir != "" {
		dirs = []string{globalDir}
	}
	return ExpandUseBlocksFromDirs(uses, gitRoot, dirs, parentCtx)
}

// ExpandUseBlocksFromDirs is ExpandUseBlocks but takes an ordered list
// of global search dirs (e.g. user-override dir first, install share
// dir second) so multi-tier deployments resolve in the right order.
func ExpandUseBlocksFromDirs(uses []*UseBlock, gitRoot string, globalDirs []string, parentCtx *hcl.EvalContext) (*ModuleFragment, error) {
	stack := newCycleStack()
	frag := &ModuleFragment{}
	for _, u := range uses {
		if err := expandOne(u, gitRoot, globalDirs, parentCtx, frag, stack); err != nil {
			return nil, err
		}
	}
	return frag, nil
}

// expandOne resolves a single use block: looks up the module file on
// disk, evaluates the args against parentCtx, builds a child EvalContext
// from the resolved variable values, decodes the module's fragment body
// in that context, and then recurses into the module's own use blocks.
func expandOne(u *UseBlock, gitRoot string, globalDirs []string, parentCtx *hcl.EvalContext, frag *ModuleFragment, stack *cycleStack) error {
	src, origin, err := ResolveModuleContentFromDirs(u.ModulePath, gitRoot, globalDirs)
	if err != nil {
		return fmt.Errorf("%s:%d: use %q: %w",
			u.DeclRange.Filename, u.DeclRange.Start.Line, u.ModulePath, err)
	}

	if stack.contains(origin) {
		return fmt.Errorf("%s:%d: use %q: module cycle detected: %s",
			u.DeclRange.Filename, u.DeclRange.Start.Line, u.ModulePath,
			stack.formatCycle(origin))
	}

	mf, parseErr := ParseModuleFile(origin, u.ModulePath, src)
	if parseErr != nil {
		return parseErr
	}

	// Resolve use-block args against the parent EvalContext, then validate
	// against the module's variable declarations.
	resolvedVars, err := resolveUseArgs(u, mf, parentCtx)
	if err != nil {
		return err
	}

	// Build the module's own EvalContext: var.<name> resolves through
	// resolvedVars. No parent — modules are referentially opaque to
	// their callers.
	modCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(resolvedVars),
		},
	}

	// Decode the module's fragment body (path attributes + network block)
	// against the module's EvalContext so ${var.foo} resolves.
	if err := mergeFragmentBody(mf, modCtx, frag); err != nil {
		return err
	}

	// Recurse into the module's own use blocks. They use modCtx as their
	// parent, so their args can read this module's variables.
	stack.push(origin)
	defer stack.pop()
	for _, child := range mf.Use {
		if err := expandOne(child, gitRoot, globalDirs, modCtx, frag, stack); err != nil {
			return err
		}
	}
	return nil
}

// resolveUseArgs reads the args from the use block's body, validates that
// every required variable is provided and that each arg's value matches
// the declared type, and returns the resolved variable map.
func resolveUseArgs(u *UseBlock, mf *ModuleFile, parentCtx *hcl.EvalContext) (map[string]cty.Value, error) {
	// Build inner schema from the module's declared variables.
	attrs := make([]hcl.AttributeSchema, 0, len(mf.Variables))
	declared := map[string]*ModuleVariable{}
	for _, v := range mf.Variables {
		attrs = append(attrs, hcl.AttributeSchema{Name: v.Name, Required: !v.HasDefault})
		declared[v.Name] = v
	}
	schema := &hcl.BodySchema{Attributes: attrs}

	content, diags := u.ArgBody.Content(schema)
	if diags.HasErrors() {
		return nil, diagsToError(diags)
	}

	resolved := make(map[string]cty.Value, len(declared))

	// Defaults first; user args override.
	for _, v := range declared {
		if v.HasDefault {
			resolved[v.Name] = v.Default
		}
	}

	for name, attr := range content.Attributes {
		v := declared[name]
		val, evalDiags := attr.Expr.Value(parentCtx)
		if evalDiags.HasErrors() {
			return nil, diagsToError(evalDiags)
		}
		converted, convErr := convert.Convert(val, v.TypeExpr)
		if convErr != nil {
			return nil, fmt.Errorf("%s:%d: use %q: argument %q does not match declared type: %v",
				u.DeclRange.Filename, u.DeclRange.Start.Line, u.ModulePath, name, convErr)
		}
		resolved[name] = converted
	}

	// Verify all required variables (no default) were provided.
	missing := []string{}
	for _, v := range declared {
		if !v.HasDefault {
			if _, ok := resolved[v.Name]; !ok {
				missing = append(missing, v.Name)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s:%d: use %q: missing required variable(s): %s",
			u.DeclRange.Filename, u.DeclRange.Start.Line, u.ModulePath, strings.Join(missing, ", "))
	}

	return resolved, nil
}

// mergeFragmentBody decodes the module's path attributes and network block
// against ctx and appends the resulting values to frag.
func mergeFragmentBody(mf *ModuleFile, ctx *hcl.EvalContext, frag *ModuleFragment) error {
	// We use a local typed struct that mirrors the profile's gohcl shape
	// for the same attributes — gohcl handles the EvalContext for us.
	type fragmentDecode struct {
		Read           []string       `hcl:"read,optional"`
		Write          []string       `hcl:"write,optional"`
		Exec           []string       `hcl:"exec,optional"`
		AllowedDomains []string       `hcl:"allowed_domains,optional"`
		MitmDomains    []string       `hcl:"mitm_domains,optional"`
		UnixSockets    []string       `hcl:"unix_sockets,optional"`
		Env            []string       `hcl:"env,optional"`
		Network        *NetworkConfig `hcl:"network,block"`
	}
	var fd fragmentDecode
	if diags := gohcl.DecodeBody(mf.fragmentBody, ctx, &fd); diags.HasErrors() {
		return diagsToError(diags)
	}

	// Validate path/domain globs at expansion time so runtime errors point
	// at the module file.
	if err := validatePathGlobs(fd.Read, mf.Path, "module", mf.RelName, "read"); err != nil {
		return err
	}
	if err := validatePathGlobs(fd.Write, mf.Path, "module", mf.RelName, "write"); err != nil {
		return err
	}
	if err := validatePathGlobs(fd.Exec, mf.Path, "module", mf.RelName, "exec"); err != nil {
		return err
	}
	if err := validateDomainGlobs(fd.AllowedDomains, mf.Path, "module", mf.RelName, "allowed_domains"); err != nil {
		return err
	}
	if err := validateDomainGlobs(fd.MitmDomains, mf.Path, "module", mf.RelName, "mitm_domains"); err != nil {
		return err
	}
	if err := validateEnvGlobs(fd.Env, mf.Path, "module", mf.RelName, "env"); err != nil {
		return err
	}
	if fd.Network != nil {
		if err := validateNetworkConfig(fd.Network, mf.Path, "module", mf.RelName); err != nil {
			return err
		}
	}

	frag.Read = append(frag.Read, fd.Read...)
	frag.Write = append(frag.Write, fd.Write...)
	frag.Exec = append(frag.Exec, fd.Exec...)
	frag.AllowedDomains = append(frag.AllowedDomains, fd.AllowedDomains...)
	frag.MitmDomains = append(frag.MitmDomains, fd.MitmDomains...)
	frag.UnixSockets = append(frag.UnixSockets, fd.UnixSockets...)
	frag.Env = append(frag.Env, fd.Env...)
	if fd.Network != nil {
		frag.NetworkDomains = append(frag.NetworkDomains, fd.Network.Domains...)
	}
	return nil
}

// MergeFragmentIntoProfile applies a fragment's contributions to a profile
// in place, with concatenate-then-dedup semantics for path lists.
// Network domains are concatenated as-is (proxy "most specific wins" picks
// the right rule at request time).
func MergeFragmentIntoProfile(p *ProfileConfig, frag *ModuleFragment) {
	p.Read = dedupAppend(p.Read, frag.Read)
	p.Write = dedupAppend(p.Write, frag.Write)
	p.Exec = dedupAppend(p.Exec, frag.Exec)
	p.AllowedDomains = dedupAppend(p.AllowedDomains, frag.AllowedDomains)
	p.MitmDomains = dedupAppend(p.MitmDomains, frag.MitmDomains)
	p.UnixSockets = dedupAppend(p.UnixSockets, frag.UnixSockets)
	p.Env = dedupAppend(p.Env, frag.Env)
	if len(frag.NetworkDomains) > 0 {
		if p.Network == nil {
			p.Network = &NetworkConfig{}
		}
		p.Network.Domains = append(p.Network.Domains, frag.NetworkDomains...)
	}
}

// dedupAppend returns base + new with duplicates of new (against base or
// itself) removed. Preserves first-occurrence order.
func dedupAppend(base, add []string) []string {
	seen := make(map[string]bool, len(base)+len(add))
	out := make([]string, 0, len(base)+len(add))
	for _, s := range base {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range add {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// cycleStack tracks the chain of absolute module paths currently being
// expanded. A cycle is detected when expandOne encounters a path already
// on the stack.
type cycleStack struct {
	paths []string
	set   map[string]int
}

func newCycleStack() *cycleStack {
	return &cycleStack{set: map[string]int{}}
}

func (s *cycleStack) push(p string) {
	s.set[p] = len(s.paths)
	s.paths = append(s.paths, p)
}

func (s *cycleStack) pop() {
	last := s.paths[len(s.paths)-1]
	s.paths = s.paths[:len(s.paths)-1]
	delete(s.set, last)
}

func (s *cycleStack) contains(p string) bool {
	_, ok := s.set[p]
	return ok
}

// formatCycle renders the chain leading up to and including the repeated
// module path, e.g. "a.hcl -> b.hcl -> a.hcl".
func (s *cycleStack) formatCycle(repeated string) string {
	startIdx := s.set[repeated]
	chain := append([]string(nil), s.paths[startIdx:]...)
	chain = append(chain, repeated)
	return strings.Join(chain, " -> ")
}
