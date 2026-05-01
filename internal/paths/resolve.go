// Package paths implements path resolution for rampart policy configs (FT3).
// It expands ~, ~user, and relative paths to absolute physical paths,
// resolving symlinks as far as possible.
package paths

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Context carries the base directories used when resolving relative paths.
type Context struct {
	// GitRoot is the git repository root; used to resolve "." and relative
	// paths in project-scoped configs.
	GitRoot string
	// Home is the user's home directory; used to resolve ~ and relative paths
	// in user-scoped configs. Defaults to os.UserHomeDir() if empty.
	Home string
}

// Resolve resolves a single path string to an absolute physical path.
//
//   - ~ expands to ctx.Home (FR16)
//   - ~user expands via os/user.Lookup (FR16.1)
//   - "." expands to ctx.GitRoot if set, else ctx.Home (FR17)
//   - relative paths are joined to ctx.GitRoot if set, else ctx.Home (FR17)
//   - symlinks are resolved via filepath.EvalSymlinks (FR18)
//   - if the final target doesn't exist, symlinks are resolved as far as
//     possible and the remaining literal suffix is appended (FR18.1)
//   - trailing slashes are removed (FR19)
//   - null bytes in the path return an error
func Resolve(path string, ctx Context) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains null byte: %q", path)
	}
	if path == "" {
		return "", fmt.Errorf("path must not be empty")
	}

	home, err := effectiveHome(ctx)
	if err != nil {
		return "", err
	}

	expanded, err := expandTilde(path, home)
	if err != nil {
		return "", err
	}

	// Make absolute.
	if !filepath.IsAbs(expanded) {
		base := ctx.GitRoot
		if base == "" {
			base = home
		}
		expanded = filepath.Join(base, expanded)
	}

	// Clean before symlink resolution.
	expanded = filepath.Clean(expanded)

	// Resolve symlinks as far as possible (FR18, FR18.1).
	resolved, err := resolveSymlinks(expanded)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

// ResolveAll resolves a slice of paths, returning all resolved paths or
// the first error encountered.
func ResolveAll(paths []string, ctx Context) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		resolved, err := Resolve(p, ctx)
		if err != nil {
			return nil, fmt.Errorf("resolving %q: %w", p, err)
		}
		out = append(out, resolved)
	}
	return out, nil
}

// expandTilde expands a leading ~ or ~user prefix.
func expandTilde(path, home string) (string, error) {
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:]), nil
	}
	if strings.HasPrefix(path, "~") {
		// ~user syntax: find the next "/" or end of string.
		rest := path[1:]
		slash := strings.IndexByte(rest, '/')
		var username, suffix string
		if slash == -1 {
			username = rest
		} else {
			username = rest[:slash]
			suffix = rest[slash:]
		}
		u, err := user.Lookup(username)
		if err != nil {
			return "", fmt.Errorf("expanding ~%s: %w", username, err)
		}
		return filepath.Join(u.HomeDir, suffix), nil
	}
	return path, nil
}

// resolveSymlinks resolves symlinks as far as possible.
// If the full path exists, filepath.EvalSymlinks is used directly.
// If not, it walks up until it finds a component that exists,
// resolves that prefix, and appends the remaining literal suffix.
func resolveSymlinks(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return path, nil // unexpected error — return as-is
	}

	// Walk up to find the longest existing prefix.
	parts := strings.Split(path, string(filepath.Separator))
	// Reconstruct components starting from the root.
	for i := len(parts); i > 0; i-- {
		prefix := strings.Join(parts[:i], string(filepath.Separator))
		if prefix == "" {
			prefix = string(filepath.Separator)
		}
		if _, statErr := os.Lstat(prefix); statErr == nil {
			resolved, resolveErr := filepath.EvalSymlinks(prefix)
			if resolveErr != nil {
				resolved = prefix
			}
			// Append the non-existent suffix.
			suffix := filepath.Join(parts[i:]...)
			if suffix != "" {
				return filepath.Join(resolved, suffix), nil
			}
			return resolved, nil
		}
	}
	return path, nil
}

func effectiveHome(ctx Context) (string, error) {
	if ctx.Home != "" {
		return ctx.Home, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}
	return home, nil
}
