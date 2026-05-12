package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// embeddedLibrary holds the entire rampart-shipped library — every agent
// HCL under assets/agents/ and every module HCL under assets/modules/.
// The `all:` prefix includes files whose names start with `_` or `.`
// (notably so the bundled README/.gitkeep files don't get silently
// dropped, and so an embedded test fixture survives go:embed defaults).
//
//go:embed all:assets
var embeddedLibrary embed.FS

// embeddedAgents and embeddedModules are kept as aliases for backward
// compatibility with the original extraction tests; they point at the
// same embed.FS, just with different conceptual scopes (callers walk
// either "assets/agents" or "assets/modules" inside).
var (
	embeddedAgents  = embeddedLibrary
	embeddedModules = embeddedLibrary
)

// bundledLibraryFS returns the embedded library as an fs.FS, ready to
// hand to config.NewRegistryWithBundled. The fs is rooted at the binary
// — paths inside it look like "assets/agents/<name>.hcl" and
// "assets/modules/<category>/<name>.hcl".
func bundledLibraryFS() fs.FS { return embeddedLibrary }

// hashesFile is the filename used to record the SHA-256 hash of each embedded
// profile when it was last extracted. Used to detect user-modified profiles.
const hashesFile = ".rampart-sha256"

// defaultAgentsDir returns ~/.local/share/rampart/agents/.
func defaultAgentsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "rampart", "agents"), nil
}

// defaultModulesDir returns ~/.local/share/rampart/modules/. Module
// extraction preserves the on-disk subdirectory tree (lang/, tooling/,
// ai/, system/, network/) so `use "lang/python"` resolves predictably.
func defaultModulesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "rampart", "modules"), nil
}

// MaybeExtractProfiles extracts embedded agent profiles to the default
// agents directory (~/.local/share/rampart/agents/) if the directory does
// not exist (FR61.1). On subsequent calls, only extracts profiles that have
// not been modified by the user (FR61.2).
//
// Silently returns nil if the directory already exists with user-modified files.
func MaybeExtractProfiles() error {
	dir, err := defaultAgentsDir()
	if err != nil {
		return err
	}
	return extractEmbedded(embeddedAgents, "assets/agents", dir, "agents")
}

// MaybeExtractModules extracts the embedded policy-module library to
// ~/.local/share/rampart/modules/, preserving the subdirectory tree.
// User edits are preserved via the same SHA-256 mechanism as profiles
// (a per-directory .rampart-sha256 manifest tracks each file's last
// rampart-written hash).
func MaybeExtractModules() error {
	dir, err := defaultModulesDir()
	if err != nil {
		return err
	}
	return extractEmbedded(embeddedModules, "assets/modules", dir, "modules")
}

// ExtractProfiles is retained for callers (and tests) that pin the
// destination directory. Behaviour identical to MaybeExtractProfiles
// against `dir` instead of the user's default.
func ExtractProfiles(dir string) error {
	return extractEmbedded(embeddedAgents, "assets/agents", dir, "agents")
}

// extractEmbedded copies an embedded HCL tree into destDir. The on-disk
// layout mirrors the embedded layout (subdirectories preserved). On a
// fresh destDir all files are written. On subsequent calls only files
// whose current SHA-256 matches the last rampart-written hash are
// overwritten — user edits survive future invocations.
//
// `kind` is a human-readable label used only in error messages.
func extractEmbedded(efs embed.FS, srcPrefix, destDir, kind string) error {
	files, err := embeddedFileMap(efs, srcPrefix)
	if err != nil {
		return fmt.Errorf("reading embedded %s: %w", kind, err)
	}

	dirExists, err := dirExistsCheck(destDir)
	if err != nil {
		return err
	}

	storedHashes := map[string]string{}
	if dirExists {
		storedHashes, _ = loadHashes(filepath.Join(destDir, hashesFile))
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating %s dir %s: %w", kind, destDir, err)
	}

	newHashes := map[string]string{}
	for relPath, content := range files {
		hash := sha256sum(content)
		newHashes[relPath] = hash

		target := filepath.Join(destDir, relPath)
		if dirExists {
			existing, readErr := os.ReadFile(target)
			if readErr == nil {
				originalHash, known := storedHashes[relPath]
				if known && sha256sum(existing) != originalHash {
					continue // user-modified: preserve
				}
			}
		}

		// Ensure the destination directory exists for files in subtrees
		// (e.g. lang/python.hcl needs lang/ to be created).
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("creating %s subdir %s: %w", kind, filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", target, err)
		}
	}

	return saveHashes(filepath.Join(destDir, hashesFile), newHashes)
}

// embeddedFileMap walks an embedded subtree and returns a map of
// relative-to-srcPrefix path → file content for every .hcl file. The
// relative path preserves any subdirectory structure (e.g. "lang/python.hcl").
func embeddedFileMap(efs embed.FS, srcPrefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := fs.WalkDir(efs, srcPrefix, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".hcl") {
			return nil
		}
		data, readErr := efs.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(srcPrefix, path)
		if relErr != nil {
			return relErr
		}
		result[rel] = data
		return nil
	})
	return result, err
}

// embeddedProfileMap is retained as an alias for the agent extraction
// tests; new code should call embeddedFileMap directly.
func embeddedProfileMap() (map[string][]byte, error) {
	return embeddedFileMap(embeddedAgents, "assets/agents")
}

// sha256sum returns the hex-encoded SHA-256 hash of data.
func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// dirExistsCheck returns (true, nil) if dir is an existing directory, (false, nil) if
// it doesn't exist, or (false, err) on any other error.
func dirExistsCheck(dir string) (bool, error) {
	fi, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return fi.IsDir(), nil
}

// loadHashes reads the hashesFile and returns a map of filename → hash.
func loadHashes(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result, nil
}

// saveHashes writes a map of filename → hash to path.
func saveHashes(path string, hashes map[string]string) error {
	var sb strings.Builder
	for name, hash := range hashes {
		fmt.Fprintf(&sb, "%s=%s\n", name, hash)
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
