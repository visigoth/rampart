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

//go:embed assets/agents/*.hcl
var embeddedAgents embed.FS

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
	return ExtractProfiles(dir)
}

// ExtractProfiles extracts embedded agent profiles to dir.
// If dir does not exist, it is created and all profiles are written.
// If dir exists, only unmodified profiles (whose SHA-256 matches the
// stored hash from the last rampart-managed write) are overwritten (FR61.2).
func ExtractProfiles(dir string) error {
	profiles, err := embeddedProfileMap()
	if err != nil {
		return fmt.Errorf("reading embedded profiles: %w", err)
	}

	dirExists, err := dirExistsCheck(dir)
	if err != nil {
		return err
	}

	// Load the stored hashes so we can detect user-modified files.
	storedHashes := map[string]string{}
	if dirExists {
		storedHashes, _ = loadHashes(filepath.Join(dir, hashesFile))
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating agents dir %s: %w", dir, err)
	}

	newHashes := map[string]string{}
	for name, content := range profiles {
		hash := sha256sum(content)
		newHashes[name] = hash

		target := filepath.Join(dir, name)
		if dirExists {
			// Check whether the file was user-modified.
			existing, readErr := os.ReadFile(target)
			if readErr == nil {
				// File exists. If its hash doesn't match what rampart last wrote,
				// the user modified it — skip (FR61.2).
				originalHash, known := storedHashes[name]
				if known && sha256sum(existing) != originalHash {
					continue // user-modified: preserve
				}
			}
		}

		if err := os.WriteFile(target, content, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", target, err)
		}
	}

	return saveHashes(filepath.Join(dir, hashesFile), newHashes)
}

// embeddedProfileMap returns a map of filename → content for all embedded HCL files.
func embeddedProfileMap() (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := fs.WalkDir(embeddedAgents, "assets/agents", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".hcl") {
			return nil
		}
		data, err := embeddedAgents.ReadFile(path)
		if err != nil {
			return err
		}
		result[filepath.Base(path)] = data
		return nil
	})
	return result, err
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
