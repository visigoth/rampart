package main

import (
	"os"
	"path/filepath"
	"strings"
)

// migrateLegacyUserDir cleans up content that older rampart versions
// auto-extracted into ~/.local/share/rampart/{agents,modules}/ on every
// startup. The bundled library now lives entirely inside the binary
// (read via the embedded fs.FS); the user directory is reserved for
// content the user manages themselves.
//
// Strategy: each old extraction wrote a manifest file
// (.rampart-sha256) recording the SHA-256 of every file it placed.
// Files whose current hash still matches the manifest are confirmed
// untouched-by-user and can be safely deleted. Files whose hash has
// drifted are preserved verbatim — they're user-edited and the user
// must decide what to do with them. The manifest is removed once
// processing finishes so the migration is idempotent.
//
// Best effort: any error short-circuits cleanup for that subtree but
// never blocks startup; the migration runs again on the next launch.
func migrateLegacyUserDir() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	root := filepath.Join(home, ".local", "share", "rampart")
	for _, sub := range []string{"agents", "modules"} {
		_ = pruneManagedFiles(filepath.Join(root, sub))
	}
	// Remove the empty subtrees if everything was migrated cleanly.
	for _, sub := range []string{"agents", "modules"} {
		_ = removeIfEmpty(filepath.Join(root, sub))
	}
	return nil
}

// pruneManagedFiles deletes files in dir whose SHA-256 matches the entry
// recorded in dir/.rampart-sha256. User-edited files (hash drift) are
// left alone. After processing, the manifest itself is removed so the
// migration doesn't re-evaluate stale state on subsequent runs.
func pruneManagedFiles(dir string) error {
	manifestPath := filepath.Join(dir, hashesFile)
	hashes, err := loadHashes(manifestPath)
	if err != nil {
		// No manifest → either never auto-extracted by rampart or
		// already migrated. Nothing to do.
		return nil
	}

	preserved := 0
	for rel, recordedHash := range hashes {
		target := filepath.Join(dir, rel)
		data, readErr := os.ReadFile(target)
		if readErr != nil {
			// File already gone — count it as migrated.
			continue
		}
		if sha256sum(data) != recordedHash {
			preserved++
			continue
		}
		_ = os.Remove(target)
		// Best-effort: clean empty parent directories as we go up to
		// the migration root. Stops as soon as a non-empty parent is
		// hit (RemoveDir errors out on non-empty).
		removeEmptyParents(filepath.Dir(target), dir)
	}

	// Only drop the manifest if every recorded file was either deleted
	// or already gone. If any user-edited file survived, keep the
	// manifest around so a future re-run can re-evaluate (in case the
	// user reverts their edits).
	if preserved == 0 {
		_ = os.Remove(manifestPath)
	}
	return nil
}

// removeEmptyParents walks from leaf upward, removing each directory
// that's now empty. Stops when it reaches stopAt (exclusive) or hits a
// non-empty directory.
func removeEmptyParents(leaf, stopAt string) {
	for leaf != stopAt && !strings.HasPrefix(stopAt, leaf+string(filepath.Separator)) {
		if err := os.Remove(leaf); err != nil {
			return // non-empty or permission denied
		}
		parent := filepath.Dir(leaf)
		if parent == leaf {
			return
		}
		leaf = parent
	}
}

// removeIfEmpty removes dir if it contains no entries.
func removeIfEmpty(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	if len(entries) == 0 {
		return os.Remove(dir)
	}
	return nil
}
