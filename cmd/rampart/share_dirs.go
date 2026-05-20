package main

import (
	"os"
	"path/filepath"
)

// installShareDir is an optional build-time override for the install
// share directory. Set via ldflags:
//
//	go build -ldflags "-X main.installShareDir=/some/path" ./cmd/rampart
//
// When empty (the default), the binary computes the install share dir
// at runtime from its own location on disk — see resolveInstallShareDir.
// The build-time override exists only for tests and bespoke layouts
// where the relative-to-executable lookup doesn't apply.
var installShareDir = ""

// resolveInstallShareDir computes where the rampart-shipped agent and
// module library lives. Resolution order:
//
//  1. $RAMPART_SHARE_DIR — explicit env override (used by tests and
//     bespoke install layouts).
//  2. Relative to the running binary: <exe-dir>/../share/rampart. This
//     is the Unix prefix convention and covers every supported install
//     path — Homebrew (/opt/homebrew or /usr/local), the bundled bash
//     installer (/opt/shaheengandhi by default), and `just install`
//     during local development.
//  3. The build-time installShareDir ldflag, if set.
//
// Returns "" if none of the above produce a path. Callers tolerate an
// empty string — the registry simply skips the install layer and falls
// back to the user override dir or the repo-local .rampart/ tree.
//
// rampart no longer ships an embedded library; if you want defaults
// like the bundled "coding" / "planning" / "reviewing" agents you must
// install rampart via one of the supported channels.
func resolveInstallShareDir() string {
	if v := os.Getenv("RAMPART_SHARE_DIR"); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		candidate := filepath.Join(filepath.Dir(exe), "..", "share", "rampart")
		if abs, err := filepath.Abs(candidate); err == nil {
			if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
				return abs
			}
		}
	}
	if installShareDir != "" {
		return installShareDir
	}
	return ""
}

// libraryGlobalDirs returns the ordered list of on-disk locations
// rampart searches for agents and modules, AFTER the per-repo
// .rampart/ directory:
//
//  1. User override dir — ~/.local/share/rampart. Content the user
//     manages themselves; an agent or module here shadows the
//     install-share-dir copy with the same name. Rampart never writes
//     to this directory.
//  2. Install share dir — e.g. /opt/shaheengandhi/share/rampart or
//     $(brew --prefix)/share/rampart, populated by whichever install
//     channel placed the binary on disk.
//
// Entries that don't exist on disk are still passed through — the
// registry's per-dir scans are tolerant of missing directories.
func libraryGlobalDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "rampart"))
	}
	if installDir := resolveInstallShareDir(); installDir != "" {
		dirs = append(dirs, installDir)
	}
	return dirs
}
