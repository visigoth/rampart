package main

import (
	"os"
	"path/filepath"
)

// installShareDir is the install-time canonical location for the
// rampart-shipped agent + module library, e.g.
// /opt/shaheengandhi/share/rampart. Populated by the Justfile install
// recipe via ldflags:
//
//	go build -ldflags "-X main.installShareDir=/opt/shaheengandhi/share/rampart" ...
//
// When set, the binary reads its bundled library from this directory
// rather than from the embedded fs.FS. Empty (the default) means
// "fall back to the embedded library", which is what `go install`
// users get.
var installShareDir = ""

// libraryGlobalDirs returns the ordered list of on-disk locations
// rampart searches for agents and modules, AFTER the per-repo
// .rampart/ directory and BEFORE the binary's embedded fs.FS:
//
//  1. user override dir  (~/.local/share/rampart): content the user
//     manages themselves; an agent or module here shadows the
//     install-share-dir copy with the same name. Rampart never writes
//     to this directory.
//  2. install share dir  (e.g. /opt/shaheengandhi/share/rampart):
//     populated at `just install rampart` time. The canonical
//     rampart-shipped library on systems that have run the install
//     recipe.
//
// Entries that don't exist on disk are still passed through — the
// registry's per-dir scans are tolerant of missing directories. The
// embedded fs.FS is the final fallback (handled at the registry
// layer, not here) for users who haven't run the install recipe.
func libraryGlobalDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "rampart"))
	}
	if installShareDir != "" {
		dirs = append(dirs, installShareDir)
	}
	return dirs
}
