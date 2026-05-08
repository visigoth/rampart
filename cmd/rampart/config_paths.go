package main

import (
	"os"
	"path/filepath"
)

// defaultEngineConfigPath returns the on-disk location of the persisted
// escalation-approvals file consumed by supervisor.Engine and rampart review:
//
//	$HOME/.config/rampart/config.json
//
// Centralizing the path keeps runLaunch (live engine) and the review
// subcommand (offline reader) in lock-step. If $HOME is unset (rare —
// generally only in stripped CI environments), the returned path is
// relative ("./.config/rampart/config.json"), which the engine and review
// will treat as missing on read and create on write.
func defaultEngineConfigPath() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "rampart", "config.json")
}
