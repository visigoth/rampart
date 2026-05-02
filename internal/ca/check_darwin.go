//go:build darwin

package ca

import (
	"errors"
	"os"
)

// CheckInitAllowed returns an error if rampart init cannot run in this session.
// macOS requires a GUI session for Keychain trust authentication (TR24).
func CheckInitAllowed() error {
	if os.Getenv("SSH_CONNECTION") != "" {
		return errors.New("rampart init must be run from a GUI session — " +
			"Keychain authentication is required. Run rampart init from a local terminal first. " +
			"Subsequent rampart sessions can run over SSH.")
	}
	if os.Getenv("CI") != "" {
		return errors.New("rampart init cannot run in CI — " +
			"Keychain authentication requires a GUI session")
	}
	if !hasGUISession() {
		return errors.New("rampart init must be run from a GUI session — " +
			"Keychain authentication requires graphical access")
	}
	return nil
}
