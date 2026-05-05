//go:build !linux && !darwin

package ca

import "errors"

var errUnsupportedPlatform = errors.New("rampart CA management is not supported on this platform")

// saveCA is not implemented on this platform.
func saveCA(certPEM, keyPEM []byte) error { return errUnsupportedPlatform }

// loadCA is not implemented on this platform.
func loadCA() (*CA, error) { return nil, errUnsupportedPlatform }

// isInstalled is not implemented on this platform.
func isInstalled() (bool, error) { return false, errUnsupportedPlatform }

// removeCA is not implemented on this platform.
func removeCA() error { return errUnsupportedPlatform }
