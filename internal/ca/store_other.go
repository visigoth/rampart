//go:build !linux && !darwin

package ca

import "errors"

var errUnsupportedPlatform = errors.New("rampart CA management is not supported on this platform")

// SaveCA is not implemented on this platform.
func SaveCA(certPEM, keyPEM []byte) error { return errUnsupportedPlatform }

// LoadCA is not implemented on this platform.
func LoadCA() (*CA, error) { return nil, errUnsupportedPlatform }

// IsInstalled is not implemented on this platform.
func IsInstalled() (bool, error) { return false, errUnsupportedPlatform }

// RemoveCA is not implemented on this platform.
func RemoveCA() error { return errUnsupportedPlatform }
