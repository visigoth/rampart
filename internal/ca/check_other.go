//go:build !linux && !darwin

package ca

// CheckInitAllowed always returns nil on unsupported platforms.
func CheckInitAllowed() error { return nil }
