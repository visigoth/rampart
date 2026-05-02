//go:build linux

package ca

// CheckInitAllowed returns nil on Linux — file-based CA works in any context.
func CheckInitAllowed() error {
	return nil
}
