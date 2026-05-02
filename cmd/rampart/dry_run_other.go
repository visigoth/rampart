//go:build !linux && !darwin

package main

import (
	"fmt"
	"io"

	"github.com/visigoth/rampart/internal/policy"
)

// printPlatformNativeRules is a stub for unsupported platforms.
func printPlatformNativeRules(rp *policy.ResolvedPolicy, out io.Writer) {
	fmt.Fprintln(out, "platform-native rules not available on this platform")
}
