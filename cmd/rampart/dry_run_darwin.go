//go:build darwin

package main

import (
	"fmt"
	"io"

	"github.com/visigoth/rampart/internal/policy"
	"github.com/visigoth/rampart/internal/sandbox/macos"
)

// printPlatformNativeRules writes the macOS Seatbelt SBPL profile to out.
func printPlatformNativeRules(rp *policy.ResolvedPolicy, out io.Writer) {
	sbpl, err := macos.CompileSBPL(rp, false)
	if err != nil {
		fmt.Fprintf(out, "sbpl error: %v\n", err)
		return
	}
	fmt.Fprintln(out, "sbpl:")
	fmt.Fprintln(out, sbpl)
}
