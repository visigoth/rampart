// Command rampart is a cross-platform sandbox wrapper for AI coding agents.
//
// Rampart compiles declarative HCL policies into kernel-level sandbox rules
// (Seatbelt on macOS, bubblewrap + seccomp on Linux) and launches a target
// command under those restrictions. See .plans/rampart/ for design docs.
package main

import (
	_ "embed"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed VERSION
var versionBytes []byte

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "rampart",
		Short:   "Cross-platform sandbox wrapper for AI coding agents",
		Version: strings.TrimSpace(string(versionBytes)),
	}
	root.AddCommand(docsCmd(root))
	return root
}
