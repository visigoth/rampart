// Command rampart is a cross-platform sandbox wrapper for AI coding agents.
//
// Rampart compiles declarative HCL policies into kernel-level sandbox rules
// (Seatbelt on macOS, bubblewrap + seccomp on Linux) and launches a target
// command under those restrictions. See .plans/rampart/ for design docs.
package main

import (
	_ "embed"
	"fmt"
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
	version := strings.TrimSpace(string(versionBytes))

	root := &cobra.Command{
		Use:     "rampart [flags] -- <command> [args...]",
		Short:   "Cross-platform sandbox wrapper for AI coding agents",
		Long: strings.TrimSpace(`
rampart compiles declarative HCL policies into kernel-level sandbox rules and
launches a target command under those restrictions.

  rampart --agent coding --profile myproject -- claude

Seatbelt on macOS, bubblewrap + seccomp on Linux.
See 'rampart help <subcommand>' for more information.
`),
		Version:      version,
		SilenceUsage: true,
	}

	// Attach run-mode flags to the root command.
	flags := attachRunFlags(root)

	root.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		if flags.verbose {
			fmt.Fprintf(cmd.OutOrStdout(), "rampart %s — platform: %s\n", version, currentPlatform())
			fmt.Fprintf(cmd.OutOrStdout(), "mode: %s\n", flags.mode)
			fmt.Fprintf(cmd.OutOrStdout(), "execution-mode: %s\n", DetectMode(flags))
		}
		if flags.dryRun {
			return runDryRun(flags, cmd.OutOrStdout())
		}
		// Full orchestration (FT1→FT2→FT3→FT4/FT5) is implemented in .1.2.
		fmt.Fprintln(cmd.OutOrStdout(), "launch (not yet implemented)")
		return nil
	}

	// Subcommands.
	root.AddCommand(
		versionCmd(version),
		escalationsCmd(),
		reviewCmd(),
		initCmd(),
		uninstallCmd(),
		testCmd(),
		launcherCmd(),
		docsCmd(root),
	)

	return root
}

// exitWithCode calls os.Exit with the given code. Extracted so tests can
// replace it; the real implementation just calls os.Exit.
var exitWithCode = func(code int) {
	os.Exit(code)
}
