// Command rampart is a cross-platform sandbox wrapper for AI coding agents.
//
// Rampart compiles declarative HCL policies into kernel-level sandbox rules
// (Seatbelt on macOS, bubblewrap + seccomp on Linux) and launches a target
// command under those restrictions. See .plans/rampart/ for design docs.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

//go:embed VERSION
var versionBytes []byte

func main() {
	// Extract embedded agent profiles to ~/.local/share/rampart/agents/ on
	// first run; skip user-modified profiles (FR61).
	_ = MaybeExtractProfiles()

	// Extract the policy-module library to ~/.local/share/rampart/modules/.
	// Same user-edit-preservation contract as the agent extraction — module
	// files modified by the user are detected by SHA-256 and left alone.
	_ = MaybeExtractModules()

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

		// Full orchestration: load + compile policy, build a sandbox-wrapped
		// child Cmd, and hand off to the supervisor lifecycle (TR38–TR58).
		// .1.2 implemented supervisor.Run; this is the wiring ().
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		defer stop()

		exitCode, err := runLaunch(ctx, flags, args, os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "rampart: %v\n", err)
		}
		exitWithCode(exitCode)
		return nil
	}

	// Subcommands.
	root.AddCommand(
		versionCmd(version),
		escalationsCmd(),
		reviewCmd(),
		initCmd(),
		uninstallCmd(),
		listCmd(),
		testCmd(),
		launcherCmd(),
		presencePushCmd(),
		docsCmd(root),
	)

	return root
}

// exitWithCode calls os.Exit with the given code. Extracted so tests can
// replace it; the real implementation just calls os.Exit.
var exitWithCode = func(code int) {
	os.Exit(code)
}
