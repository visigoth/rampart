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
	// One-time migration: older versions of rampart auto-extracted the
	// bundled agents and modules to ~/.local/share/rampart/. That made
	// upgrades silently stale because the on-disk copies had precedence
	// over the binary's current embedded library. The bundled library
	// now lives entirely inside the binary; the user directory is
	// reserved for content the user adds themselves. Best-effort cleanup
	// of unmodified files lifted from the embed; user-edited files are
	// preserved.
	_ = migrateLegacyUserDir()

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

		// Route rampart's diagnostic logging away from the controlling
		// TTY when an interactive agent is about to own it; otherwise
		// the agent's TUI gets clobbered by proxy CONNECT and session-
		// socket INFO lines. The log file path is reported on stderr
		// once, before the agent takes over the terminal.
		logPath, cleanupLog := configureSlog(flags)
		defer cleanupLog()
		go pruneOldLogs()
		if logPath != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "rampart: logging to %s (pass -v to mirror to stderr)\n", logPath)
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
