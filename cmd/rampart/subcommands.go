package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// versionCmd prints the binary version and exits.
func versionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the rampart version and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "rampart %s\n", version)
			return nil
		},
	}
}

// escalationsCmd is the rampart escalations subcommand (FR59).
// Lists pending escalations from active sessions and allows approve/deny.
func escalationsCmd() *cobra.Command {
	var (
		approveID string
		denyID    string
		watch     bool
	)

	cmd := &cobra.Command{
		Use:   "escalations",
		Short: "List and act on pending escalations across active sessions",
		Long: strings.TrimSpace(`
List pending escalations from all active rampart sessions.
Active sessions are discovered via ~/.rampart/sessions/*.sock.

With --approve or --deny, act on a specific escalation.
With --watch, subscribe to future escalations in real time.
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case approveID != "":
				fmt.Fprintf(cmd.OutOrStdout(), "approve: %s (not yet implemented)\n", approveID)
			case denyID != "":
				fmt.Fprintf(cmd.OutOrStdout(), "deny: %s (not yet implemented)\n", denyID)
			case watch:
				fmt.Fprintln(cmd.OutOrStdout(), "escalations --watch (not yet implemented)")
			default:
				fmt.Fprintln(cmd.OutOrStdout(), "escalations list (not yet implemented)")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&approveID, "approve", "", "Approve escalation by ID")
	cmd.Flags().StringVar(&denyID, "deny", "", "Deny escalation by ID")
	cmd.Flags().BoolVar(&watch, "watch", false, "Subscribe to escalations in real time (--watch mode)")
	cmd.MarkFlagsMutuallyExclusive("approve", "deny", "watch")

	return cmd
}

// reviewCmd is the rampart review subcommand (FR58).
// Delegates to the escape hatch triage flow (FT8 — not yet implemented).
func reviewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "review",
		Short: "Review and act on pending escape hatch requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "review (not yet implemented)")
			return nil
		},
	}
}

// initCmd is the rampart init subcommand.
// Scaffolds .rampart/ configs for the current project.
func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Scaffold .rampart/ configuration for the current project",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "init (not yet implemented)")
			return nil
		},
	}
}

// testCmd is the rampart test subcommand.
// Runs in REPL mode with permissive enforcement (FT17).
func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run in test REPL mode with permissive enforcement (FT17)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "test (not yet implemented)")
			return nil
		},
	}
}
