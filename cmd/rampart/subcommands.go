package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/visigoth/rampart/internal/ca"
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

// initCmd installs the rampart MITM CA certificate needed for HTTPS path filtering.
func initCmd() *cobra.Command {
	var rotate bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Install the rampart MITM CA certificate",
		Long: strings.TrimSpace(`
Install the rampart MITM CA certificate needed for HTTPS path filtering.

On macOS: stores the key and certificate in Keychain and sets user trust.
On Linux: writes ~/.config/rampart/ca.pem (0644) and ca-key.pem (0600).

Use --rotate to replace an existing CA.
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ca.CheckInitAllowed(); err != nil {
				return err
			}
			installed, err := ca.IsInstalled()
			if err != nil {
				return fmt.Errorf("checking CA status: %w", err)
			}
			if installed && !rotate {
				fmt.Fprintln(cmd.OutOrStdout(), "rampart CA is already installed. Use --rotate to replace it.")
				return nil
			}
			if installed {
				if err := ca.RemoveCA(); err != nil {
					return fmt.Errorf("removing existing CA: %w", err)
				}
			}
			gen, err := ca.Generate()
			if err != nil {
				return fmt.Errorf("generating CA: %w", err)
			}
			if err := ca.SaveCA(gen.CertPEM, gen.KeyPEM); err != nil {
				return fmt.Errorf("saving CA: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "rampart CA installed successfully.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&rotate, "rotate", false, "Replace an existing CA")
	return cmd
}

// uninstallCmd removes the rampart MITM CA certificate from platform storage.
func uninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the rampart MITM CA certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ca.RemoveCA(); err != nil {
				return fmt.Errorf("removing CA: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "rampart CA removed.")
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
