package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/visigoth/rampart/internal/ca"
	"github.com/visigoth/rampart/internal/config"
	"github.com/visigoth/rampart/internal/proxy"
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

// reviewCmd is the rampart review subcommand (FR58, FR39).
// Lists accumulated escape hatches from config.json and prompts the user to
// incorporate, discard, or skip each entry.
func reviewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "review",
		Short: "Review and act on accumulated escape hatch requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := filepath.Join(os.Getenv("HOME"), ".config", "rampart", "config.json")
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("getting working directory: %w", err)
			}
			gitRoot := config.FindGitRoot(wd)
			if gitRoot == "" {
				gitRoot = wd
			}
			rampartDir := filepath.Join(gitRoot, ".rampart")
			return RunReview(configPath, rampartDir, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

// initCmd scaffolds a .rampart/ directory in the git root and installs the MITM CA (FR60, FR60.1-4).
func initCmd() *cobra.Command {
	var (
		rotate       bool
		projectName  string
		installHooks bool
		noGit        bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold .rampart/ config and install the MITM CA",
		Long: strings.TrimSpace(`
Initialize rampart for this repository. Two things happen:

  1. .rampart/ is scaffolded with defaults.hcl and a conservative profile.
  2. The MITM CA certificate is installed (Keychain on macOS, files on Linux).

On macOS, step 2 requires an interactive session — it is skipped in SSH or CI.
Use --rotate to regenerate an existing .rampart/ scaffold or replace the CA.
Use --install-hooks to also install tmux and shell hook templates.
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			// --- 1. Locate git root ---
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("getting working directory: %w", err)
			}
			gitRoot := config.FindGitRoot(wd)
			if gitRoot == "" && !noGit {
				return fmt.Errorf("not in a git repository; use --no-git to scaffold without git")
			}
			if gitRoot == "" {
				gitRoot = wd
			}

			// --- 2. Infer project name ---
			if projectName == "" {
				projectName = filepath.Base(gitRoot)
			}

			// --- 3. Scaffold .rampart/ ---
			rampartDir := filepath.Join(gitRoot, ".rampart")
			if _, err := os.Stat(rampartDir); err == nil && !rotate {
				return fmt.Errorf(".rampart/ already exists — edit it manually or re-run with --rotate")
			}
			if err := scaffoldRampartDir(rampartDir, projectName); err != nil {
				return fmt.Errorf("scaffolding .rampart/: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created .rampart/ for project %q\n", projectName)
			fmt.Fprintf(cmd.OutOrStdout(), "  .rampart/defaults.hcl\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  .rampart/profiles/%s/default.hcl\n", projectName)

			// --- 4. MITM CA ---
			if err := ca.CheckInitAllowed(); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Note: MITM CA skipped (%v)\n", err)
			} else {
				installed, err := ca.IsInstalled()
				if err != nil {
					return fmt.Errorf("checking CA status: %w", err)
				}
				if installed && !rotate {
					fmt.Fprintln(cmd.OutOrStdout(), "MITM CA: already installed.")
				} else {
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
					fmt.Fprintln(cmd.OutOrStdout(), "MITM CA: installed.")
				}
			}

			// --- 5. Hooks (optional) ---
			if installHooks {
				tmuxConf, err := defaultTmuxConfPath()
				if err != nil {
					return fmt.Errorf("hooks: %w", err)
				}
				if err := installTmuxHooks(tmuxConf); err != nil {
					return fmt.Errorf("installing tmux hooks: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "tmux hooks: installed to %s\n", tmuxConf)

				shellRC, err := defaultShellRCPath()
				if err != nil {
					return fmt.Errorf("hooks: %w", err)
				}
				if err := installShellHooks(shellRC); err != nil {
					return fmt.Errorf("installing shell hooks: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "shell hooks: installed to %s\n", shellRC)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nEdit .rampart/profiles/%s/default.hcl to customize.\n", projectName)
			return nil
		},
	}

	cmd.Flags().BoolVar(&rotate, "rotate", false, "Replace existing .rampart/ scaffold and CA")
	cmd.Flags().StringVar(&projectName, "project", "", "Project name (default: git repo basename)")
	cmd.Flags().BoolVar(&installHooks, "install-hooks", false, "Install tmux and shell hooks")
	cmd.Flags().BoolVar(&noGit, "no-git", false, "Scaffold without a git repository")
	return cmd
}

// scaffoldRampartDir creates .rampart/defaults.hcl and .rampart/profiles/<project>/default.hcl
// with conservative defaults. Existing files are overwritten (callers check existence first).
func scaffoldRampartDir(rampartDir, projectName string) error {
	profileDir := filepath.Join(rampartDir, "profiles", projectName)
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		return fmt.Errorf("creating profile directory: %w", err)
	}

	defaults := fmt.Sprintf(`// Rampart defaults for this repository.
// Edit to change the active agent and profile.

defaults {
  default_agent   = "coding"
  default_profile = %q
}
`, projectName+"/default")

	if err := os.WriteFile(filepath.Join(rampartDir, "defaults.hcl"), []byte(defaults), 0o644); err != nil {
		return fmt.Errorf("writing defaults.hcl: %w", err)
	}

	profile := fmt.Sprintf(`// Default rampart profile for %s.
// Conservative: read-write access to the working directory, no network.
// Uncomment sections to enable additional access.

profile "default" {
  // Working directory for sandboxed commands (relative to git root).
  workdir = "."

  // Read-write access to the current directory.
  write = ["."]

  // Additional read-only paths outside workdir:
  // read = ["/etc/ssl/certs"]

  // Programs allowed to execute:
  // exec = ["/usr/bin/git", "/usr/bin/make"]

  // Network access (disabled by default).
  // Add domains to enable filtered outbound traffic:
  // network {
  //   domain "api.anthropic.com" {
  //     allow "*" { paths = ["/**"] }
  //   }
  // }
}
`, projectName)

	if err := os.WriteFile(filepath.Join(profileDir, "default.hcl"), []byte(profile), 0o644); err != nil {
		return fmt.Errorf("writing profiles/%s/default.hcl: %w", projectName, err)
	}

	return nil
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

// presencePushCmd is a hidden subcommand used by tmux and shell hooks to push
// a presence event to the active session socket (FR42, FR43). It reads
// $RAMPART_SESSION_SOCK and writes a JSON event line; silently no-ops when the
// variable is unset or the socket doesn't exist.
func presencePushCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "presence-push <event>",
		Short:  "Push a presence event to the active session socket",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sock := os.Getenv("RAMPART_SESSION_SOCK")
			return pushPresenceEvent(sock, args[0])
		},
	}
}

// testCmd is the rampart test subcommand.
// Loads the policy for the given agent/profile and launches a REPL where the
// user can check read/write/exec/http verdicts without launching a real sandbox.
func testCmd() *cobra.Command {
	var flags *runFlags
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Launch policy test REPL (check read/write/exec/http verdicts)",
		Long: strings.TrimSpace(`
Launch an interactive REPL against the resolved policy for --agent/--profile.
Commands:
  read  <path>           check filesystem read access
  write <path>           check filesystem write access
  exec  <path>           check filesystem exec access
  http  <METHOD> <URL>   check proxy ACL verdict
  policy                 print resolved policy summary
  exit / quit / Ctrl-D   exit
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("getting working directory: %w", err)
			}
			cp, err := loadPolicy(flags, wd)
			if err != nil {
				return err
			}
			rp := cp.Policy
			aclRules := proxy.CompileACLRules(rp.ProxyACLs, rp.MitmDomains)

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "rampart test — agent: %s  profile: %s\n", cp.AgentName, cp.ProfileName)
			fmt.Fprintf(out, "Type 'policy' for summary, 'exit' to quit.\n\n")

			if isTTY(os.Stdin) {
				return RunInteractiveREPL(rp, aclRules, out)
			}
			return RunREPL(rp, aclRules, cmd.InOrStdin(), out)
		},
	}
	flags = attachRunFlags(cmd)
	return cmd
}
