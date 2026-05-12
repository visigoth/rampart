package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/visigoth/rampart/internal/ca"
	"github.com/visigoth/rampart/internal/config"
	"github.com/visigoth/rampart/internal/proxy"
	"github.com/visigoth/rampart/internal/session"
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
			out := cmd.OutOrStdout()
			switch {
			case approveID != "":
				return runEscalationCommand(out, "approve", approveID)
			case denyID != "":
				return runEscalationCommand(out, "deny", denyID)
			case watch:
				return runEscalationsWatch(cmd.Context(), out)
			default:
				return runEscalationsList(out)
			}
		},
	}

	cmd.Flags().StringVar(&approveID, "approve", "", "Approve escalation by ID")
	cmd.Flags().StringVar(&denyID, "deny", "", "Deny escalation by ID")
	cmd.Flags().BoolVar(&watch, "watch", false, "Subscribe to escalations in real time (--watch mode)")
	cmd.MarkFlagsMutuallyExclusive("approve", "deny", "watch")

	return cmd
}

// runEscalationsList queries every active rampart session socket under
// ~/.rampart/sessions/*.sock and prints a combined table of pending
// escalations. No active sessions = "no active sessions" message and exit 0.
func runEscalationsList(out io.Writer) error {
	socks, err := session.ListActiveSockets()
	if err != nil {
		return fmt.Errorf("discovering session sockets: %w", err)
	}
	if len(socks) == 0 {
		fmt.Fprintln(out, "no active rampart sessions found at ~/.rampart/sessions/*.sock")
		return nil
	}

	type row struct {
		sessionPID string
		esc        session.OutboundEscalation
	}
	var rows []row
	for _, s := range socks {
		c, err := session.Dial(s)
		if err != nil {
			fmt.Fprintf(out, "warn: dial %s: %v\n", s, err)
			continue
		}
		resp, err := c.List()
		_ = c.Close()
		if err != nil {
			fmt.Fprintf(out, "warn: list %s: %v\n", s, err)
			continue
		}
		pid := strings.TrimSuffix(filepath.Base(s), ".sock")
		for _, e := range resp.Escalations {
			rows = append(rows, row{sessionPID: pid, esc: e})
		}
	}

	if len(rows) == 0 {
		fmt.Fprintln(out, "no pending escalations across active sessions")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSESSION\tOPERATION\tRESOURCE\tSTATUS\tTIMESTAMP")
	for _, r := range rows {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
			r.esc.ID, r.sessionPID, r.esc.Operation, r.esc.Resource, r.esc.Status, r.esc.Timestamp)
	}
	_ = tw.Flush()
	return nil
}

// runEscalationCommand sends an approve or deny command to all active
// session sockets. The session that owns the escalation responds with the
// outcome ("approved", "denied", "persisted"); others reply "not_found".
// Exit zero only if at least one session recognized the ID.
func runEscalationCommand(out io.Writer, action, idStr string) error {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid escalation ID %q: must be a positive integer", idStr)
	}
	socks, err := session.ListActiveSockets()
	if err != nil {
		return fmt.Errorf("discovering session sockets: %w", err)
	}
	if len(socks) == 0 {
		return fmt.Errorf("no active rampart sessions found")
	}

	var owner string
	var ownerResult string
	for _, s := range socks {
		c, err := session.Dial(s)
		if err != nil {
			fmt.Fprintf(out, "warn: dial %s: %v\n", s, err)
			continue
		}
		ack, err := c.Command(action, id, "")
		_ = c.Close()
		if err != nil {
			fmt.Fprintf(out, "warn: %s on %s: %v\n", action, s, err)
			continue
		}
		if ack.Result != "not_found" {
			owner = filepath.Base(s)
			ownerResult = ack.Result
			break
		}
	}

	if owner == "" {
		return fmt.Errorf("escalation %d not found in any active session", id)
	}
	fmt.Fprintf(out, "%s %d in %s: %s\n", action, id, strings.TrimSuffix(owner, ".sock"), ownerResult)
	return nil
}

// runEscalationsWatch subscribes to every active session socket and streams
// escalation events line-by-line until interrupted (SIGINT/SIGTERM/SIGHUP).
// When invoked from a tmux pane created by the supervisor, the pane stays
// open until rampart kills it via tmux kill-pane (which delivers SIGHUP).
//
// If no active sessions exist at start, watch holds the pane open with a
// "no active sessions" banner and waits for one to appear (re-discovers
// every 2s); this keeps the supervisor-spawned pane usable even if it
// races the session socket startup.
func runEscalationsWatch(ctx context.Context, out io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	fmt.Fprintln(out, "rampart escalations — watching for events (Ctrl-C to exit)")

	// Track which sockets we're already watching to avoid duplicates.
	watching := map[string]context.CancelFunc{}
	defer func() {
		for _, c := range watching {
			c()
		}
	}()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	subscribe := func(sockPath string) {
		if _, ok := watching[sockPath]; ok {
			return
		}
		c, err := session.Dial(sockPath)
		if err != nil {
			return
		}
		subCtx, subCancel := context.WithCancel(ctx)
		watching[sockPath] = subCancel
		pid := strings.TrimSuffix(filepath.Base(sockPath), ".sock")
		fmt.Fprintf(out, "[session %s] subscribed\n", pid)

		go func() {
			defer func() {
				_ = c.Close()
				subCancel()
			}()
			err := c.Watch(subCtx, func(msg map[string]any) error {
				if r, ok := session.DecodeAsResponse(msg); ok {
					if len(r.Escalations) == 0 {
						fmt.Fprintf(out, "[session %s] no pending escalations\n", pid)
						return nil
					}
					for _, e := range r.Escalations {
						fmt.Fprintf(out, "[session %s] pending #%d %s %s (%s)\n",
							pid, e.ID, e.Operation, e.Resource, e.Status)
					}
					return nil
				}
				if e, ok := session.DecodeAsEvent(msg); ok {
					fmt.Fprintf(out, "[session %s] ESCALATION #%d %s %s (%s)\n",
						pid, e.ID, e.Operation, e.Resource, e.Status)
				}
				return nil
			})
			if err != nil && err != context.Canceled {
				fmt.Fprintf(out, "[session %s] watch ended: %v\n", pid, err)
			}
		}()
	}

	// Initial discovery.
	if socks, err := session.ListActiveSockets(); err == nil {
		if len(socks) == 0 {
			fmt.Fprintln(out, "(no active sessions yet — waiting)")
		}
		for _, s := range socks {
			subscribe(s)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			socks, err := session.ListActiveSockets()
			if err != nil {
				continue
			}
			seen := make(map[string]bool, len(socks))
			for _, s := range socks {
				seen[s] = true
				subscribe(s)
			}
			// Drop subscriptions to sockets that have gone away.
			for path, cancel := range watching {
				if !seen[path] {
					cancel()
					delete(watching, path)
					pid := strings.TrimSuffix(filepath.Base(path), ".sock")
					fmt.Fprintf(out, "[session %s] disconnected\n", pid)
				}
			}
		}
	}
}

// reviewCmd is the rampart review subcommand (FR58, FR39).
// Lists accumulated escape hatches from config.json and prompts the user to
// incorporate, discard, or skip each entry.
func reviewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "review",
		Short: "Review and act on accumulated escape hatch requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := defaultEngineConfigPath()
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
		force        bool
		noCA         bool
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

Re-running on an already-initialized repo errors by default. Use --force to
silently overwrite the .rampart/ scaffold (the CA is left alone). Use
--rotate when you also want to replace the existing CA. --no-ca skips
the MITM CA step entirely (handy over SSH where Keychain prompts can't
appear). --install-hooks also installs tmux and shell hook templates.
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
			alreadyScaffolded := false
			if _, err := os.Stat(rampartDir); err == nil {
				alreadyScaffolded = true
				if !force && !rotate {
					return fmt.Errorf(".rampart/ already exists — edit it manually, re-run with --force to overwrite the scaffold, or --rotate to also rotate the CA")
				}
			}
			if err := scaffoldRampartDir(rampartDir, projectName); err != nil {
				return fmt.Errorf("scaffolding .rampart/: %w", err)
			}
			verb := "Created"
			if alreadyScaffolded {
				verb = "Overwrote"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s .rampart/ for project %q\n", verb, projectName)
			fmt.Fprintf(cmd.OutOrStdout(), "  .rampart/defaults.hcl\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  .rampart/profiles/%s/default.hcl\n", projectName)

			// --- 4. MITM CA ---
			switch {
			case noCA:
				fmt.Fprintln(cmd.OutOrStdout(), "MITM CA: skipped (--no-ca). Re-run 'rampart init --force' from a GUI session to install it later.")
			default:
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
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing .rampart/ scaffold (CA is left alone)")
	cmd.Flags().BoolVar(&noCA, "no-ca", false, "Skip MITM CA install (useful over SSH where Keychain prompts can't appear)")
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

// listCmd is the rampart list subcommand: shows registered agents or profiles
// from all scopes (global, repo, project) discovered from the current git root.
func listCmd() *cobra.Command {
	var namesOnly bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered agents or profiles",
		Long: strings.TrimSpace(`
List the agents or profiles visible to rampart from the current working directory.

Subcommands:
  agents    Show all agents from global, repo, and project scope
  profiles  Show all profiles defined in the current repo
`),
	}

	cmd.AddCommand(listAgentsCmd(&namesOnly))
	cmd.AddCommand(listProfilesCmd(&namesOnly))
	cmd.PersistentFlags().BoolVar(&namesOnly, "names-only", false, "Print only resolution names, one per line (no source paths)")
	return cmd
}

func listAgentsCmd(namesOnly *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "agents",
		Short: "List all registered agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := openRegistry()
			if err != nil {
				return err
			}
			printAgents(cmd.OutOrStdout(), reg.ListAgents(), *namesOnly)
			return nil
		},
	}
}

func listProfilesCmd(namesOnly *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List all registered profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := openRegistry()
			if err != nil {
				return err
			}
			printProfiles(cmd.OutOrStdout(), reg.ListProfiles(), *namesOnly)
			return nil
		},
	}
}

// openRegistry loads the config registry from the current git root and the
// global share directory. Used by `rampart list` subcommands.
func openRegistry() (*config.Registry, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("getting working directory: %w", err)
	}
	gitRoot := config.FindGitRoot(wd)
	reg, err := config.NewRegistryWithBundled(gitRoot, config.GlobalShareDir(), bundledLibraryFS())
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return reg, nil
}

func printAgents(out io.Writer, infos []config.AgentInfo, namesOnly bool) {
	if namesOnly {
		for _, a := range infos {
			for _, name := range a.Aliases {
				fmt.Fprintln(out, name)
			}
		}
		return
	}
	if len(infos) == 0 {
		fmt.Fprintln(out, "no agents registered")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tSOURCE")
	for _, a := range infos {
		fmt.Fprintf(tw, "%s\t%s\n", strings.Join(a.Aliases, ", "), displayPath(a.SourceFile))
	}
	_ = tw.Flush()
}

func printProfiles(out io.Writer, infos []config.ProfileInfo, namesOnly bool) {
	if namesOnly {
		for _, p := range infos {
			for _, name := range p.Aliases {
				fmt.Fprintln(out, name)
			}
		}
		return
	}
	if len(infos) == 0 {
		fmt.Fprintln(out, "no profiles registered")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROFILE\tSOURCE")
	for _, p := range infos {
		fmt.Fprintf(tw, "%s\t%s\n", strings.Join(p.Aliases, ", "), displayPath(p.SourceFile))
	}
	_ = tw.Flush()
}

// displayPath replaces $HOME prefix with ~ for compactness.
func displayPath(p string) string {
	if p == "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
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
