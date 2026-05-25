package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// docsCmd serves `rampart docs man` (and any future doc-format helpers).
//
// We render an OMNIBUS man page — one file, rampart.1 — covering every
// subcommand plus reference sections on configuration, lookup order,
// path expansion, network policy layers, and key environment + file
// locations. Cobra's built-in doc.GenManTree produces one file per
// subcommand which makes `man rampart` show only top-level flags and
// hides the actual configuration model; the hand-crafted form lets us
// document that model alongside the command reference.
func docsCmd(root *cobra.Command) *cobra.Command {
	docs := &cobra.Command{
		Use:   "docs",
		Short: "Generate documentation artifacts (man pages, etc.)",
	}

	var outputDir string
	manCmd := &cobra.Command{
		Use:   "man",
		Short: "Generate the rampart(1) omnibus man page",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := os.MkdirAll(outputDir, 0o755); err != nil {
				return fmt.Errorf("creating output dir %s: %w", outputDir, err)
			}
			out := renderOmnibusMan(root)
			return os.WriteFile(filepath.Join(outputDir, "rampart.1"), out, 0o644)
		},
	}
	manCmd.Flags().StringVar(&outputDir, "output-dir", ".", "Directory to write rampart.1 into")
	docs.AddCommand(manCmd)
	return docs
}

// renderOmnibusMan walks the cobra tree and emits a single groff man page.
func renderOmnibusMan(root *cobra.Command) []byte {
	version := strings.TrimSpace(string(versionBytes))
	if version == "" {
		version = "dev"
	}
	date := time.Now().UTC().Format("2006-01-02")

	var b bytes.Buffer

	// --- Header ---
	fmt.Fprintf(&b, ".TH RAMPART 1 %q %q %q\n", date, "Rampart "+version, "Rampart Manual")

	section(&b, "NAME")
	fmt.Fprintln(&b, "rampart \\- cross-platform sandbox wrapper for AI coding agents")

	section(&b, "SYNOPSIS")
	fmt.Fprintln(&b, ".B rampart")
	fmt.Fprintln(&b, "[\\fIflags\\fR] \\fB--\\fR \\fIcommand\\fR [\\fIargs...\\fR]")
	fmt.Fprintln(&b, ".br")
	fmt.Fprintln(&b, ".B rampart")
	fmt.Fprintln(&b, "\\fIsubcommand\\fR [\\fIflags\\fR] [\\fIargs...\\fR]")

	section(&b, "DESCRIPTION")
	fmt.Fprintln(&b, escapeProse(`rampart compiles declarative HCL policies into kernel-level sandbox
rules — Seatbelt on macOS, bubblewrap + seccomp on Linux — and launches
a target command (typically an AI coding agent) under those
restrictions. Policies are layered: a profile imports modules, agents
declare abstract capability requests, and the resolved policy is the
intersection of profile grants and agent requests.

A long-running supervisor manages the child: it streams sandbox
violation events from the kernel, consults a per-session authorization
engine, can prompt the user via a tmux pane or external hook, and on
deny in enforcing mode signals SIGKILL.

The rest of this manual covers the subcommands and the reference
sections under CONFIGURATION.`))

	// --- Flags (root) ---
	if hasFlags(root) {
		section(&b, "GLOBAL FLAGS")
		fmt.Fprintln(&b, escapeProse(`These flags apply to the default form `+
			"`rampart [flags] -- <command>`."+`. Subcommands declare their own
flag sets; see SUBCOMMANDS below for per-command options.`))
		renderFlags(&b, root.Flags())
	}

	// --- Subcommands ---
	section(&b, "SUBCOMMANDS")
	subs := sortedSubcommands(root)
	for _, sub := range subs {
		renderSubcommand(&b, sub)
	}

	// --- Configuration reference ---
	renderConfiguration(&b)

	// --- Files ---
	section(&b, "FILES")
	fileRef(&b, "~/.rampart/sessions/<pid>.sock", `Per-supervisor Unix-domain socket. `+"`rampart escalations`"+` and
`+"`rampart escalations --watch`"+` connect here.`)
	fileRef(&b, "~/.rampart/logs/<pid>-<timestamp>.log", `Diagnostic log file for an interactive supervisor session.
Default slog handler + Go's standard log package are both
redirected here so the agent's TUI stays clean. See
ENVIRONMENT below for `+"`--verbose`"+` mirroring.`)
	fileRef(&b, "<git-root>/.rampart/", `Per-repository configuration root. Holds defaults.hcl (default
agent + profile), profiles/<project>/<name>.hcl, agents.hcl, and
modules/ (per-repo override modules).`)
	fileRef(&b, "~/.local/share/rampart/{agents,modules}/", `User override library. Files placed here shadow same-named
entries in the install share dir. Rampart never writes to this
directory.`)
	fileRef(&b, "<install-share-dir>/rampart/{agents,modules}/", `Canonical install share dir, populated by the installer that placed
the rampart binary on disk (Homebrew, the bash installer, or
`+"`just install`"+`). The runtime location is computed
relative to the binary at `+"`<exe-dir>/../share/rampart`"+`,
overridable via `+"`$RAMPART_SHARE_DIR`"+`.`)
	fileRef(&b, "~/.config/rampart/{ca.pem,ca-key.pem}", `Persistent MITM CA on Linux. macOS stores the CA in the system
Keychain (file-backed when the install is adhoc-signed).`)

	// --- Environment ---
	section(&b, "ENVIRONMENT")
	envRef(&b, "TMUX", `When set, rampart's execution-mode detection picks
`+"`interactive-tmux`"+` and creates a side pane running
`+"`rampart escalations --watch`"+` for live escalation visibility.`)
	envRef(&b, "CI", `When set, forces `+"`headless`"+` mode regardless of TTY state.
Diagnostic logs stay on stderr.`)
	envRef(&b, "HTTP_PROXY, HTTPS_PROXY", `Set by rampart on the SANDBOXED child's environment when the
forward proxy is in path. The agent's HTTPS traffic transparently
flows through `+"`127.0.0.1:<random>`"+` for ACL enforcement.`)
	envRef(&b, "SSH_AUTH_SOCK", `Passed through from the launching shell to the sandboxed child.
ssh-agent / 1Password op-ssh-autopen agents work transparently
when the profile grants both file-write and the new
`+"`unix_sockets`"+` rule on the socket path.`)
	envRef(&b, "PATH, HOME, USER, TERM, LANG, SHELL, TMPDIR, XDG_RUNTIME_DIR, XDG_CACHE_HOME", `Built-in pass-through to the sandboxed child even with
`+"`--no-env`"+`.`)
	envRef(&b, "RAMPART_POLICY_MODE", `Set on the child to `+"`enforcing`"+` or `+"`permissive`"+`,
mirroring the supervisor's `+"`--mode`"+` flag.`)
	envRef(&b, "RAMPART_PROFILE", `Set on the child to the resolved profile name.`)
	envRef(&b, "RAMPART_NET", `Set on the child to `+"`none`"+`, `+"`filtered`"+`, `+"`full`"+`, or
`+"`blocked`"+` for Linux network-namespace introspection.`)
	envRef(&b, "RAMPART_SESSION_SOCK", `Set on the child to the absolute path of its session socket.
Used by tmux + shell hooks (`+"`rampart presence-push`"+`) to feed
focus / TTY-present events back to the supervisor.`)

	section(&b, "EXIT STATUS")
	fmt.Fprintln(&b, escapeProse(`rampart exits with the sandboxed child's exit status when the child
exits naturally. Non-zero rampart-side errors (config load failure,
sandbox-exec / bwrap launch failure, CA missing for MITM-required
policies, etc.) exit with 1.`))

	section(&b, "SEE ALSO")
	fmt.Fprintln(&b, escapeProse(`Repository docs under .plans/rampart/ for the design rationale (the
PRD, floorplan, contracts, TDD). The starchitect plugin's PRD-+-
floorplan workflow drives those; rampart is the canonical reference
implementation for a sandboxed-agent supervisor in the  repo.`))

	return b.Bytes()
}

// section emits a top-level .SH header.
func section(b *bytes.Buffer, title string) {
	fmt.Fprintf(b, ".SH %s\n", title)
}

// subsection emits a .SS sub-header.
func subsection(b *bytes.Buffer, title string) {
	fmt.Fprintf(b, ".SS %s\n", title)
}

// escapeProse renders a multi-line string as groff prose, with blank
// lines turning into .PP paragraph breaks and groff-special characters
// escaped.
func escapeProse(s string) string {
	parts := strings.Split(s, "\n\n")
	var out strings.Builder
	for i, p := range parts {
		if i > 0 {
			out.WriteString(".PP\n")
		}
		p = strings.TrimSpace(p)
		p = strings.ReplaceAll(p, `\`, `\\`)
		p = strings.ReplaceAll(p, "-", `\-`)
		out.WriteString(p)
		out.WriteString("\n")
	}
	return out.String()
}

// fileRef emits a .TP entry pairing a path with its description.
func fileRef(b *bytes.Buffer, path, desc string) {
	fmt.Fprintln(b, ".TP")
	fmt.Fprintf(b, ".B %s\n", strings.ReplaceAll(path, "-", `\-`))
	fmt.Fprintln(b, escapeProse(desc))
}

// envRef emits a .TP entry for an environment variable.
func envRef(b *bytes.Buffer, name, desc string) {
	fmt.Fprintln(b, ".TP")
	fmt.Fprintf(b, ".B %s\n", name)
	fmt.Fprintln(b, escapeProse(desc))
}

// sortedSubcommands returns the non-hidden subcommands of cmd, sorted
// alphabetically by Use.
func sortedSubcommands(cmd *cobra.Command) []*cobra.Command {
	var subs []*cobra.Command
	for _, s := range cmd.Commands() {
		if s.Hidden || s.Name() == "help" {
			continue
		}
		subs = append(subs, s)
	}
	sort.Slice(subs, func(i, j int) bool {
		return subs[i].Name() < subs[j].Name()
	})
	return subs
}

// renderSubcommand emits a .SS block for one subcommand: short
// description, long description (when present), and its flag table.
// Recurses one level into nested subcommands (e.g. `rampart docs man`).
func renderSubcommand(b *bytes.Buffer, cmd *cobra.Command) {
	parent := cmd.Parent()
	name := cmd.Name()
	if parent != nil && parent.Name() != "" && !cmd.HasParent() == false && parent.Name() != "rampart" {
		name = parent.Name() + " " + name
	}
	subsection(b, "rampart "+name)
	if cmd.Short != "" {
		fmt.Fprintln(b, escapeProse(cmd.Short))
	}
	if cmd.Long != "" && cmd.Long != cmd.Short {
		fmt.Fprintln(b, escapeProse(cmd.Long))
	}
	if hasFlags(cmd) {
		fmt.Fprintln(b, ".RS")
		fmt.Fprintln(b, ".PP")
		fmt.Fprintln(b, "Flags:")
		renderFlags(b, cmd.LocalFlags())
		fmt.Fprintln(b, ".RE")
	}
	for _, child := range sortedSubcommands(cmd) {
		renderSubcommand(b, child)
	}
}

// hasFlags reports whether cmd has any non-help local flags.
func hasFlags(cmd *cobra.Command) bool {
	count := 0
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "help" {
			count++
		}
	})
	return count > 0
}

// renderFlags emits .TP entries for every flag in fs, skipping --help.
func renderFlags(b *bytes.Buffer, fs *pflag.FlagSet) {
	var flags []*pflag.Flag
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" {
			return
		}
		flags = append(flags, f)
	})
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	for _, f := range flags {
		fmt.Fprintln(b, ".TP")
		label := "--" + f.Name
		if f.Shorthand != "" && f.Shorthand != " " {
			label = "-" + f.Shorthand + ", " + label
		}
		fmt.Fprintf(b, ".B %s\n", strings.ReplaceAll(label, "-", `\-`))
		usage := f.Usage
		if usage == "" {
			usage = "(no description)"
		}
		fmt.Fprintln(b, escapeProse(usage))
	}
}

// renderConfiguration emits the CONFIGURATION reference section — the
// load-bearing topics that aren't discoverable from --help and were the
// motivating reason to switch to an omnibus man page.
func renderConfiguration(b *bytes.Buffer) {
	section(b, "CONFIGURATION")

	subsection(b, "Agent and profile resolution")
	fmt.Fprintln(b, escapeProse(`When rampart starts without explicit `+"`--agent`"+` / `+"`--profile`"+`
flags it reads `+"`<git-root>/.rampart/defaults.hcl`"+` for default_agent
and default_profile. Name resolution walks three scopes from
highest precedence to lowest:`))
	fmt.Fprintln(b, ".RS")
	fmt.Fprintln(b, ".PP")
	fmt.Fprintln(b, ".IP 1. 4")
	fmt.Fprintln(b, escapeProse(`Per-repository — `+"`<git-root>/.rampart/agents.hcl`"+`,
`+"`<git-root>/.rampart/agents/<name>.hcl`"+`, and
`+"`<git-root>/.rampart/profiles/<project>/<name>.hcl`"+`. Project-
qualified profile names ("`+"`demo/limited`"+`") resolve here.`))
	fmt.Fprintln(b, ".IP 2. 4")
	fmt.Fprintln(b, escapeProse(`User override — `+"`~/.local/share/rampart/agents/`"+` and
`+"`~/.local/share/rampart/modules/`"+`. Files placed here shadow
same-named entries in the install share dir. Rampart never
writes to this directory.`))
	fmt.Fprintln(b, ".IP 3. 4")
	fmt.Fprintln(b, escapeProse(`Install share — `+"`<install-share-dir>/rampart/{agents,modules}/`"+`.
Populated by whichever installer placed the rampart binary on
disk (Homebrew, the bash installer, or `+"`just install`"+`).
The runtime location is computed relative to the binary at
`+"`<exe-dir>/../share/rampart`"+`, overridable via
`+"`$RAMPART_SHARE_DIR`"+`. Rampart no longer ships an embedded
fallback library — if no install share dir exists, only the
per-repo and user-override scopes are available.`))
	fmt.Fprintln(b, ".RE")
	fmt.Fprintln(b, escapeProse(`Bare agent names ("`+"`coding`"+`") resolve only at scopes 1–3
above. Profile names without a project prefix resolve to
"`+"`<name>/default`"+`" when present, otherwise fail.`))

	subsection(b, "Module resolution")
	fmt.Fprintln(b, escapeProse(`Modules live under `+"`modules/<category>/<name>.hcl`"+` in any of
the three resolution tiers above. A profile imports modules via
`+"`use \"category/name\" { var1 = expr1, ... }`"+`. The expander
recursively pulls in nested `+"`use`"+` blocks, evaluates variable
substitutions against each module's `+"`variable`"+` blocks (with
type checks), concatenates path and network grants, and detects
cycles via the absolute resolved path.`))
	fmt.Fprintln(b, escapeProse(`Embedded modules ship under
`+"`<binary>/assets/modules/<category>/<name>.hcl`"+`. Run
`+"`rampart list`"+` to see what's currently visible from the
working directory.`))

	subsection(b, "Profile inheritance")
	fmt.Fprintln(b, escapeProse(`A profile can declare `+"`extends = \"<other>\"`"+` (resolved with the
same lookup chain as a direct profile reference). Inheritance
semantics:`))
	fmt.Fprintln(b, ".RS")
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`Path lists (read/write/exec, allowed_domains, mitm_domains,
unix_sockets) are concatenated parent-first, then deduped.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`Network domains (the `+"`network { domain ... }`"+` block) are
concatenated.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`Workdir uses the child's value when set, else inherits the
parent's. `+"`workdir`"+` is optional at parse time when `+"`extends`"+`
is set; the registry validates that the fully-resolved profile
has one.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`no_tls_mitm is OR'd (child can loosen, can't currently tighten).`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`Cycles are rejected with a clear error.`))
	fmt.Fprintln(b, ".RE")

	subsection(b, "Path expansion")
	fmt.Fprintln(b, escapeProse(`Path strings in modules and profiles are normalized at policy-
compile time by paths.Resolve:`))
	fmt.Fprintln(b, ".RS")
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`A leading `+"`~/`"+` expands to `+"`$HOME`"+`. `+"`~user/`"+` expands via
the system passwd database.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`A bare `+"`.`"+` resolves to the git root (or to the launch CWD
when not in a git repository).`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`Other relative paths are joined with the git root.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`Symlinks are evaluated as far as the filesystem allows; the
longest existing prefix is resolved and the non-existent suffix
is appended, so paths like `+"`~/.claude/sessions/<future-id>`"+`
resolve correctly before the leaf exists.`))
	fmt.Fprintln(b, ".RE")
	fmt.Fprintln(b, escapeProse(`The HCL parser's glob validator accepts segments that are fully
literal or fully wildcard (`+"`*`"+` for a single segment, `+"`**`"+`
for zero or more). Mixed segments like `+"`foo.*`"+` are rejected.`))

	subsection(b, "Network policy layers")
	fmt.Fprintln(b, escapeProse(`Network access in rampart is enforced at two distinct layers:`))
	fmt.Fprintln(b, ".RS")
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`The HTTP forward proxy admits HTTP/HTTPS based on
`+"`network { domain ... }`"+` blocks (per-method, per-path ACLs).
The proxy listens on `+"`127.0.0.1:<random>`"+` and is injected into
the child via `+"`HTTP_PROXY`"+` / `+"`HTTPS_PROXY`"+`. HTTPS is tunneled
via CONNECT unless `+"`mitm_domains`"+` requests interception (which
requires the rampart CA installed via `+"`rampart init`"+`).`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`The kernel sandbox admits raw outbound TCP / UDP based on the
profile's `+"`allowed_domains = [...]`"+` list, emitted as
`+"`(remote tcp \"<host>:*\")`"+` on macOS Seatbelt or as iptables
rules on Linux. SSH, dial-to-DB, and anything else that doesn't
go through `+"`HTTP_PROXY`"+` falls under this layer — the proxy
doesn't see it.`))
	fmt.Fprintln(b, ".RE")
	fmt.Fprintln(b, escapeProse(`AF_UNIX sockets are a third surface: connect(2) on a Unix socket
counts as `+"`network-outbound`"+` in Seatbelt (and bind(2) as
`+"`network-bind`"+`), distinct from file-read/write on the inode.
Profiles declare allowed paths via `+"`unix_sockets = [...]`"+`; the
SBPL emit produces both outbound and bind rules with subpath
semantics so `+"`~/.ssh/cm/`"+` covers temp-renamed control sockets.`))
	fmt.Fprintln(b, escapeProse(`The profile field `+"`no_tls_mitm = true`"+` (or `+"`--no-tls-mitm`"+`
at the command line) suppresses TLS interception entirely: the
proxy stays in path for HTTP and HTTPS CONNECT routing, but
never decrypts. Path-level ACLs are unenforceable on HTTPS in
this mode; only domain-level allow/deny applies.`))

	subsection(b, "Profile fields reference")
	fmt.Fprintln(b, escapeProse(`A profile HCL file may declare:`))
	fmt.Fprintln(b, ".RS")
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`workdir — required (or supplied by extends).`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`extends — name of a profile to inherit from.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`read / write / exec — path lists for the filesystem rules.
write implies read at the capability level.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`allowed_domains — kernel-level outbound TCP/UDP allowlist.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`mitm_domains — domains for which the proxy should decrypt TLS.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`unix_sockets — AF_UNIX socket paths the agent may connect/bind.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`network — block of `+"`domain \"<pattern>\" { allow|deny ... }`"+`
proxy ACLs.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`no_tls_mitm — boolean opt-out of TLS interception.`))
	fmt.Fprintln(b, ".IP \\(bu 4")
	fmt.Fprintln(b, escapeProse(`use "category/name" { var = value ... } — import a module.`))
	fmt.Fprintln(b, ".RE")
}
