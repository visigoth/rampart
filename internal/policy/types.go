// Package policy implements capability negotiation and produces ResolvedPolicy (FT2).
package policy

import "github.com/visigoth/rampart/internal/config"

// ResolvedPolicy is ENT3: the merged result of agent requests intersected with
// profile grants, plus CLI overrides. Platform-agnostic. Consumed by both
// sandbox backends and the HTTP proxy.
type ResolvedPolicy struct {
	AgentName   string
	ProfileName string

	// Mode is the enforcement mode (enforcing or permissive). Comes from CLI or
	// config.json — NOT from the agent or profile.
	Mode string

	// Filesystem capabilities.
	FilesystemMode string   // none | read-only | read-write
	Read           []string // Resolved absolute physical paths
	Write          []string
	Exec           []string
	Workdir        string // Resolved absolute workdir path

	// Network capabilities. Profile is the sole source of runtime rules (TR16).
	NetworkMode    string   // none | filtered | full
	AllowedDomains []string // From profile
	ProxyACLs      []config.DomainConfig // From profile network block
	MitmDomains    []string              // From profile (cleared when NoTLSMITM is true)
	// UnixSockets is the set of local Unix-domain socket paths the
	// agent may connect() to. ssh-agent, gpg-agent, 1Password's
	// op-ssh-autopen agent, Docker's daemon socket, etc. Seatbelt
	// treats connect() to an AF_UNIX socket as a network-outbound
	// operation distinct from TCP/UDP, so each socket needs an
	// explicit (allow network-outbound (literal X)) emit even when
	// file-read+write on the socket inode is granted.
	UnixSockets    []string              // From profile

	// NoTLSMITM disables TLS interception. HTTPS gets domain-only filtering
	// at CONNECT time; path rules and mitm_domains are ignored on HTTPS.
	// HTTP path rules are unaffected. Source: profile.NoTLSMITM, optionally
	// overridden by MergeOptions.NoTLSMITM (CLI --no-tls-mitm).
	NoTLSMITM bool

	// CLI augmentations: bypass intersection (FR17).
	CLIExtraPaths   []string
	CLIExtraDomains []string

	// Warnings produced during compile-time validation.
	Warnings []string
}

// MergeOptions carries CLI overrides applied after intersection.
type MergeOptions struct {
	// Mode overrides the enforcement mode ("enforcing" | "permissive").
	// Empty means use the default ("enforcing").
	Mode string

	// ExtraPaths are added to the policy unconditionally (--allow-path).
	ExtraPaths []string

	// ExtraDomains are added to the policy unconditionally (--allow-domain).
	ExtraDomains []string

	// Strict causes compile-time validation mismatches to be errors instead of warnings.
	Strict bool

	// NoTLSMITM, when non-nil, overrides the profile's no_tls_mitm setting.
	// Bound from the --no-tls-mitm CLI flag only when explicitly passed
	// (cobra flag.Changed) so the default false doesn't accidentally undo a
	// profile that opted in.
	NoTLSMITM *bool
}
