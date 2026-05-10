// Package config implements HCL policy config loading, validation, and agent/profile
// registry indexing for the rampart policy engine (FT1).
package config

import "github.com/hashicorp/hcl/v2"

// AgentConfig is ENT1: an agent capability declaration loaded from HCL.
type AgentConfig struct {
	Name        string          `hcl:",label"`
	Description string          `hcl:"description,optional"`
	Filesystem  string          `hcl:"filesystem,attr"`
	Read        []string        `hcl:"read,optional"`
	Write       []string        `hcl:"write,optional"`
	Exec        []string        `hcl:"exec,optional"`
	NetworkMode string          `hcl:"network_mode,attr"`
	Domains     []string        `hcl:"domains,optional"`
	Toolchains  []string        `hcl:"toolchains,optional"`
	Network     *NetworkConfig  `hcl:"network,block"`
	Remain      hcl.Body        `hcl:",remain"`

	// SourceFile is set by the loader after parsing; not an HCL field.
	SourceFile string
}

// ProfileConfig is ENT2: a project profile loaded from HCL.
type ProfileConfig struct {
	Name           string          `hcl:",label"`
	Workdir        string          `hcl:"workdir,attr"`
	Read           []string        `hcl:"read,optional"`
	Write          []string        `hcl:"write,optional"`
	Exec           []string        `hcl:"exec,optional"`
	AllowedDomains []string        `hcl:"allowed_domains,optional"`
	MitmDomains    []string        `hcl:"mitm_domains,optional"`
	// NoTLSMITM disables TLS interception (man-in-the-middle) for this profile.
	// HTTPS still flows through the proxy with domain-level allow/deny at
	// CONNECT time, but path rules are not enforced for HTTPS (HTTP is
	// unaffected). When true, no MITM CA is required at runtime.
	NoTLSMITM      bool            `hcl:"no_tls_mitm,optional"`
	Toolchains     []string        `hcl:"toolchains,optional"`
	Network        *NetworkConfig  `hcl:"network,block"`
	Remain         hcl.Body        `hcl:",remain"`

	// SourceFile is set by the loader after parsing; not an HCL field.
	SourceFile string

	// Use is the parsed list of `use "<path>" { ... }` blocks declared in
	// the profile. Populated by ParseProfileFile via a second-pass partial
	// decode of Remain. The expander resolves these against the module
	// search path and merges contributions into Read/Write/Exec/Network.
	Use []*UseBlock
}

// DefaultsConfig is the parsed representation of defaults.hcl.
type DefaultsConfig struct {
	DefaultAgent   string `hcl:"default_agent,optional"`
	DefaultProfile string `hcl:"default_profile,optional"`
	Remain         hcl.Body `hcl:",remain"`
}

// NetworkConfig holds the network block within an agent or profile config.
type NetworkConfig struct {
	Domains []DomainConfig `hcl:"domain,block"`
	Remain  hcl.Body       `hcl:",remain"`
}

// DomainConfig represents a single labeled domain block.
type DomainConfig struct {
	Pattern string        `hcl:",label"`
	Allow   []RuleConfig  `hcl:"allow,block"`
	Deny    []RuleConfig  `hcl:"deny,block"`
	Remain  hcl.Body      `hcl:",remain"`
}

// RuleConfig is an allow or deny rule within a domain block.
type RuleConfig struct {
	Method string   `hcl:",label"`
	Paths  []string `hcl:"paths,optional"`
	Remain hcl.Body `hcl:",remain"`
}

// agentFile is the top-level schema when parsing a file containing agent blocks.
type agentFile struct {
	Agents []AgentConfig `hcl:"agent,block"`
	Remain hcl.Body      `hcl:",remain"`
}

// profileFile is the top-level schema when parsing a file containing profile blocks.
type profileFile struct {
	Profiles []ProfileConfig `hcl:"profile,block"`
	Remain   hcl.Body        `hcl:",remain"`
}

// defaultsFile is the top-level schema for a defaults.hcl file.
type defaultsFile struct {
	Defaults []DefaultsConfig `hcl:"defaults,block"`
	Remain   hcl.Body         `hcl:",remain"`
}
