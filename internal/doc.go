// Package rampart is the parent package for rampart's internal libraries.
//
// Subpackages:
//
//   - config: HCL config loading and agent/profile registry (FT1) [planned]
//   - policy: capability merging and ResolvedPolicy (FT2) [planned]
//   - paths: absolute physical path resolution (FT3) [planned]
//   - profiles: pre-baked agent HCL profiles (embedded via go:embed)
//   - sandbox/macos: Seatbelt SBPL backend, SBPL templates (embedded; darwin-only)
//   - sandbox/linux: bwrap + seccomp + iptables backend (FT5) [planned]
//   - supervisor: lifecycle, authorization engine (FT6, FT7, FT12) [planned]
//   - proxy: HTTP forward proxy with method+path ACLs (FT16) [planned]
//   - presence: session socket and presence detection (FT9) [planned]
//   - tmux: pane management (FT10) [planned]
//   - hook: escalation hook executor (FT11) [planned]
//   - glob: pattern matching engine (TR125-TR136) [planned]
//
// See .plans/rampart/ for design documents.
package rampart
