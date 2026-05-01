// Package profiles contains pre-baked agent HCL profiles embedded into the
// rampart binary at build time. FT15.2 authors the actual policy content;
// this file establishes the embed wiring.
package profiles

import "embed"

//go:embed agents/*.hcl
var EmbeddedAgents embed.FS
