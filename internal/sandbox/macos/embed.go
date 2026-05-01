//go:build darwin

// Package macos provides the macOS Seatbelt sandbox backend. SBPL templates
// are embedded into the binary at build time via go:embed; FT4.1 authors the
// actual template content.
package macos

import "embed"

//go:embed sbpl/*.sb.tmpl
var EmbeddedSBPL embed.FS
