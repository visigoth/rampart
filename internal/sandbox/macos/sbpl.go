//go:build darwin

package macos

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/visigoth/rampart/internal/policy"
)

// sbplData is the template context passed to base.sb.tmpl.
type sbplData struct {
	// Filesystem rules from ResolvedPolicy.
	ReadPaths  []string
	WritePaths []string
	ExecPaths  []string

	// Network policy.
	NetworkMode    string
	AllowedDomains []string

	// TestMode suppresses hard SIGKILL denial rules (FT17).
	TestMode bool
}

// CompileSBPL generates a Seatbelt profile string from a ResolvedPolicy.
// testMode disables the hard SIGKILL denial rules so violations return EPERM
// rather than killing the process — used for the interactive test REPL (FT17).
func CompileSBPL(rp *policy.ResolvedPolicy, testMode bool) (string, error) {
	raw, err := EmbeddedSBPL.ReadFile("sbpl/base.sb.tmpl")
	if err != nil {
		return "", fmt.Errorf("reading base SBPL template: %w", err)
	}

	funcMap := sprig.TxtFuncMap()
	// sbplEscape escapes double-quotes and backslashes inside SBPL string literals.
	funcMap["sbplEscape"] = sbplEscape

	tmpl, err := template.New("base").Funcs(funcMap).Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("parsing SBPL template: %w", err)
	}

	// Deduplicate write paths from read paths — if a path appears in both, the
	// write rule (file-read* file-write*) is more permissive and subsumes read.
	writeSet := make(map[string]bool, len(rp.Write)+len(rp.Exec))
	for _, p := range rp.Write {
		writeSet[p] = true
	}
	for _, p := range rp.Exec {
		writeSet[p] = true
	}
	var readOnly []string
	for _, p := range rp.Read {
		if !writeSet[p] {
			readOnly = append(readOnly, p)
		}
	}

	data := sbplData{
		ReadPaths:      readOnly,
		WritePaths:     rp.Write,
		ExecPaths:      rp.Exec,
		NetworkMode:    rp.NetworkMode,
		AllowedDomains: rp.AllowedDomains,
		TestMode:       testMode,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing SBPL template: %w", err)
	}
	return buf.String(), nil
}

// sbplEscape escapes characters that are special inside SBPL double-quoted
// string literals: backslash and double-quote.
func sbplEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
