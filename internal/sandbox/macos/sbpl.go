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
	UnixSockets    []string

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
	// sbplPathRule emits a Seatbelt match clause for a single policy path.
	// Distinguishes between literal subpaths and trailing-`*` filename
	// globs (e.g. "/Users/foo/.claude.json.tmp.*"), compiling the latter
	// to a (regex) match against the canonical vnode path.
	funcMap["sbplPathRule"] = sbplPathRule

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
		UnixSockets:    rp.UnixSockets,
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

// sbplPathRule returns a Seatbelt match clause for a single policy path.
//
//   - Literal paths emit `(subpath "X")` — Seatbelt's directory-tree
//     match that covers X and anything below it.
//   - Paths ending in a single trailing `*` after the last `/` (e.g.
//     "/Users/foo/.claude.json.tmp.*") emit `(regex #"...")` — the
//     glob desugars to "match X with any filename suffix replacing
//     the `*`, no further slashes." Used for atomic-write tempfile
//     patterns and similar.
//   - Trailing `**` after the last `/` would behave like subpath
//     (any depth); we collapse it to subpath form for consistency.
//
// Only trailing-`*` is supported here — the validator rejects
// leading-star or mid-segment-star patterns.
func sbplPathRule(p string) string {
	idx := strings.LastIndex(p, "/")
	last := p
	if idx >= 0 {
		last = p[idx+1:]
	}
	switch {
	case last == "**":
		// "/foo/**" → subpath on the parent.
		return fmt.Sprintf(`(subpath "%s")`, sbplEscape(p[:idx]))
	case last == "*":
		// "/foo/*" → regex on the parent, one path segment only.
		prefix := p[:idx+1] // include trailing slash
		return fmt.Sprintf(`(regex #"^%s[^/]+$")`, sbplRegexEscape(prefix))
	case strings.HasSuffix(last, "*") && !strings.Contains(last[:len(last)-1], "*"):
		// "/foo/prefix*" — last segment is a literal prefix followed
		// by trailing `*`. Match any filename starting with the
		// prefix, no further path separators.
		return fmt.Sprintf(`(regex #"^%s[^/]*$")`, sbplRegexEscape(p[:len(p)-1]))
	}
	return fmt.Sprintf(`(subpath "%s")`, sbplEscape(p))
}

// sbplRegexEscape escapes regex metacharacters that may appear in a
// policy-supplied path so the resulting regex matches the path
// literally. The Seatbelt regex flavour is POSIX-extended; this
// covers the metacharacters that show up in real-world paths.
func sbplRegexEscape(s string) string {
	// In order: backslash first so subsequent rules don't double-escape.
	replacements := []struct{ old, new string }{
		{`\`, `\\`},
		{`.`, `\.`},
		{`+`, `\+`},
		{`?`, `\?`},
		{`(`, `\(`},
		{`)`, `\)`},
		{`[`, `\[`},
		{`]`, `\]`},
		{`{`, `\{`},
		{`}`, `\}`},
		{`^`, `\^`},
		{`$`, `\$`},
		{`|`, `\|`},
		{`"`, `\"`},
	}
	for _, r := range replacements {
		s = strings.ReplaceAll(s, r.old, r.new)
	}
	return s
}
