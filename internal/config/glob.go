package config

import (
	"fmt"
	"strings"
)

// ValidateGlobPattern validates a glob pattern per TR135:
// - not empty
// - no mixed literal+wildcard segments (e.g. "foo*", "*bar")
// - no consecutive separators (e.g. "//foo" or "api..com")
// - no unsupported wildcards (?, brace expansion)
// sep is '/' for paths, '.' for domains.
func ValidateGlobPattern(pattern string, sep byte) error {
	if pattern == "" {
		return fmt.Errorf("glob pattern must not be empty")
	}
	// Check for unsupported wildcards.
	if strings.ContainsAny(pattern, "?{}[]") {
		return fmt.Errorf("glob pattern %q contains unsupported wildcard characters (?, {}); only * and ** are supported", pattern)
	}

	sepStr := string(sep)
	segments := strings.Split(pattern, sepStr)

	for i, seg := range segments {
		// Consecutive separators produce empty segments (except for leading/trailing).
		// Allow leading empty segment for paths like "/foo" (splits to ["", "foo"]).
		// Disallow internal empty segments, e.g. "//foo" → ["", "", "foo"].
		if seg == "" {
			if i == 0 && sep == '/' {
				// Leading "/" is fine for absolute paths.
				continue
			}
			if i == len(segments)-1 && sep == '/' {
				// Trailing "/" is also fine.
				continue
			}
			return fmt.Errorf("glob pattern %q contains consecutive %q separators", pattern, sepStr)
		}

		if err := validateSegment(seg, pattern); err != nil {
			return err
		}
	}
	return nil
}

// validateSegment checks that a single pattern segment is one of:
//
//   - Fully literal:  "foo"
//   - Fully wildcard: "*" or "**"
//   - Trailing-star prefix: "foo*" (literal followed by a single trailing "*")
//
// The trailing-star form is what lets policies express things like
// "any file in this dir whose name starts with .claude.json.tmp." —
// it desugars to a regex match (subpath-with-prefix) at policy
// compile time. Leading-star ("*bar") or mid-segment stars ("fo*o")
// stay rejected — they're harder to compile portably across seatbelt
// and bwrap and aren't needed by any module so far.
func validateSegment(seg, pattern string) error {
	starCount := strings.Count(seg, "*")
	if starCount == 0 {
		return nil // fully literal
	}
	// Fully wildcard segments are exactly "*" or "**".
	if seg == "*" || seg == "**" {
		return nil
	}
	// Trailing-star prefix: "prefix*" with exactly one trailing star
	// and no other stars in the segment. The literal prefix must be
	// non-empty (a bare "*" hits the case above).
	if starCount == 1 && strings.HasSuffix(seg, "*") {
		return nil
	}
	return fmt.Errorf("glob pattern %q has a mixed literal+wildcard segment %q; segments must be fully literal, fully wildcard (* or **), or a literal followed by a trailing `*`", pattern, seg)
}
