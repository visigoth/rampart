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

// validateSegment checks that a single pattern segment is either fully literal
// or fully wildcard (* or **), rejecting mixed segments like "foo*" or "*bar".
func validateSegment(seg, pattern string) error {
	hasStar := strings.Contains(seg, "*")
	if !hasStar {
		return nil // fully literal
	}
	// Fully wildcard segments are exactly "*" or "**".
	if seg == "*" || seg == "**" {
		return nil
	}
	return fmt.Errorf("glob pattern %q has a mixed literal+wildcard segment %q; each segment must be fully literal or fully wildcard (* or **)", pattern, seg)
}
