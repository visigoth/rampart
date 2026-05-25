package policy

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
)

// execEnvPlaceholder matches an exec entry whose entire value is a
// single `${VAR}` reference. Whole-entry replacement is the only form
// supported in v1; in-string interpolation like "/usr/bin/${PROG}"
// is rejected so the policy stays auditable — each exec entry is
// either a literal absolute path or a single env-var placeholder.
var execEnvPlaceholder = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// ResolveExecEnvRefs expands the `${VAR}` placeholders that MergePolicy
// deferred onto rp.execPlaceholders. For each placeholder it looks up
// the parent env var, runs exec.LookPath on the value to get an
// absolute binary path, coverage-checks the result against the
// profile's exec grants, and appends successes to rp.Exec.
//
// Failures (unset var, value not on PATH, profile doesn't grant the
// resolved path) are non-fatal: a warning is appended to rp.Warnings
// and the entry is dropped. A missing $EDITOR shouldn't block launch
// — anything else in the policy still applies.
//
// Returns the deduplicated list of env-var names that were referenced
// (regardless of whether their resolution succeeded), so callers can
// confirm those names will also reach the child env via BuildEnv.
func ResolveExecEnvRefs(rp *ResolvedPolicy) []string {
	if len(rp.execPlaceholders) == 0 {
		return nil
	}
	grants := rp.profileExecGrants
	var referenced []string
	seenRef := map[string]bool{}
	for _, entry := range rp.execPlaceholders {
		m := execEnvPlaceholder.FindStringSubmatch(entry)
		if m == nil {
			// Defensive: MergePolicy only routes well-formed placeholders
			// here. Anything else is a programmer error, not user input.
			continue
		}
		varName := m[1]
		if !seenRef[varName] {
			seenRef[varName] = true
			referenced = append(referenced, varName)
		}
		val, ok := os.LookupEnv(varName)
		if !ok || val == "" {
			rp.Warnings = append(rp.Warnings, fmt.Sprintf(
				"exec entry %q dropped: env var %s is unset", entry, varName))
			continue
		}
		abs, err := exec.LookPath(val)
		if err != nil {
			rp.Warnings = append(rp.Warnings, fmt.Sprintf(
				"exec entry %q dropped: %s=%q not found on PATH (%v)",
				entry, varName, val, err))
			continue
		}
		if !isCoveredByAny(abs, grants) {
			rp.Warnings = append(rp.Warnings, fmt.Sprintf(
				"exec entry %q dropped: resolved path %q not granted by profile",
				entry, abs))
			continue
		}
		rp.Exec = append(rp.Exec, abs)
	}
	// Clear the placeholder buffer so a second call is a no-op.
	rp.execPlaceholders = nil
	return referenced
}
