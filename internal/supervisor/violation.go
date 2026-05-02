// Cross-platform violation types for the authorization engine (FT6/FT7/FT12).
//
// Capability, ViolationEvent, Decision, and AuthEngine are shared between the
// Linux seccomp supervisor (FT6), the macOS monitor (FT7), and the auth engine
// reactor (FT12). Keeping them here (no build tag) avoids duplication.
package supervisor

import (
	"context"
	"fmt"
	"strings"
)

// Capability represents the access level required by a filtered syscall.
// Hierarchy: write > read > stat; exec > read > stat; write ⊥ exec.
type Capability int

const (
	CapStat  Capability = iota // path metadata only
	CapRead                    // open for reading
	CapWrite                   // create, modify, delete
	CapExec                    // execute binary
)

func (c Capability) String() string {
	switch c {
	case CapStat:
		return "stat"
	case CapRead:
		return "read"
	case CapWrite:
		return "write"
	case CapExec:
		return "exec"
	default:
		return fmt.Sprintf("capability(%d)", int(c))
	}
}

// capFromString is the inverse of Capability.String().
func capFromString(s string) Capability {
	switch s {
	case "read":
		return CapRead
	case "write":
		return CapWrite
	case "exec":
		return CapExec
	default:
		return CapStat
	}
}

// satisfies reports whether a cached approval at `cached` capability level
// satisfies a new request requiring `required` capability (TR71.1).
//
//   - any cached capability satisfies CapStat
//   - CapWrite or CapExec satisfies CapRead
//   - CapWrite satisfies only CapWrite (not CapExec)
//   - CapExec satisfies only CapExec (not CapWrite)
func satisfies(cached, required Capability) bool {
	if cached == required {
		return true
	}
	if required == CapStat {
		return true
	}
	if required == CapRead {
		return cached == CapWrite || cached == CapExec
	}
	return false
}

// ViolationEvent describes an intercepted syscall that the auth engine must decide.
type ViolationEvent struct {
	PID      uint32
	Syscall  string
	Path     string     // resolved absolute path
	Required Capability // minimum capability needed
	NotifID  uint64     // platform-specific notification ID; 0 on macOS
}

// Decision indicates whether the auth engine permits or denies the request.
type Decision bool

const (
	Allow Decision = true
	Deny  Decision = false
)

// AuthEngine is consulted for every intercepted syscall or file access.
type AuthEngine interface {
	Authorize(ctx context.Context, ev ViolationEvent) Decision
}

// DenyAllEngine denies every request. Useful as a safe default.
type DenyAllEngine struct{}

func (DenyAllEngine) Authorize(_ context.Context, _ ViolationEvent) Decision { return Deny }

// AllowAllEngine allows every request. Useful for permissive mode / tests.
type AllowAllEngine struct{}

func (AllowAllEngine) Authorize(_ context.Context, _ ViolationEvent) Decision { return Allow }

// matchGlob reports whether path matches pattern.
// Supports * (matches exactly one path segment) and ** (matches zero or more segments).
// Segments are split on "/"; empty segments (leading/trailing slashes) are ignored.
func matchGlob(pattern, path string) bool {
	return matchSegments(splitPathSegments(pattern), splitPathSegments(path))
}

func splitPathSegments(s string) []string {
	var parts []string
	for _, p := range strings.Split(s, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func matchSegments(pat, seg []string) bool {
	if len(pat) == 0 {
		return len(seg) == 0
	}
	if pat[0] == "**" {
		if len(pat) == 1 {
			return true // ** at end matches everything remaining
		}
		// ** matches zero or more segments; try each count
		for i := 0; i <= len(seg); i++ {
			if matchSegments(pat[1:], seg[i:]) {
				return true
			}
		}
		return false
	}
	if len(seg) == 0 {
		return false
	}
	if pat[0] != "*" && pat[0] != seg[0] {
		return false
	}
	return matchSegments(pat[1:], seg[1:])
}
