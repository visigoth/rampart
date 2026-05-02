// ACL types and matching for the rampart HTTP proxy (FT16, TR1-TR16).
package proxy

import (
	"net"
	"sort"
	"strings"

	"github.com/visigoth/rampart/internal/config"
)

// ProxyACLRule is ENT8: one domain's network filtering configuration compiled
// from the profile's DomainConfig. It holds ordered allow/deny items and a
// flag for whether HTTPS MITM is required for this domain.
type ProxyACLRule struct {
	Domain string    // domain pattern (glob, dot-separated)
	Items  []ACLItem // ordered allow/deny rules, first-match-wins (TR3)
	MITM   bool      // true = HTTPS MITM enabled (TR5)
}

// ACLItem is a single allow or deny rule within a ProxyACLRule.
type ACLItem struct {
	Allow  bool
	Method string   // "" = any method
	Paths  []string // empty = any path; glob patterns otherwise
}

// Verdict is the outcome of evaluating an ACL.
type Verdict int

const (
	VerdictAllow   Verdict = iota
	VerdictDeny              // explicitly denied or implicit deny (TR13)
	VerdictNoMatch           // no domain pattern matched the request host
)

// EvalRequest evaluates a method+path against this rule.
// Empty Items means the domain body was empty → allow all (TR4).
// If no item matches → implicit deny (TR13).
func (r ProxyACLRule) EvalRequest(method, path string) Verdict {
	if len(r.Items) == 0 {
		return VerdictAllow // TR4: empty domain body = allow all
	}
	for _, item := range r.Items {
		if item.matches(method, path) {
			if item.Allow {
				return VerdictAllow
			}
			return VerdictDeny
		}
	}
	return VerdictDeny // TR13: no match = implicit deny
}

func (item ACLItem) matches(method, path string) bool {
	if item.Method != "" && item.Method != method {
		return false
	}
	if len(item.Paths) == 0 {
		return true // no paths = any path
	}
	for _, pattern := range item.Paths {
		if MatchPath(pattern, path) {
			return true
		}
	}
	return false
}

// CompileACLRules converts DomainConfigs from a ResolvedPolicy into sorted
// ProxyACLRules ready for runtime evaluation. mitmDomains is the list of
// domains that require HTTPS MITM even without path rules.
func CompileACLRules(domains []config.DomainConfig, mitmDomains []string) []ProxyACLRule {
	mitmSet := make(map[string]bool, len(mitmDomains))
	for _, d := range mitmDomains {
		mitmSet[d] = true
	}

	rules := make([]ProxyACLRule, 0, len(domains))
	for _, dc := range domains {
		rule := ProxyACLRule{Domain: dc.Pattern}

		// MITM is auto-enabled when any rule has paths (TR5), or when the
		// domain is explicitly listed in mitmDomains.
		for _, r := range dc.Allow {
			if len(r.Paths) > 0 {
				rule.MITM = true
			}
			rule.Items = append(rule.Items, ACLItem{Allow: true, Method: r.Method, Paths: r.Paths})
		}
		for _, r := range dc.Deny {
			if len(r.Paths) > 0 {
				rule.MITM = true
			}
			rule.Items = append(rule.Items, ACLItem{Allow: false, Method: r.Method, Paths: r.Paths})
		}
		if mitmSet[dc.Pattern] {
			rule.MITM = true
		}

		rules = append(rules, rule)
	}

	SortBySpecificity(rules)
	return rules
}

// FindMatchingRule returns the most specific ProxyACLRule whose domain pattern
// matches host, or (zero, false) if none matches.
// rules must be sorted by specificity descending (via SortBySpecificity).
func FindMatchingRule(rules []ProxyACLRule, host string) (ProxyACLRule, bool) {
	domain := domainFromHost(host)
	for _, r := range rules {
		if MatchDomain(r.Domain, domain) {
			return r, true
		}
	}
	return ProxyACLRule{}, false
}

// SortBySpecificity sorts rules in-place, most specific domain first (TR11).
// Specificity: literal segments score 10; "*" scores 2; "**" scores 1.
func SortBySpecificity(rules []ProxyACLRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return domainSpecificity(rules[i].Domain) > domainSpecificity(rules[j].Domain)
	})
}

func domainSpecificity(pattern string) int {
	score := 0
	for _, seg := range strings.Split(pattern, ".") {
		switch seg {
		case "**":
			score += 1
		case "*":
			score += 2
		default:
			score += 10
		}
	}
	return score
}

// MatchPath reports whether path matches pattern.
// * matches exactly one path segment; ** matches zero or more.
func MatchPath(pattern, path string) bool {
	return matchSegments(splitNonEmpty(pattern, "/"), splitNonEmpty(path, "/"))
}

// MatchDomain reports whether domain matches pattern using DNS hierarchy
// (right-to-left comparison per TR1).
// * matches one DNS label; ** matches zero or more labels.
func MatchDomain(pattern, domain string) bool {
	pat := reverseStrings(strings.Split(pattern, "."))
	seg := reverseStrings(strings.Split(domain, "."))
	return matchSegments(pat, seg)
}

// matchSegments matches a pattern segment list against a value segment list.
// Both must be pre-split on their separator.
func matchSegments(pat, seg []string) bool {
	if len(pat) == 0 {
		return len(seg) == 0
	}
	if pat[0] == "**" {
		if len(pat) == 1 {
			return true
		}
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

func splitNonEmpty(s, sep string) []string {
	var parts []string
	for _, p := range strings.Split(s, sep) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func reverseStrings(ss []string) []string {
	cp := make([]string, len(ss))
	copy(cp, ss)
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

// domainFromHost strips port from a host:port string and returns just the host.
func domainFromHost(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
