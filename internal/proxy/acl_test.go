package proxy

import (
	"testing"
)

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", false},
		{"**.example.com", "sub.example.com", true},
		{"**.example.com", "deep.sub.example.com", true},
		{"**.example.com", "example.com", true}, // ** matches zero labels
		{"*", "localhost", true},         // * matches exactly one label
		{"*", "example.com", false},       // * does not match two labels
		{"**", "any.thing.here", true},
		{"registry.npmjs.org", "registry.npmjs.org", true},
		{"registry.npmjs.org", "other.npmjs.org", false},
	}
	for _, tt := range tests {
		got := MatchDomain(tt.pattern, tt.domain)
		if got != tt.want {
			t.Errorf("MatchDomain(%q, %q) = %v, want %v", tt.pattern, tt.domain, got, tt.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/api/**", "/api/v1/resource", true},
		{"/api/**", "/api/", true},
		{"/api/**", "/other/path", false},
		{"/api/*", "/api/v1", true},
		{"/api/*", "/api/v1/deep", false},
		{"/exact", "/exact", true},
		{"/exact", "/exact/more", false},
		{"/**", "/anything/goes", true},
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/d", false},
	}
	for _, tt := range tests {
		got := MatchPath(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("MatchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestSortBySpecificity_MostSpecificFirst(t *testing.T) {
	rules := []ProxyACLRule{
		{Domain: "**.example.com"},
		{Domain: "*.example.com"},
		{Domain: "sub.example.com"},
	}
	SortBySpecificity(rules)
	if rules[0].Domain != "sub.example.com" {
		t.Errorf("rules[0] = %q, want sub.example.com", rules[0].Domain)
	}
	if rules[1].Domain != "*.example.com" {
		t.Errorf("rules[1] = %q, want *.example.com", rules[1].Domain)
	}
	if rules[2].Domain != "**.example.com" {
		t.Errorf("rules[2] = %q, want **.example.com", rules[2].Domain)
	}
}

func TestFindMatchingRule_MostSpecificWins(t *testing.T) {
	rules := []ProxyACLRule{
		{Domain: "**.example.com", Items: []ACLItem{{Allow: false}}},
		{Domain: "sub.example.com", Items: []ACLItem{{Allow: true}}},
	}
	SortBySpecificity(rules)

	rule, ok := FindMatchingRule(rules, "sub.example.com")
	if !ok {
		t.Fatal("expected a matching rule")
	}
	if !rule.Items[0].Allow {
		t.Error("expected specific rule (sub.example.com) to win over wildcard (**.example.com)")
	}
}

func TestEvalRequest_EmptyItems_AllowAll(t *testing.T) {
	rule := ProxyACLRule{Domain: "example.com", Items: nil}
	if got := rule.EvalRequest("GET", "/anything"); got != VerdictAllow {
		t.Errorf("EvalRequest with empty items = %v, want VerdictAllow", got)
	}
}

func TestEvalRequest_ImplicitDeny(t *testing.T) {
	rule := ProxyACLRule{
		Domain: "example.com",
		Items:  []ACLItem{{Allow: true, Method: "GET", Paths: []string{"/allowed"}}},
	}
	if got := rule.EvalRequest("GET", "/other"); got != VerdictDeny {
		t.Errorf("EvalRequest no-match = %v, want VerdictDeny (TR13)", got)
	}
}

func TestEvalRequest_FirstMatchWins(t *testing.T) {
	rule := ProxyACLRule{
		Domain: "example.com",
		Items: []ACLItem{
			{Allow: true, Paths: []string{"/api/**"}},
			{Allow: false},
		},
	}
	if got := rule.EvalRequest("GET", "/api/v1"); got != VerdictAllow {
		t.Errorf("first-match allow: got %v, want VerdictAllow", got)
	}
	if got := rule.EvalRequest("GET", "/other"); got != VerdictDeny {
		t.Errorf("second-match deny: got %v, want VerdictDeny", got)
	}
}
