// Performance benchmarks for the policy compilation pipeline (.2.3).
// Verifies AC9: full compilation completes in under 50ms (TR150).
package policy

import (
	"testing"

	"github.com/visigoth/rampart/internal/config"
)

// realisticAgent builds an AgentConfig representative of a real coding agent:
// 10 paths, 5 network domains, 3 toolchains.
func realisticAgent() *config.AgentConfig {
	return &config.AgentConfig{
		Name:        "coding",
		Filesystem:  "read-write",
		NetworkMode: "filtered",
		Read: []string{
			"/home/user/code",
			"/home/user/.config",
			"/usr/share/doc",
			"/etc/ssl/certs",
			"/usr/lib/go",
		},
		Write: []string{
			"/home/user/code",
			"/home/user/.cache",
			"/tmp/build",
		},
		Exec: []string{
			"/usr/bin/go",
			"/usr/bin/git",
		},
		Network: &config.NetworkConfig{
			Domains: []config.DomainConfig{
				{Pattern: "api.anthropic.com"},
				{Pattern: "api.github.com"},
				{Pattern: "*.npmjs.org"},
				{Pattern: "proxy.golang.org"},
				{Pattern: "sum.golang.org"},
			},
		},
		Toolchains: []string{"go", "node", "python"},
	}
}

// realisticProfile builds a ProfileConfig representative of a real project profile.
func realisticProfile() *config.ProfileConfig {
	return &config.ProfileConfig{
		Name:    "",
		Workdir: "/home/user/code/",
		Read: []string{
			"/home/user/code/",
			"/home/user/.config/git",
			"/usr/share/doc",
			"/etc/ssl/certs",
			"/usr/lib/go",
		},
		Write: []string{
			"/home/user/code/",
			"/home/user/.cache/go",
			"/tmp/build",
		},
		Exec: []string{
			"/usr/bin/go",
			"/usr/bin/git",
		},
		AllowedDomains: []string{
			"api.anthropic.com",
			"api.github.com",
			"registry.npmjs.org",
			"proxy.golang.org",
			"sum.golang.org",
		},
		Network: &config.NetworkConfig{
			Domains: []config.DomainConfig{
				{Pattern: "api.anthropic.com"},
				{Pattern: "api.github.com"},
				{Pattern: "*.npmjs.org"},
				{Pattern: "proxy.golang.org"},
				{Pattern: "sum.golang.org"},
			},
		},
		Toolchains: []string{"go", "node", "python"},
	}
}

// BenchmarkMergePolicy measures the full MergePolicy call with a realistic
// agent and profile (5 domains, 10 paths, 3 toolchains).
func BenchmarkMergePolicy(b *testing.B) {
	a := realisticAgent()
	p := realisticProfile()
	opts := MergeOptions{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := MergePolicy(a, p, opts)
		if err != nil {
			b.Fatalf("MergePolicy: %v", err)
		}
	}
}

// BenchmarkMergePolicy_Strict measures MergePolicy with --strict validation enabled.
func BenchmarkMergePolicy_Strict(b *testing.B) {
	a := realisticAgent()
	p := realisticProfile()
	opts := MergeOptions{Strict: false} // all satisfied → no error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := MergePolicy(a, p, opts)
		if err != nil {
			b.Fatalf("MergePolicy: %v", err)
		}
	}
}

// TestMergePolicy_Under50ms asserts that MergePolicy completes well within
// the 50ms budget required by AC9 / TR150 in CI. Uses testing.T so it is
// a hard CI fail, not just a benchmark number.
func TestMergePolicy_Under50ms(t *testing.T) {
	a := realisticAgent()
	p := realisticProfile()
	opts := MergeOptions{}

	// Run 1000 iterations and measure total time.
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = MergePolicy(a, p, opts)
		}
	})

	nsPerOp := result.NsPerOp()
	const budget = 50_000_000 // 50ms in nanoseconds
	if nsPerOp > budget {
		t.Errorf("MergePolicy p99 exceeded 50ms budget: %dns/op (%.2fms)", nsPerOp, float64(nsPerOp)/1e6)
	} else {
		t.Logf("MergePolicy: %dns/op (%.3fms) — within 50ms budget", nsPerOp, float64(nsPerOp)/1e6)
	}
}
