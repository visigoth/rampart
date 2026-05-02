package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// rampartTestBin is set by TestMain to the path of the compiled binary.
var rampartTestBin string

// TestMain compiles the rampart binary once for all tests in this package.
// Tests that need the binary check rampartTestBin != "".
func TestMain(m *testing.M) {
	bin, cleanup, err := buildRampartBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "startup_bench: building rampart binary: %v\n", err)
		// Don't fail: other tests in this package don't need the binary.
		// Set rampartTestBin to "" so startup tests skip.
	} else {
		rampartTestBin = bin
		defer cleanup()
	}
	os.Exit(m.Run())
}

// buildRampartBinary compiles the rampart binary into a temp directory.
// Returns (path, cleanupFn, error).
func buildRampartBinary() (string, func(), error) {
	dir, err := os.MkdirTemp("", "rampart-bench-*")
	if err != nil {
		return "", nil, fmt.Errorf("mkdirtemp: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }

	bin := filepath.Join(dir, "rampart")
	modRoot := moduleRootFromWD()
	if modRoot == "" {
		wd, _ := os.Getwd()
		modRoot = wd
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/rampart")
	cmd.Dir = modRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("go build: %w\n%s", err, out)
	}
	return bin, cleanup, nil
}

// moduleRootFromWD finds go.mod by walking up from os.Getwd().
// Used instead of moduleRoot(t) when we don't have a *testing.T.
func moduleRootFromWD() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	return ""
}

// BenchmarkStartup measures the wall-clock time to execute 'rampart version',
// covering the full binary-startup critical path (process start → cobra init →
// subcommand dispatch → exit).
func BenchmarkStartup(b *testing.B) {
	if rampartTestBin == "" {
		b.Skip("rampart binary not built")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command(rampartTestBin, "version")
		if err := cmd.Run(); err != nil {
			b.Fatalf("rampart version: %v", err)
		}
	}
}

// TestStartupRegression_Under100ms is a CI-failfast regression gate.
// It runs 'rampart version' 50 times and fails if the p99 exceeds 100ms (G2.1).
// Skipped in short mode and when the binary is unavailable (e.g., cross-compile).
func TestStartupRegression_Under100ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping startup regression in short mode")
	}
	if rampartTestBin == "" {
		t.Skip("rampart binary not built")
	}

	const iterations = 50
	const limit = 100 * time.Millisecond

	samples := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		cmd := exec.Command(rampartTestBin, "version")
		if err := cmd.Run(); err != nil {
			t.Fatalf("iteration %d: rampart version: %v", i, err)
		}
		samples = append(samples, time.Since(start))
	}

	p50, p99, max := percentiles(samples)
	t.Logf("startup latency (n=%d): p50=%v p99=%v max=%v", iterations, p50, p99, max)

	// Identify any stage that dominates; log for profiling insight.
	if p50 > 50*time.Millisecond {
		t.Logf("WARNING: p50 %v > 50ms; startup may be too slow", p50)
	}

	if p99 > limit {
		t.Errorf("startup p99 %v exceeds %v limit (G2.1)", p99, limit)
	}
}

// TestStartupMemoryUnder50MB verifies resident memory stays below 50MB at launch.
// Uses a helper binary invocation that runs 'rampart version' and captures the
// MaxRSS from process resource usage (linux: /proc/<pid>/status; darwin: wait4).
func TestStartupMemoryUnder50MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in short mode")
	}
	if rampartTestBin == "" {
		t.Skip("rampart binary not built")
	}

	rss, err := measureMaxRSS(rampartTestBin)
	if err != nil {
		t.Skipf("cannot measure RSS on this platform: %v", err)
	}

	const limit = 50 * 1024 * 1024 // 50 MiB
	t.Logf("rampart version MaxRSS: %d bytes (%.1f MiB)", rss, float64(rss)/1024/1024)
	if rss > limit {
		t.Errorf("MaxRSS %d bytes > 50 MiB limit", rss)
	}
}

// percentiles returns p50, p99, and max for a slice of durations.
func percentiles(samples []time.Duration) (p50, p99, max time.Duration) {
	if len(samples) == 0 {
		return
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx50 := int(math.Round(float64(len(sorted)-1) * 0.50))
	idx99 := int(math.Round(float64(len(sorted)-1) * 0.99))
	return sorted[idx50], sorted[idx99], sorted[len(sorted)-1]
}
