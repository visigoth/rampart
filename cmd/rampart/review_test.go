package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/visigoth/rampart/internal/supervisor"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func writeConfigJSON(t *testing.T, dir string, recs []supervisor.EscalationRecord) string {
	t.Helper()
	cfg := reviewConfigFile{Approvals: recs}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func writeProfileHCL(t *testing.T, rampartDir, profileName, content string) string {
	t.Helper()
	hclPath, _ := profileHCLPath(rampartDir, profileName)
	if err := os.MkdirAll(filepath.Dir(hclPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(hclPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write hcl: %v", err)
	}
	return hclPath
}

func readConfigJSON(t *testing.T, path string) []supervisor.EscalationRecord {
	t.Helper()
	recs, err := loadEscalationRecords(path)
	if err != nil {
		t.Fatalf("loadEscalationRecords: %v", err)
	}
	return recs
}

func newRecord(agent, profile, op, pattern string) supervisor.EscalationRecord {
	return supervisor.EscalationRecord{
		AgentName:   agent,
		ProfileName: profile,
		Operation:   op,
		Pattern:     pattern,
		CreatedAt:   time.Now(),
	}
}

// --------------------------------------------------------------------------
// RunReview: empty config
// --------------------------------------------------------------------------

func TestRunReview_EmptyConfig_PrintsNoPending(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	rampartDir := filepath.Join(dir, ".rampart")

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader(""), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}
	if !strings.Contains(out.String(), "No pending escalations") {
		t.Errorf("expected 'No pending escalations', got: %q", out.String())
	}
}

func TestRunReview_MissingConfigFile_NoPanic(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "does-not-exist.json")
	var out bytes.Buffer
	err := RunReview(configPath, dir, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("RunReview with missing config should succeed: %v", err)
	}
}

// --------------------------------------------------------------------------
// RunReview: skip
// --------------------------------------------------------------------------

func TestRunReview_Skip_LeavesRecordIntact(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/tmp/foo"),
	})
	rampartDir := filepath.Join(dir, ".rampart")

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("s\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	recs := readConfigJSON(t, configPath)
	if len(recs) != 1 {
		t.Errorf("expected 1 record after skip, got %d", len(recs))
	}
}

// --------------------------------------------------------------------------
// RunReview: discard
// --------------------------------------------------------------------------

func TestRunReview_Discard_RemovesFromConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/tmp/foo"),
		newRecord("coding", "proj/default", "write", "/tmp/bar"),
	})
	rampartDir := filepath.Join(dir, ".rampart")

	// Discard first, skip second.
	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("d\ns\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	recs := readConfigJSON(t, configPath)
	if len(recs) != 1 {
		t.Errorf("expected 1 record after discard, got %d", len(recs))
	}
	if recs[0].Pattern != "/tmp/bar" {
		t.Errorf("wrong record survived: %v", recs[0])
	}
}

func TestRunReview_DiscardAll_WritesEmptyApprovals(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/tmp/foo"),
	})
	rampartDir := filepath.Join(dir, ".rampart")

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("d\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	recs := readConfigJSON(t, configPath)
	if len(recs) != 0 {
		t.Errorf("expected 0 records after discard-all, got %d", len(recs))
	}
}

func TestRunReview_Discard_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/tmp/foo"),
	})
	rampartDir := filepath.Join(dir, ".rampart")

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("d\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	// tmp file should be gone after rename.
	tmpPath := configPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("tmp file should be removed after atomic rename")
	}
}

// --------------------------------------------------------------------------
// RunReview: incorporate
// --------------------------------------------------------------------------

func TestRunReview_Incorporate_AddsToReadList(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	writeProfileHCL(t, rampartDir, "proj/default", `
profile "default" {
  workdir = "."
  write   = ["."]
}
`)
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/usr/include"),
	})

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	if !strings.Contains(out.String(), "Incorporated.") {
		t.Errorf("expected 'Incorporated.' in output: %q", out.String())
	}

	// Verify HCL now contains the path.
	hclPath, profileLabel := profileHCLPath(rampartDir, "proj/default")
	vals, err := readProfileAttrValues(mustReadFile(t, hclPath), hclPath, profileLabel, "read")
	if err != nil {
		t.Fatalf("readProfileAttrValues: %v", err)
	}
	if !contains(vals, "/usr/include") {
		t.Errorf("read list should contain /usr/include; got %v", vals)
	}
}

func TestRunReview_Incorporate_AddsToWriteList(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	writeProfileHCL(t, rampartDir, "proj/default", `
profile "default" {
  workdir = "."
  write   = ["."]
}
`)
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "write", "/var/cache"),
	})

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	hclPath, profileLabel := profileHCLPath(rampartDir, "proj/default")
	vals, err := readProfileAttrValues(mustReadFile(t, hclPath), hclPath, profileLabel, "write")
	if err != nil {
		t.Fatalf("readProfileAttrValues: %v", err)
	}
	if !contains(vals, "/var/cache") {
		t.Errorf("write list should contain /var/cache; got %v", vals)
	}
}

func TestRunReview_Incorporate_AddsToExecList(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	writeProfileHCL(t, rampartDir, "proj/default", `
profile "default" {
  workdir = "."
}
`)
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "exec", "/usr/bin/python3"),
	})

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	hclPath, profileLabel := profileHCLPath(rampartDir, "proj/default")
	vals, err := readProfileAttrValues(mustReadFile(t, hclPath), hclPath, profileLabel, "exec")
	if err != nil {
		t.Fatalf("readProfileAttrValues: %v", err)
	}
	if !contains(vals, "/usr/bin/python3") {
		t.Errorf("exec list should contain /usr/bin/python3; got %v", vals)
	}
}

func TestRunReview_Incorporate_StatOperation_UsesReadAttr(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	writeProfileHCL(t, rampartDir, "proj/default", `
profile "default" {
  workdir = "."
}
`)
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "stat", "/proc/cpuinfo"),
	})

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	hclPath, profileLabel := profileHCLPath(rampartDir, "proj/default")
	vals, err := readProfileAttrValues(mustReadFile(t, hclPath), hclPath, profileLabel, "read")
	if err != nil {
		t.Fatalf("readProfileAttrValues: %v", err)
	}
	if !contains(vals, "/proc/cpuinfo") {
		t.Errorf("stat should map to read attr; got %v", vals)
	}
}

// --------------------------------------------------------------------------
// Incorporate: duplicate guard
// --------------------------------------------------------------------------

func TestRunReview_Incorporate_DuplicateRule_ReportsAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	writeProfileHCL(t, rampartDir, "proj/default", `
profile "default" {
  workdir = "."
  read    = ["/usr/include"]
}
`)
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/usr/include"),
	})

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	if !strings.Contains(out.String(), "Already present") {
		t.Errorf("expected 'Already present' for duplicate rule; got: %q", out.String())
	}
}

// --------------------------------------------------------------------------
// Incorporate: HCL comment preservation
// --------------------------------------------------------------------------

func TestRunReview_Incorporate_PreservesHCLComments(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	const originalHCL = `// Project profile — do not edit by hand.
profile "default" {
  // Working directory.
  workdir = "."

  // Read-write access.
  write = ["."]
}
`
	writeProfileHCL(t, rampartDir, "proj/default", originalHCL)
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/etc/ssl"),
	})

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	hclPath, _ := profileHCLPath(rampartDir, "proj/default")
	result, err := os.ReadFile(hclPath)
	if err != nil {
		t.Fatalf("reading hcl: %v", err)
	}
	if !strings.Contains(string(result), "// Project profile") {
		t.Error("file-level comment should be preserved")
	}
	if !strings.Contains(string(result), "// Working directory.") {
		t.Error("inline comment should be preserved")
	}
	if !strings.Contains(string(result), "// Read-write access.") {
		t.Error("inline comment before write should be preserved")
	}
}

// --------------------------------------------------------------------------
// Incorporate: no profile name
// --------------------------------------------------------------------------

func TestRunReview_Incorporate_NoProfileName_ReportsError(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		{Operation: "read", Pattern: "/tmp/foo", CreatedAt: time.Now()},
	})

	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}
	if !strings.Contains(out.String(), "!") {
		t.Errorf("expected error indicator '!' in output; got: %q", out.String())
	}
}

// --------------------------------------------------------------------------
// profileHCLPath
// --------------------------------------------------------------------------

func TestProfileHCLPath_TwoSegment(t *testing.T) {
	path, label := profileHCLPath("/repo/.rampart", "myproject/default")
	wantPath := "/repo/.rampart/profiles/myproject/default.hcl"
	if path != wantPath {
		t.Errorf("path = %q, want %q", path, wantPath)
	}
	if label != "default" {
		t.Errorf("label = %q, want %q", label, "default")
	}
}

func TestProfileHCLPath_OneSegment(t *testing.T) {
	path, label := profileHCLPath("/repo/.rampart", "default")
	wantPath := "/repo/.rampart/profiles/default.hcl"
	if path != wantPath {
		t.Errorf("path = %q, want %q", path, wantPath)
	}
	if label != "default" {
		t.Errorf("label = %q, want %q", label, "default")
	}
}

// --------------------------------------------------------------------------
// operationToAttr
// --------------------------------------------------------------------------

func TestOperationToAttr(t *testing.T) {
	cases := []struct{ op, want string }{
		{"stat", "read"},
		{"read", "read"},
		{"write", "write"},
		{"exec", "exec"},
		{"unknown", ""},
	}
	for _, tc := range cases {
		got := operationToAttr(tc.op)
		if got != tc.want {
			t.Errorf("operationToAttr(%q) = %q, want %q", tc.op, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------------
// errAlreadyPresent
// --------------------------------------------------------------------------

func TestAppendToHCLList_DuplicateReturnsErrAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	hclPath := writeProfileHCL(t, rampartDir, "proj/default", `
profile "default" {
  workdir = "."
  read    = ["/etc/ssl"]
}
`)
	err := appendToHCLList(hclPath, "default", "read", "/etc/ssl")
	if !errors.Is(err, errAlreadyPresent) {
		t.Errorf("expected errAlreadyPresent, got %v", err)
	}
}

// --------------------------------------------------------------------------
// Group display
// --------------------------------------------------------------------------

func TestRunReview_GroupsDisplayAgentAndProfile(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfigJSON(t, dir, []supervisor.EscalationRecord{
		newRecord("browser", "web/default", "read", "/tmp/a"),
	})
	rampartDir := filepath.Join(dir, ".rampart")

	var out bytes.Buffer
	RunReview(configPath, rampartDir, strings.NewReader("s\n"), &out) //nolint

	if !strings.Contains(out.String(), "browser") {
		t.Errorf("output should show agent name 'browser'; got: %q", out.String())
	}
	if !strings.Contains(out.String(), "web/default") {
		t.Errorf("output should show profile name; got: %q", out.String())
	}
}

// --------------------------------------------------------------------------
// Integration: full round-trip with 4 records and two profiles
// --------------------------------------------------------------------------

// TestRunReview_Integration_RoundTrip is the comprehensive integration test for
// the escalation review flow (.3.3). It sets up two profile HCL files
// with comments and formatting, writes 4 EscalationRecords, and runs RunReview
// with incorporate/discard/skip/incorporate actions.
func TestRunReview_Integration_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	rampartDir := filepath.Join(dir, ".rampart")

	// Profile 1: proj/default — has existing read list and inline comments.
	const defaultProfileHCL = `// Rampart profile for project default.
// Conservative: read-write to workdir, no network.
profile "default" {
  // Working directory.
  workdir = "."

  // Read-write access to workdir.
  write = ["."]

  // Common read-only paths.
  read = ["/etc/ssl/certs"]
}
`
	writeProfileHCL(t, rampartDir, "proj/default", defaultProfileHCL)

	// Profile 2: web/prod — minimal, no existing list attrs.
	const prodProfileHCL = `// Production web agent profile.
profile "prod" {
  workdir = "/app"
}
`
	writeProfileHCL(t, rampartDir, "web/prod", prodProfileHCL)

	records := []supervisor.EscalationRecord{
		newRecord("coding", "proj/default", "read", "/usr/include"),  // [I]ncorporate
		newRecord("coding", "proj/default", "write", "/tmp/scratch"), // [D]iscard
		newRecord("coding", "proj/default", "exec", "/usr/bin/make"), // [S]kip
		newRecord("browser", "web/prod", "read", "/var/log"),          // [I]ncorporate
	}
	configPath := writeConfigJSON(t, dir, records)

	// Run review: I, D, S, I.
	var out bytes.Buffer
	if err := RunReview(configPath, rampartDir, strings.NewReader("i\nd\ns\ni\n"), &out); err != nil {
		t.Fatalf("RunReview: %v", err)
	}

	// --- proj/default.hcl: comments preserved, /usr/include added to read ---
	defaultHCLPath, defaultLabel := profileHCLPath(rampartDir, "proj/default")
	defaultContent, err := os.ReadFile(defaultHCLPath)
	if err != nil {
		t.Fatalf("reading proj/default.hcl: %v", err)
	}
	content := string(defaultContent)

	if !strings.Contains(content, "// Rampart profile for project default.") {
		t.Error("file-level comment should be preserved")
	}
	if !strings.Contains(content, "// Working directory.") {
		t.Error("inline workdir comment should be preserved")
	}
	if !strings.Contains(content, "// Common read-only paths.") {
		t.Error("inline read comment should be preserved")
	}

	readVals, err := readProfileAttrValues(defaultContent, defaultHCLPath, defaultLabel, "read")
	if err != nil {
		t.Fatalf("readProfileAttrValues default/read: %v", err)
	}
	if !contains(readVals, "/usr/include") {
		t.Errorf("read should contain /usr/include after incorporate; got %v", readVals)
	}
	if !contains(readVals, "/etc/ssl/certs") {
		t.Errorf("read should still contain /etc/ssl/certs (existing); got %v", readVals)
	}

	// --- web/prod.hcl: /var/log added to read, prod comment preserved ---
	prodHCLPath, prodLabel := profileHCLPath(rampartDir, "web/prod")
	prodContent, err := os.ReadFile(prodHCLPath)
	if err != nil {
		t.Fatalf("reading web/prod.hcl: %v", err)
	}
	if !strings.Contains(string(prodContent), "// Production web agent profile.") {
		t.Error("prod file-level comment should be preserved")
	}
	prodReadVals, err := readProfileAttrValues(prodContent, prodHCLPath, prodLabel, "read")
	if err != nil {
		t.Fatalf("readProfileAttrValues prod/read: %v", err)
	}
	if !contains(prodReadVals, "/var/log") {
		t.Errorf("prod read should contain /var/log after incorporate; got %v", prodReadVals)
	}

	// --- config.json: discard removed /tmp/scratch; skip left /usr/bin/make ---
	remaining := readConfigJSON(t, configPath)
	for _, r := range remaining {
		if r.Pattern == "/tmp/scratch" {
			t.Error("discarded record /tmp/scratch should not be in config.json")
		}
	}
	foundMake := false
	for _, r := range remaining {
		if r.Pattern == "/usr/bin/make" {
			foundMake = true
		}
	}
	if !foundMake {
		t.Error("skipped record /usr/bin/make should still be in config.json")
	}

	// --- Atomic writes: no temp files should remain ---
	if _, err := os.Stat(configPath + ".tmp"); !os.IsNotExist(err) {
		t.Error("config .tmp should not exist after atomic write")
	}
	if _, err := os.Stat(defaultHCLPath + ".rampart.tmp"); !os.IsNotExist(err) {
		t.Error("HCL .rampart.tmp should not exist after atomic write")
	}
	if _, err := os.Stat(prodHCLPath + ".rampart.tmp"); !os.IsNotExist(err) {
		t.Error("prod HCL .rampart.tmp should not exist after atomic write")
	}
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return data
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
