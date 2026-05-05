package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Tests: snippet content ---

func TestTmuxHookSnippet_ContainsMarkers(t *testing.T) {
	s := tmuxHookSnippet()
	if !strings.Contains(s, tmuxHookBegin) {
		t.Error("snippet missing begin marker")
	}
	if !strings.Contains(s, tmuxHookEnd) {
		t.Error("snippet missing end marker")
	}
}

func TestTmuxHookSnippet_ContainsFocusEvents(t *testing.T) {
	s := tmuxHookSnippet()
	for _, want := range []string{"focus-in", "focus-out", "client-attached", "client-detached"} {
		if !strings.Contains(s, want) {
			t.Errorf("tmux snippet missing %q", want)
		}
	}
}

func TestTmuxHookSnippet_ContainsPresencePushCommand(t *testing.T) {
	s := tmuxHookSnippet()
	if !strings.Contains(s, "presence-push") {
		t.Error("tmux snippet should delegate to 'rampart presence-push'")
	}
}

func TestShellLoginHookSnippet_ContainsMarkers(t *testing.T) {
	s := shellLoginHookSnippet()
	if !strings.Contains(s, shellHookBegin) {
		t.Error("shell snippet missing begin marker")
	}
	if !strings.Contains(s, shellHookEnd) {
		t.Error("shell snippet missing end marker")
	}
}

func TestShellLoginHookSnippet_ContainsSessionStart(t *testing.T) {
	s := shellLoginHookSnippet()
	if !strings.Contains(s, "session-start") {
		t.Error("shell snippet should push session-start event")
	}
	if !strings.Contains(s, "RAMPART_SESSION_SOCK") {
		t.Error("shell snippet should reference RAMPART_SESSION_SOCK")
	}
}

// --- Tests: installHooksToFile ---

func TestInstallHooksToFile_CreatesFileIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	if err := installHooksToFile(path, "# hello\n", "# hello", "# unused-end"); err != nil {
		t.Fatalf("installHooksToFile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("file should be created")
	}
}

func TestInstallHooksToFile_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tmux.conf")
	snippet := tmuxHookSnippet()

	if err := installHooksToFile(path, snippet, tmuxHookBegin, tmuxHookEnd); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if err := installHooksToFile(path, snippet, tmuxHookBegin, tmuxHookEnd); err != nil {
		t.Fatalf("second install: %v", err)
	}

	data, _ := os.ReadFile(path)
	count := strings.Count(string(data), tmuxHookBegin)
	if count != 1 {
		t.Errorf("begin marker should appear exactly once after second install, got %d", count)
	}
}

func TestInstallHooksToFile_AppendsToExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tmux.conf")

	existing := "# existing content\nset -g mouse on\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	snippet := tmuxHookSnippet()
	if err := installHooksToFile(path, snippet, tmuxHookBegin, tmuxHookEnd); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, "set -g mouse on") {
		t.Error("existing content should be preserved")
	}
	if !strings.Contains(s, tmuxHookBegin) {
		t.Error("hook section should be appended")
	}
}

func TestInstallHooksToFile_ReplacesExistingSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tmux.conf")

	oldSnippet := tmuxHookBegin + "\n# old hooks\n" + tmuxHookEnd + "\n"
	initial := "# preamble\n" + oldSnippet + "# postamble\n"
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	newSnippet := tmuxHookSnippet()
	if err := installHooksToFile(path, newSnippet, tmuxHookBegin, tmuxHookEnd); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, _ := os.ReadFile(path)
	s := string(data)
	if strings.Contains(s, "# old hooks") {
		t.Error("old hooks section should be replaced")
	}
	if !strings.Contains(s, "client-attached") {
		t.Error("new hooks should be present")
	}
	// Preamble and postamble should survive.
	if !strings.Contains(s, "# preamble") {
		t.Error("preamble should be preserved")
	}
}

// --- Tests: installTmuxHooks / installShellHooks ---

func TestInstallTmuxHooks_WritesHookSnippet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".tmux.conf")

	if err := installTmuxHooks(path); err != nil {
		t.Fatalf("installTmuxHooks: %v", err)
	}

	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, "client-attached") {
		t.Error("tmux.conf missing client-attached hook")
	}
	if !strings.Contains(s, "client-detached") {
		t.Error("tmux.conf missing client-detached hook")
	}
}

func TestInstallShellHooks_WritesHookSnippet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".bashrc")

	if err := installShellHooks(path); err != nil {
		t.Fatalf("installShellHooks: %v", err)
	}

	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, "session-start") {
		t.Error(".bashrc missing session-start hook")
	}
	if !strings.Contains(s, "RAMPART_SESSION_SOCK") {
		t.Error(".bashrc missing RAMPART_SESSION_SOCK reference")
	}
}

// --- Tests: initCmd --install-hooks ---

func TestInitCmd_InstallHooks_WritesHookFiles(t *testing.T) {
	skipIfNoKeychainEntitlement(t)
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")

	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--project", "test", "--install-hooks"})
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --install-hooks: %v", err)
	}

	// ~/.tmux.conf should exist with hook snippet.
	tmuxConf := filepath.Join(home, ".tmux.conf")
	if data, err := os.ReadFile(tmuxConf); err != nil {
		t.Errorf("~/.tmux.conf not created: %v", err)
	} else if !strings.Contains(string(data), "client-attached") {
		t.Error("~/.tmux.conf missing client-attached hook")
	}

	// ~/.bashrc should exist with hook snippet.
	bashrc := filepath.Join(home, ".bashrc")
	if data, err := os.ReadFile(bashrc); err != nil {
		t.Errorf("~/.bashrc not created: %v", err)
	} else if !strings.Contains(string(data), "session-start") {
		t.Error("~/.bashrc missing session-start hook")
	}

	// Output should mention the installed files.
	if !strings.Contains(out.String(), ".tmux.conf") {
		t.Error("output should mention tmux.conf")
	}
}

func TestInitCmd_InstallHooks_Idempotent(t *testing.T) {
	skipIfNoKeychainEntitlement(t)
	gitDir, origDir := makeTempGitRepo(t)
	defer os.Chdir(origDir)
	if err := os.Chdir(gitDir); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")

	runInit := func() {
		cmd := rootCmd()
		cmd.SetArgs([]string{"init", "--project", "test", "--install-hooks", "--rotate"})
		cmd.SetOut(&bytes.Buffer{})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("init: %v", err)
		}
	}

	runInit()
	runInit() // second run should succeed without error

	data, _ := os.ReadFile(filepath.Join(home, ".tmux.conf"))
	count := strings.Count(string(data), tmuxHookBegin)
	if count != 1 {
		t.Errorf("tmux hook section should appear exactly once after two installs, got %d", count)
	}
}

// --- Tests: presencePushCmd ---

func TestPresencePushCmd_NoopWhenSockNotSet(t *testing.T) {
	t.Setenv("RAMPART_SESSION_SOCK", "")

	cmd := rootCmd()
	cmd.SetArgs([]string{"presence-push", "focus-in"})
	cmd.SetOut(&bytes.Buffer{})

	// Should exit 0 when RAMPART_SESSION_SOCK is empty.
	if err := cmd.Execute(); err != nil {
		t.Fatalf("presence-push with no sock should succeed: %v", err)
	}
}

func TestPresencePushCmd_SendsEventToSocket(t *testing.T) {
	sockPath := tmpSock(t)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	t.Setenv("RAMPART_SESSION_SOCK", sockPath)

	cmd := rootCmd()
	cmd.SetArgs([]string{"presence-push", "focus-in"})
	cmd.SetOut(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("presence-push: %v", err)
	}

	msg := <-received
	var parsed map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(msg)), &parsed); err != nil {
		t.Fatalf("invalid JSON received: %s", msg)
	}
	if parsed["type"] != "presence" {
		t.Errorf("type: got %q, want %q", parsed["type"], "presence")
	}
	if parsed["event"] != "focus-in" {
		t.Errorf("event: got %q, want %q", parsed["event"], "focus-in")
	}
}

func TestPresencePushCmd_SilentIfSocketMissing(t *testing.T) {
	t.Setenv("RAMPART_SESSION_SOCK", "/nonexistent/path.sock")

	cmd := rootCmd()
	cmd.SetArgs([]string{"presence-push", "focus-out"})
	cmd.SetOut(&bytes.Buffer{})

	// Should not return an error even if socket is missing (best-effort).
	if err := cmd.Execute(); err != nil {
		t.Fatalf("presence-push with missing socket should succeed: %v", err)
	}
}

// --- Tests: pushPresenceEvent ---

func TestPushPresenceEvent_WritesJSONToSocket(t *testing.T) {
	sockPath := tmpSock(t)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan []byte, 1)
	go func() {
		conn, _ := ln.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		received <- buf[:n]
	}()

	if err := pushPresenceEvent(sockPath, "focus-in"); err != nil {
		t.Fatalf("pushPresenceEvent: %v", err)
	}

	data := <-received
	line := strings.TrimSpace(string(data))
	var msg map[string]string
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		t.Fatalf("bad JSON: %s", line)
	}
	if msg["type"] != "presence" || msg["event"] != "focus-in" {
		t.Errorf("unexpected message: %v", msg)
	}
}

func TestPushPresenceEvent_EmptyPathIsNoop(t *testing.T) {
	if err := pushPresenceEvent("", "focus-in"); err != nil {
		t.Errorf("empty path should be a no-op: %v", err)
	}
}

func TestPushPresenceEvent_MissingSocketIsNoop(t *testing.T) {
	if err := pushPresenceEvent("/nonexistent/path.sock", "focus-out"); err != nil {
		t.Errorf("missing socket should be a no-op: %v", err)
	}
}

// --- Tests: pane visibility model ---

// TestTmuxHookSnippet_VisibilityBestEffort verifies that the hook snippet
// uses best-effort invocation (no hard failures on missing socket or binary).
func TestTmuxHookSnippet_VisibilityBestEffort(t *testing.T) {
	s := tmuxHookSnippet()
	// Must contain error suppression: "|| true" or "2>/dev/null".
	if !strings.Contains(s, "|| true") && !strings.Contains(s, "2>/dev/null") {
		t.Error("hook snippet should suppress errors (|| true or 2>/dev/null)")
	}
}

// TestDefaultShellRCPath_Zsh verifies zsh RC path selection.
func TestDefaultShellRCPath_Zsh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/usr/bin/zsh")

	path, err := defaultShellRCPath()
	if err != nil {
		t.Fatalf("defaultShellRCPath: %v", err)
	}
	if !strings.HasSuffix(path, ".zshrc") {
		t.Errorf("expected .zshrc for zsh, got %q", path)
	}
}

// TestDefaultShellRCPath_Bash verifies bash RC path selection.
func TestDefaultShellRCPath_Bash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")

	path, err := defaultShellRCPath()
	if err != nil {
		t.Fatalf("defaultShellRCPath: %v", err)
	}
	if !strings.HasSuffix(path, ".bashrc") {
		t.Errorf("expected .bashrc for bash, got %q", path)
	}
}

// Ensure the hooks_test file compiles with all imports used.
var _ = fmt.Sprintf
