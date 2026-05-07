//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/visigoth/rampart/internal/sandbox/macos"
)

// buildSandboxedCmd wraps the user's target command in /usr/bin/sandbox-exec
// using the SBPL profile compiled from the resolved policy (FT4).
//
// argv: /usr/bin/sandbox-exec -p <SBPL> -D HOME=... -D WORKDIR=... -D TMPDIR=...
//
//	-D CLAUDE_BIN_DIR=... <target> <target-args>...
//
// The four -D parameters fill the (param ...) references in base.sb.tmpl;
// without them sandbox-exec rejects the profile at parse time.
func buildSandboxedCmd(cp *compiledPolicy, flags *runFlags, args []string, workdir string) (*exec.Cmd, error) {
	sbpl, err := macos.CompileSBPL(cp.Policy, false)
	if err != nil {
		return nil, fmt.Errorf("compile SBPL: %w", err)
	}

	target := args[0]
	targetArgs := args[1:]

	// Resolve the target binary so CLAUDE_BIN_DIR can permit process-exec on it.
	resolvedTarget, err := exec.LookPath(target)
	if err != nil {
		return nil, fmt.Errorf("locating %s: %w", target, err)
	}
	if abs, err := filepath.Abs(resolvedTarget); err == nil {
		resolvedTarget = abs
	}
	if r, err := filepath.EvalSymlinks(resolvedTarget); err == nil {
		resolvedTarget = r
	}
	binDir := filepath.Dir(resolvedTarget)

	params := sandboxParams(workdir, binDir)

	cmdArgs := []string{"-p", sbpl}
	for k, v := range params {
		cmdArgs = append(cmdArgs, "-D", k+"="+v)
	}
	cmdArgs = append(cmdArgs, resolvedTarget)
	cmdArgs = append(cmdArgs, targetArgs...)

	cmd := exec.Command("/usr/bin/sandbox-exec", cmdArgs...)
	cmd.Env = BuildEnv(flags.envVars, flags.noEnv)
	cmd.Dir = workdir
	return cmd, nil
}

// sandboxParams returns the -D parameter map covering all (param ...)
// references in the base SBPL template: HOME, WORKDIR, TMPDIR, CLAUDE_BIN_DIR.
// Symlinks are resolved because Seatbelt subpath rules match the canonical
// /private-prefixed path.
func sandboxParams(workdir, binDir string) map[string]string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	tmp := os.Getenv("TMPDIR")
	if tmp == "" {
		tmp = "/tmp"
	}
	tmp = strings.TrimRight(tmp, "/")
	if r, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = r
	}
	if r, err := filepath.EvalSymlinks(home); err == nil {
		home = r
	}
	if r, err := filepath.EvalSymlinks(workdir); err == nil {
		workdir = r
	}
	return map[string]string{
		"HOME":           home,
		"WORKDIR":        workdir,
		"TMPDIR":         tmp,
		"CLAUDE_BIN_DIR": binDir,
	}
}
