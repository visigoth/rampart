//go:build linux

package main

import (
	"fmt"
	"os/exec"

	linuxsb "github.com/visigoth/rampart/internal/sandbox/linux"
)

// buildSandboxedCmd wraps the user's target command in bwrap with the flags
// derived from the resolved policy (FT5). seccomp BPF installation via the
// fd-passing launcher is left to a future task — this minimal wiring relies
// on bwrap's namespace + bind-mount restrictions for enforcement.
//
// argv: bwrap <flags-from-policy> -- <target> <target-args>...
func buildSandboxedCmd(cp *compiledPolicy, flags *runFlags, args []string, workdir string) (*exec.Cmd, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bwrap not found in PATH (install bubblewrap): %w", err)
	}

	bwrapFlags := linuxsb.CompileBwrapFlags(cp.Policy)
	cmdArgs := append([]string{}, bwrapFlags...)
	cmdArgs = append(cmdArgs, "--")
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(bwrapPath, cmdArgs...)
	cmd.Env = BuildEnv(flags.envVars, flags.noEnv)
	cmd.Dir = workdir
	return cmd, nil
}
