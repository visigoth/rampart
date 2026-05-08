//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/visigoth/rampart/internal/policy"
	linuxsb "github.com/visigoth/rampart/internal/sandbox/linux"
)

// buildSandboxedCmd wraps the user's target command in bwrap with the flags
// derived from the resolved policy (FT5). seccomp BPF installation via the
// fd-passing launcher is left to a future task — this minimal wiring relies
// on bwrap's namespace + bind-mount restrictions for enforcement.
//
// Relative path resolution: HCL profiles routinely use "." for workdir/read/
// write/exec to mean "the directory rampart was launched from". bwrap's
// --bind interprets paths absolutely (relative paths bind whatever the
// kernel resolves them to in bwrap's launch CWD, which is unreliable across
// nested mount namespaces). We absolutize each path against `workdir`
// before handing them to CompileBwrapFlags so the bwrap argv is fully
// canonical.
//
// argv: bwrap <flags-from-policy> -- <target> <target-args>...
func buildSandboxedCmd(cp *compiledPolicy, flags *runFlags, args []string, workdir string) (*exec.Cmd, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bwrap not found in PATH (install bubblewrap): %w", err)
	}

	resolved := absolutizePolicyPaths(cp.Policy, workdir)
	bwrapFlags := linuxsb.CompileBwrapFlags(resolved)
	cmdArgs := append([]string{}, bwrapFlags...)
	cmdArgs = append(cmdArgs, "--")
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(bwrapPath, cmdArgs...)
	cmd.Env = BuildEnv(flags.envVars, flags.noEnv)
	cmd.Dir = workdir
	return cmd, nil
}

// absolutizePolicyPaths returns a copy of rp with Workdir/Read/Write/Exec
// resolved to absolute paths against workdir. Symlinks are evaluated so the
// path matches what bwrap sees from the host filesystem.
func absolutizePolicyPaths(rp *policy.ResolvedPolicy, workdir string) *policy.ResolvedPolicy {
	out := *rp // shallow copy — we replace path slices below
	out.Workdir = absolutizePath(rp.Workdir, workdir)
	out.Read = absolutizePathSlice(rp.Read, workdir)
	out.Write = absolutizePathSlice(rp.Write, workdir)
	out.Exec = absolutizePathSlice(rp.Exec, workdir)
	return &out
}

func absolutizePathSlice(paths []string, workdir string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, absolutizePath(p, workdir))
	}
	return out
}

func absolutizePath(p, workdir string) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(workdir, p)
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}
