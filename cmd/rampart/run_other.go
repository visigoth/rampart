//go:build !darwin && !linux

package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

func buildSandboxedCmd(cp *compiledPolicy, flags *runFlags, args []string, workdir string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("rampart: sandboxed launch is not supported on %s", runtime.GOOS)
}
