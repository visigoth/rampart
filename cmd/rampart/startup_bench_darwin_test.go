//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

// measureMaxRSS runs the binary with 'version' and returns peak resident set
// size in bytes via wait4 rusage. On Darwin ru_maxrss is in bytes (vs KB on Linux).
func measureMaxRSS(bin string) (int64, error) {
	cmd := exec.Command(bin, "version")
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("run: %w", err)
	}
	usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0, fmt.Errorf("rusage unavailable")
	}
	return int64(usage.Maxrss), nil
}
