//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// measureMaxRSS runs the binary with 'version' and returns peak resident set
// size in bytes using wait4 rusage (ru_maxrss is in kilobytes on Linux).
func measureMaxRSS(bin string) (int64, error) {
	cmd := exec.Command(bin, "version")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start: %w", err)
	}

	// Read /proc/<pid>/status to get VmRSS while the process is alive.
	pid := cmd.Process.Pid
	rssBytes, statErr := readProcRSSKB(pid)

	if err := cmd.Wait(); err != nil {
		// The process may have exited before we could read status — use rusage.
		if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			return usage.Maxrss * 1024, nil // ru_maxrss in KB on Linux
		}
		return 0, fmt.Errorf("wait: %w", err)
	}

	if statErr != nil {
		// Fall back to rusage from ProcessState.
		if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			return usage.Maxrss * 1024, nil
		}
		return 0, fmt.Errorf("reading /proc status: %w", statErr)
	}

	// Return the larger of the two readings.
	rusageKB := int64(0)
	if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
		rusageKB = usage.Maxrss
	}
	if rusageKB*1024 > rssBytes {
		return rusageKB * 1024, nil
	}
	return rssBytes, nil
}

// readProcRSSKB reads VmRSS from /proc/<pid>/status and returns bytes.
func readProcRSSKB(pid int) (int64, error) {
	path := fmt.Sprintf("/proc/%d/status", pid)
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parsing VmRSS: %w", err)
			}
			return kb * 1024, nil
		}
	}
	return 0, fmt.Errorf("VmRSS not found in /proc/%d/status", pid)
}
