//go:build !windows

package tmux

import "syscall"

// syscallExec replaces the current process image (exec(2)).
func syscallExec(path string, args []string) error {
	return syscall.Exec(path, args, nil)
}
