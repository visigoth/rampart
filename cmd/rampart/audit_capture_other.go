//go:build !darwin

package main

import (
	"io"

	"github.com/visigoth/rampart/internal/supervisor"
)

// wrapPostStartForAudit is a no-op outside darwin — fs_usage is a
// macOS-only tool. Linux's audit-mode capture should use seccomp's
// SECCOMP_RET_LOG via the existing engine instead, which doesn't
// need an out-of-band process.
func wrapPostStartForAudit(
	original func(pid int) ([]supervisor.Subsystem, error),
	mode string,
	stderr io.Writer,
) func(pid int) ([]supervisor.Subsystem, error) {
	return original
}
