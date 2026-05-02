//go:build !linux

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// launcherCmd returns a stub on non-Linux platforms.
func launcherCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "launcher",
		Short: "Internal: seccomp fd-passing launcher (Linux only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("launcher is only supported on Linux")
		},
	}
}
