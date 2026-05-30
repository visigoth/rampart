//go:build darwin

// Audit-mode helpers: when --mode audit is set the SBPL baseline
// flips to (allow default), so rampart's auth engine no longer sees
// denials and the agent's actual touched-paths set has to come from
// outside the engine. This file wires up fs_usage to capture that
// set while the child runs.
//
// fs_usage on macOS requires root. We attempt sudo -n (non-interactive)
// so users who have NOPASSWD configured for fs_usage get a transparent
// capture; everyone else gets a clear printed hint and the capture is
// skipped. The agent itself runs regardless — capture is best-effort.

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/visigoth/rampart/internal/supervisor"
)

// auditCaptureSubsystem spawns fs_usage against the child PID and
// streams its output to ~/.rampart/audit/<pid>.fs_usage.log. The
// subsystem keeps the capture alive until ctx is cancelled (the
// supervisor's shutdown path), then sends SIGTERM and waits for
// fs_usage to drain.
type auditCaptureSubsystem struct {
	childPID int
	logPath  string
	stderr   io.Writer
}

func newAuditCaptureSubsystem(childPID int, stderr io.Writer) (*auditCaptureSubsystem, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home dir: %w", err)
	}
	dir := filepath.Join(home, ".rampart", "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating audit dir: %w", err)
	}
	logPath := filepath.Join(dir, fmt.Sprintf("%d-%s.fs_usage.log",
		childPID, time.Now().Format("20060102T150405")))
	return &auditCaptureSubsystem{
		childPID: childPID,
		logPath:  logPath,
		stderr:   stderr,
	}, nil
}

func (a *auditCaptureSubsystem) Name() string { return "audit-fs_usage" }

func (a *auditCaptureSubsystem) Run(ctx context.Context) error {
	out, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil // best-effort: don't kill the session
	}
	defer out.Close()

	// fs_usage requires root. We try sudo -n so users with NOPASSWD
	// configured for fs_usage get the capture transparently; everyone
	// else falls through to a printed hint and skips it.
	cmd := exec.CommandContext(ctx, "sudo", "-n",
		"/usr/bin/fs_usage", "-w", "-f", "filesys",
		fmt.Sprintf("%d", a.childPID))
	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(a.stderr,
			"rampart: audit fs_usage capture disabled (couldn't spawn sudo fs_usage: %v)\n"+
				"        for a full capture, in another terminal run:\n"+
				"          sudo /usr/bin/fs_usage -w -f filesys %d >> %s\n",
			err, a.childPID, a.logPath)
		return nil
	}

	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
	}()

	if err := cmd.Wait(); err != nil {
		// Most common failure: sudo asks for a password and the -n
		// short-circuits. Surface a one-line hint so the user knows
		// they need to run fs_usage themselves for this session.
		fmt.Fprintf(a.stderr,
			"rampart: audit fs_usage capture stopped early (sudo -n likely refused).\n"+
				"        for a full capture, in another terminal run:\n"+
				"          sudo /usr/bin/fs_usage -w -f filesys %d >> %s\n",
			a.childPID, a.logPath)
	} else {
		fmt.Fprintf(a.stderr, "rampart: audit fs_usage log written to %s\n", a.logPath)
	}
	return nil
}

// wrapPostStartForAudit returns a PostStartHook that delegates to the
// existing hook and additionally spawns an audit capture subsystem
// whose lifetime tracks the supervisor's ctx. When mode != "audit"
// (and != legacy "permissive") the original hook is returned
// unchanged.
func wrapPostStartForAudit(
	original func(pid int) ([]supervisor.Subsystem, error),
	mode string,
	stderr io.Writer,
) func(pid int) ([]supervisor.Subsystem, error) {
	if mode != "audit" && mode != "permissive" {
		return original
	}
	return func(pid int) ([]supervisor.Subsystem, error) {
		var subs []supervisor.Subsystem
		if original != nil {
			s, err := original(pid)
			if err != nil {
				return nil, err
			}
			subs = append(subs, s...)
		}
		capture, err := newAuditCaptureSubsystem(pid, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "rampart: audit capture unavailable: %v\n", err)
			return subs, nil
		}
		fmt.Fprintf(stderr,
			"rampart: --mode audit — sandbox baseline is (allow default); "+
				"fs_usage capture starting for pid %d\n", pid)
		return append(subs, capture), nil
	}
}
