//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// launcherCmd implements the internal 'rampart launcher' subcommand (FR101-FR104).
// It is spawned by the supervisor inside a new tmux pane. It:
//  1. Reads the BPF filter compiled by CompileSeccomp.
//  2. Connects to the supervisor's Unix socket.
//  3. Calls prctl(PR_SET_NO_NEW_PRIVS) so unprivileged seccomp install is allowed.
//  4. Installs the filter via seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER) → listener fd.
//  5. Sends the listener fd to the supervisor via SCM_RIGHTS.
//  6. execve()s into bwrap with the remaining args.
func launcherCmd() *cobra.Command {
	var (
		socketPath string
		bpfFile    string
	)

	cmd := &cobra.Command{
		Use:          "launcher --socket <path> --bpf-file <path> -- <bwrap-cmd...>",
		Short:        "Internal: seccomp fd-passing launcher (Linux only)",
		Long:         "Spawned by the rampart supervisor to install seccomp and exec into bwrap.\nNot intended for direct user invocation.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLauncher(socketPath, bpfFile, args)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", "", "supervisor Unix socket path (required)")
	cmd.Flags().StringVar(&bpfFile, "bpf-file", "", "path to compiled BPF filter (required)")
	_ = cmd.MarkFlagRequired("socket")
	_ = cmd.MarkFlagRequired("bpf-file")

	return cmd
}

// runLauncher executes the full launcher lifecycle (TR101-TR104).
func runLauncher(socketPath, bpfFile string, bwrapArgs []string) error {
	filters, err := parseBPFFilter(bpfFile)
	if err != nil {
		return fmt.Errorf("launcher: %w", err)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("launcher: connect to socket: %w", err)
	}
	defer conn.Close()

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("launcher: prctl PR_SET_NO_NEW_PRIVS: %w", err)
	}

	listenerFd, err := installSeccompListener(filters)
	if err != nil {
		return fmt.Errorf("launcher: seccomp install: %w", err)
	}

	if err := sendListenerFd(conn.(*net.UnixConn), listenerFd); err != nil {
		_ = unix.Close(listenerFd)
		return fmt.Errorf("launcher: send fd: %w", err)
	}
	_ = unix.Close(listenerFd)
	conn.Close()

	return execBwrap(bwrapArgs)
}

// parseBPFFilter reads raw BPF bytecode from path and returns the filter instructions.
// The file must be non-empty and a multiple of SizeofSockFilter (8) bytes.
func parseBPFFilter(path string) ([]unix.SockFilter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read BPF filter: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("BPF filter file is empty: %s", path)
	}
	if len(data)%unix.SizeofSockFilter != 0 {
		return nil, fmt.Errorf("BPF filter file: length %d is not a multiple of %d", len(data), unix.SizeofSockFilter)
	}

	n := len(data) / unix.SizeofSockFilter
	filters := make([]unix.SockFilter, n)
	for i := range filters {
		off := i * unix.SizeofSockFilter
		filters[i].Code = binary.NativeEndian.Uint16(data[off:])
		filters[i].Jt = data[off+2]
		filters[i].Jf = data[off+3]
		filters[i].K = binary.NativeEndian.Uint32(data[off+4:])
	}
	return filters, nil
}

// installSeccompListener installs the BPF filter with SECCOMP_FILTER_FLAG_NEW_LISTENER
// and returns the resulting listener file descriptor.
// prctl(PR_SET_NO_NEW_PRIVS) must be called before this function.
func installSeccompListener(filters []unix.SockFilter) (int, error) {
	prog := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER): %w", errno)
	}
	return int(fd), nil
}

// sendListenerFd sends fd to the supervisor over conn using SCM_RIGHTS.
// A single sentinel byte is sent alongside the rights so that the SOCK_STREAM
// socket becomes readable on the receiver's epoll poller.
func sendListenerFd(conn *net.UnixConn, fd int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}
	rights := unix.UnixRights(fd)
	var sendErr error
	if ctrlErr := raw.Write(func(socketFd uintptr) bool {
		_, sendErr = unix.SendmsgN(int(socketFd), []byte{0}, rights, nil, 0)
		return sendErr != syscall.EAGAIN && sendErr != syscall.EWOULDBLOCK
	}); ctrlErr != nil {
		return ctrlErr
	}
	return sendErr
}

// execBwrap replaces the current process with bwrap invoked with args.
func execBwrap(args []string) error {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("bwrap not found in PATH: %w", err)
	}
	return syscall.Exec(bwrapPath, append([]string{"bwrap"}, args...), os.Environ())
}
