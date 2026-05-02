//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// --- Command registration ---

func TestLauncherCmd_FlagsPresent(t *testing.T) {
	cmd := launcherCmd()
	flags := cmd.Flags()

	for _, name := range []string{"socket", "bpf-file"} {
		if flags.Lookup(name) == nil {
			t.Errorf("flag --%s not registered on launcher command", name)
		}
	}
}

func TestLauncherCmd_RequiredFlags(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"launcher"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when required flags are missing")
	}
}

func TestLauncherCmd_Use(t *testing.T) {
	cmd := launcherCmd()
	if cmd.Use == "" {
		t.Error("launcher Use should not be empty")
	}
}

// --- parseBPFFilter ---

func TestParseBPFFilter_Valid(t *testing.T) {
	// Minimal valid BPF: one instruction (BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
	filter := makeRawBPF([]unix.SockFilter{
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x7fff0000}, // BPF_RET ALLOW
	})

	path := writeTempFile(t, filter)
	filters, err := parseBPFFilter(path)
	if err != nil {
		t.Fatalf("parseBPFFilter: unexpected error: %v", err)
	}
	if len(filters) != 1 {
		t.Errorf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Code != 0x06 {
		t.Errorf("filter Code: got %04x, want 0006", filters[0].Code)
	}
	if filters[0].K != 0x7fff0000 {
		t.Errorf("filter K: got %08x, want 7fff0000", filters[0].K)
	}
}

func TestParseBPFFilter_MultipleInstructions(t *testing.T) {
	instructions := []unix.SockFilter{
		{Code: 0x20, Jt: 0, Jf: 0, K: 4},          // LD ABS offset=4
		{Code: 0x15, Jt: 0, Jf: 1, K: 0xc000003c}, // JEQ syscall_number
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x7fff0000}, // RET ALLOW
		{Code: 0x06, Jt: 0, Jf: 0, K: 0},           // RET KILL
	}
	filter := makeRawBPF(instructions)

	path := writeTempFile(t, filter)
	filters, err := parseBPFFilter(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(filters) != 4 {
		t.Errorf("expected 4 filters, got %d", len(filters))
	}
}

func TestParseBPFFilter_FileNotFound(t *testing.T) {
	_, err := parseBPFFilter("/nonexistent/bpf.bin")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseBPFFilter_Empty(t *testing.T) {
	path := writeTempFile(t, []byte{})
	_, err := parseBPFFilter(path)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestParseBPFFilter_UnalignedLength(t *testing.T) {
	// 7 bytes — not a multiple of SizeofSockFilter (8)
	path := writeTempFile(t, []byte{1, 2, 3, 4, 5, 6, 7})
	_, err := parseBPFFilter(path)
	if err == nil {
		t.Error("expected error for unaligned file length")
	}
}

// --- sendListenerFd via Unix socket pair ---

func TestSendListenerFd_TransfersFdToReceiver(t *testing.T) {
	// Create a Unix socket pair for the transfer.
	server, client := mustUnixSocketPair(t)
	defer server.Close()
	defer client.Close()

	// Create a dummy fd to transfer (use a temp file fd).
	tmpFile, err := os.CreateTemp(t.TempDir(), "rampart-test-fd-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Send the fd via the client connection.
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- sendListenerFd(client, int(tmpFile.Fd()))
	}()

	// Receive the fd via the server connection.
	receivedFd, err := recvFdFromConn(server)
	if err != nil {
		t.Fatalf("recv fd: %v", err)
	}
	defer unix.Close(receivedFd)

	if err := <-sendErr; err != nil {
		t.Fatalf("sendListenerFd: %v", err)
	}

	// Verify the received fd is valid (can stat it).
	var stat unix.Stat_t
	if err := unix.Fstat(receivedFd, &stat); err != nil {
		t.Errorf("received fd is not a valid file descriptor: %v", err)
	}
}

// --- runLauncher error paths ---

func TestRunLauncher_BPFFileNotFound(t *testing.T) {
	dir := t.TempDir()
	err := runLauncher(filepath.Join(dir, "sock"), "/nonexistent/bpf.bin", nil)
	if err == nil {
		t.Error("expected error when BPF file not found")
	}
}

func TestRunLauncher_SocketNotFound(t *testing.T) {
	// Write a minimal valid BPF file.
	filter := makeRawBPF([]unix.SockFilter{
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x7fff0000},
	})
	bpfPath := writeTempFile(t, filter)

	dir := t.TempDir()
	err := runLauncher(filepath.Join(dir, "nonexistent.sock"), bpfPath, nil)
	if err == nil {
		t.Error("expected error when socket not found")
	}
}

// --- helpers ---

// makeRawBPF serialises a slice of SockFilter structs into the raw byte format
// expected by parseBPFFilter.
func makeRawBPF(filters []unix.SockFilter) []byte {
	buf := make([]byte, len(filters)*unix.SizeofSockFilter)
	for i, f := range filters {
		off := i * unix.SizeofSockFilter
		binary.NativeEndian.PutUint16(buf[off:], f.Code)
		buf[off+2] = f.Jt
		buf[off+3] = f.Jf
		binary.NativeEndian.PutUint32(buf[off+4:], f.K)
	}
	return buf
}

// writeTempFile writes data to a temp file and returns its path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "rampart-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return f.Name()
}

// mustUnixSocketPair creates a connected pair of *net.UnixConn for testing.
func mustUnixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	makeConn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatalf("FileConn: %v", err)
		}
		return c.(*net.UnixConn)
	}
	return makeConn(fds[0]), makeConn(fds[1])
}

// recvFdFromConn receives a single fd via SCM_RIGHTS from conn.
// Uses raw.Read so the Go poller blocks until the socket is readable
// rather than returning EAGAIN immediately.
func recvFdFromConn(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4)) // space for 1 int32 fd
	var receivedFd int
	var recvErr error
	ctrlErr := raw.Read(func(fd uintptr) bool {
		_, oobn, _, _, err := unix.Recvmsg(int(fd), buf, oob, 0)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return false // not ready; poller will retry
		}
		if err != nil {
			recvErr = err
			return true
		}
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			recvErr = err
			return true
		}
		for _, msg := range msgs {
			fds, err := unix.ParseUnixRights(&msg)
			if err != nil {
				recvErr = err
				return true
			}
			if len(fds) > 0 {
				receivedFd = fds[0]
			}
		}
		return true
	})
	if ctrlErr != nil {
		return -1, ctrlErr
	}
	return receivedFd, recvErr
}
