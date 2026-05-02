//go:build linux

package supervisor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// atFDCWDArg is AT_FDCWD (-100) sign-extended to the 64-bit register value
// that appears in seccomp notification args (0xFFFFFFFFFFFFFF9C on all archs).
const atFDCWDArg uint64 = 0xFFFFFFFFFFFFFF9C

// --- classifyOpenCap ---

func TestClassifyOpenCap_ReadOnly(t *testing.T) {
	if got := classifyOpenCap(unix.O_RDONLY); got != CapRead {
		t.Errorf("O_RDONLY: got %v, want CapRead", got)
	}
}

func TestClassifyOpenCap_WriteOnly(t *testing.T) {
	if got := classifyOpenCap(unix.O_WRONLY); got != CapWrite {
		t.Errorf("O_WRONLY: got %v, want CapWrite", got)
	}
}

func TestClassifyOpenCap_RDWR(t *testing.T) {
	if got := classifyOpenCap(unix.O_RDWR); got != CapWrite {
		t.Errorf("O_RDWR: got %v, want CapWrite", got)
	}
}

func TestClassifyOpenCap_CreateImpliesWrite(t *testing.T) {
	if got := classifyOpenCap(unix.O_CREAT | unix.O_RDONLY); got != CapWrite {
		t.Errorf("O_CREAT|O_RDONLY: got %v, want CapWrite", got)
	}
}

func TestClassifyOpenCap_TruncImpliesWrite(t *testing.T) {
	if got := classifyOpenCap(unix.O_TRUNC); got != CapWrite {
		t.Errorf("O_TRUNC: got %v, want CapWrite", got)
	}
}

func TestClassifyOpenCap_OPath(t *testing.T) {
	if got := classifyOpenCap(unix.O_PATH); got != CapStat {
		t.Errorf("O_PATH: got %v, want CapStat", got)
	}
}

func TestClassifyOpenCap_OPathWithWrite(t *testing.T) {
	// O_PATH takes priority over write flags (per TR152.2).
	if got := classifyOpenCap(unix.O_PATH | unix.O_WRONLY); got != CapStat {
		t.Errorf("O_PATH|O_WRONLY: got %v, want CapStat", got)
	}
}

// --- syscallProfiles coverage ---

func TestSyscallProfiles_AllFilteredSyscallsHaveProfile(t *testing.T) {
	// These are the syscalls in the seccomp filter (TR153-TR156).
	required := []string{
		"openat", "openat2", "open", "creat",
		"fstatat", "newfstatat", "statx", "stat", "lstat",
		"faccessat", "faccessat2", "access",
		"readlinkat", "readlink",
		"unlinkat", "unlink", "rmdir",
		"renameat2", "renameat", "rename",
		"linkat", "link", "symlinkat", "symlink",
		"mkdirat", "mkdir", "mknodat", "mknod",
		"fchmodat", "fchmodat2", "fchownat", "chmod", "chown", "lchown",
		"truncate", "truncate64",
		"execve", "execveat",
	}
	for _, name := range required {
		if _, ok := syscallProfiles[name]; !ok {
			t.Errorf("syscall %q missing from syscallProfiles", name)
		}
	}
}

func TestSyscallProfiles_OpenFamilyIsfdReturning(t *testing.T) {
	for _, name := range []string{"openat", "openat2", "open", "creat"} {
		if !syscallProfiles[name].fdReturn {
			t.Errorf("syscall %q: fdReturn should be true", name)
		}
	}
}

func TestSyscallProfiles_NonOpenIsNotfdReturning(t *testing.T) {
	for _, name := range []string{"stat", "unlinkat", "execve", "fstatat"} {
		if syscallProfiles[name].fdReturn {
			t.Errorf("syscall %q: fdReturn should be false", name)
		}
	}
}

func TestSyscallProfiles_OpenatCapBasedOnFlags(t *testing.T) {
	prof := syscallProfiles["openat"]
	if prof.flagsIdx < 0 {
		t.Error("openat: flagsIdx should be >= 0")
	}
	if prof.baseCap != CapRead {
		t.Errorf("openat: baseCap %v, want CapRead", prof.baseCap)
	}
}

func TestSyscallProfiles_ExecveCapIsExec(t *testing.T) {
	if syscallProfiles["execve"].baseCap != CapExec {
		t.Error("execve: baseCap should be CapExec")
	}
}

func TestSyscallProfiles_StatCapIsStat(t *testing.T) {
	for _, name := range []string{"stat", "lstat", "fstatat", "access", "readlink"} {
		if syscallProfiles[name].baseCap != CapStat {
			t.Errorf("syscall %q: baseCap %v, want CapStat", name, syscallProfiles[name].baseCap)
		}
	}
}

func TestSyscallProfiles_WriteCap(t *testing.T) {
	for _, name := range []string{"unlinkat", "mkdir", "rename", "chmod", "truncate"} {
		if syscallProfiles[name].baseCap != CapWrite {
			t.Errorf("syscall %q: baseCap %v, want CapWrite", name, syscallProfiles[name].baseCap)
		}
	}
}

// --- readPath / resolveDirfd with fake /proc ---

// fakeProcPid creates a minimal fake /proc/<pid> directory for a test.
// Returns the directory path.
func fakeProcPid(t *testing.T, pid int, cwd string, fds map[int]string) string {
	t.Helper()
	base := t.TempDir()

	pidDir := filepath.Join(base, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}

	// cwd symlink
	if cwd != "" {
		if err := os.Symlink(cwd, filepath.Join(pidDir, "cwd")); err != nil {
			t.Fatal(err)
		}
	}

	// fd symlinks
	for n, target := range fds {
		if err := os.Symlink(target, filepath.Join(pidDir, "fd", fmt.Sprintf("%d", n))); err != nil {
			t.Fatal(err)
		}
	}

	// mem file: we write path strings at specific "addresses" by writing a
	// block of bytes where address = offset in the file.
	// Tests should use writeMemString to populate it.
	if err := os.WriteFile(filepath.Join(pidDir, "mem"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	return base
}

// writeMemString writes a null-terminated string at the given offset in the
// fake mem file, returning the offset as a uint64 "address".
func writeMemString(t *testing.T, procRoot string, pid int, offset uint64, s string) {
	t.Helper()
	memPath := filepath.Join(procRoot, fmt.Sprintf("%d/mem", pid))

	// Read existing
	data, err := os.ReadFile(memPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// Extend if needed
	need := int(offset) + len(s) + 1
	if need > len(data) {
		data = append(data, make([]byte, need-len(data))...)
	}

	copy(data[offset:], s)
	data[int(offset)+len(s)] = 0 // null terminator

	if err := os.WriteFile(memPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadPath_AbsoluteNoDir(t *testing.T) {
	const pid = 100
	const addr = uint64(0x100)
	procRoot := fakeProcPid(t, pid, "/workspace", nil)
	writeMemString(t, procRoot, pid, addr, "/etc/hosts")

	s := &SeccompSupervisor{procRoot: procRoot}
	prof := syscallProfiles["stat"] // dirfdIdx=-1, pathIdx=0
	args := []uint64{addr}

	got, err := s.readPath(pid, prof, args)
	if err != nil {
		t.Fatalf("readPath: %v", err)
	}
	if got != "/etc/hosts" {
		t.Errorf("got %q, want /etc/hosts", got)
	}
}

func TestReadPath_RelativeUsesATFDCWD(t *testing.T) {
	const pid = 101
	const addr = uint64(0x200)
	procRoot := fakeProcPid(t, pid, "/workspace/project", nil)
	writeMemString(t, procRoot, pid, addr, "src/main.go")

	s := &SeccompSupervisor{procRoot: procRoot}
	prof := syscallProfiles["openat"]
	args := []uint64{
		atFDCWDArg, // dirfd = AT_FDCWD
		addr,                          // pathname ptr
		uint64(unix.O_RDONLY),         // flags
		0,                             // mode
	}

	got, err := s.readPath(pid, prof, args)
	if err != nil {
		t.Fatalf("readPath: %v", err)
	}
	if got != "/workspace/project/src/main.go" {
		t.Errorf("got %q, want /workspace/project/src/main.go", got)
	}
}

func TestReadPath_ExplicitDirfd(t *testing.T) {
	const pid = 102
	const addr = uint64(0x300)
	fds := map[int]string{5: "/home/user/code"}
	procRoot := fakeProcPid(t, pid, "/home/user", fds)
	writeMemString(t, procRoot, pid, addr, "go.mod")

	s := &SeccompSupervisor{procRoot: procRoot}
	prof := syscallProfiles["openat"]
	args := []uint64{
		5,                     // dirfd = fd 5
		addr,                  // pathname ptr
		uint64(unix.O_RDONLY), // flags
		0,                     // mode
	}

	got, err := s.readPath(pid, prof, args)
	if err != nil {
		t.Fatalf("readPath: %v", err)
	}
	if got != "/home/user/code/go.mod" {
		t.Errorf("got %q, want /home/user/code/go.mod", got)
	}
}

func TestReadPath_ProcMemFailure(t *testing.T) {
	const pid = 103
	const addr = uint64(0x100)
	// No mem file created — /proc/103/mem doesn't exist.
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "103"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := &SeccompSupervisor{procRoot: procRoot}
	prof := syscallProfiles["stat"]
	args := []uint64{addr}

	_, err := s.readPath(pid, prof, args)
	if err == nil {
		t.Error("expected error when /proc/<pid>/mem missing")
	}
}

// --- classifyCapability ---

func TestClassifyCapability_OpenatReadOnly(t *testing.T) {
	s := &SeccompSupervisor{}
	prof := syscallProfiles["openat"]
	args := []uint64{
		atFDCWDArg,
		0x1000,
		unix.O_RDONLY,
		0,
	}
	cap, flags, err := s.classifyCapability(0, prof, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap != CapRead {
		t.Errorf("cap: got %v, want CapRead", cap)
	}
	if flags != unix.O_RDONLY {
		t.Errorf("flags: got %d, want O_RDONLY", flags)
	}
}

func TestClassifyCapability_OpenatWrite(t *testing.T) {
	s := &SeccompSupervisor{}
	prof := syscallProfiles["openat"]
	args := []uint64{
		atFDCWDArg,
		0x1000,
		unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC,
		0o644,
	}
	cap, _, err := s.classifyCapability(0, prof, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap != CapWrite {
		t.Errorf("cap: got %v, want CapWrite", cap)
	}
}

func TestClassifyCapability_OpenatOPath(t *testing.T) {
	s := &SeccompSupervisor{}
	prof := syscallProfiles["openat"]
	args := []uint64{
		atFDCWDArg,
		0x1000,
		unix.O_PATH,
		0,
	}
	cap, _, err := s.classifyCapability(0, prof, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap != CapStat {
		t.Errorf("cap: got %v, want CapStat", cap)
	}
}

func TestClassifyCapability_Stat(t *testing.T) {
	s := &SeccompSupervisor{}
	prof := syscallProfiles["stat"]
	args := []uint64{0x1000, 0x2000} // path, stat_buf
	cap, _, err := s.classifyCapability(0, prof, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap != CapStat {
		t.Errorf("cap: got %v, want CapStat", cap)
	}
}

func TestClassifyCapability_Execve(t *testing.T) {
	s := &SeccompSupervisor{}
	prof := syscallProfiles["execve"]
	args := []uint64{0x1000}
	cap, _, err := s.classifyCapability(0, prof, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap != CapExec {
		t.Errorf("cap: got %v, want CapExec", cap)
	}
}

// --- handleNotif: decision dispatch ---

// recordingAuthEngine records the events it was asked to authorize.
type recordingAuthEngine struct {
	mu      sync.Mutex
	events  []ViolationEvent
	verdict Decision
}

func (e *recordingAuthEngine) Authorize(_ context.Context, ev ViolationEvent) Decision {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
	return e.verdict
}

func (e *recordingAuthEngine) first() (ViolationEvent, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.events) == 0 {
		return ViolationEvent{}, false
	}
	return e.events[0], true
}

// recordingResponder captures NotifRespond calls.
type recordingResponder struct {
	mu    sync.Mutex
	resps []*libseccomp.ScmpNotifResp
}

func (r *recordingResponder) respond(_ libseccomp.ScmpFd, resp *libseccomp.ScmpNotifResp) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *resp
	r.resps = append(r.resps, &cp)
	return nil
}

func (r *recordingResponder) first() (*libseccomp.ScmpNotifResp, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.resps) == 0 {
		return nil, false
	}
	return r.resps[0], true
}

func buildReq(t *testing.T, syscallName string, args []uint64) *libseccomp.ScmpNotifReq {
	t.Helper()
	sc, err := libseccomp.GetSyscallFromName(syscallName)
	if err != nil {
		t.Fatalf("GetSyscallFromName(%q): %v", syscallName, err)
	}
	return &libseccomp.ScmpNotifReq{
		ID:  42,
		Pid: 200,
		Data: libseccomp.ScmpNotifData{
			Syscall: sc,
			Args:    args,
		},
	}
}

func supervisorWithFakeProc(t *testing.T, auth AuthEngine, resp *recordingResponder) (*SeccompSupervisor, string) {
	t.Helper()
	procRoot := t.TempDir()
	s := &SeccompSupervisor{
		Auth:         auth,
		Enforcing:    true,
		procRoot:     procRoot,
		notifRespFn:  resp.respond,
		notifValidFn: func(_ libseccomp.ScmpFd, _ uint64) error { return nil }, // always valid
	}
	return s, procRoot
}

func TestHandleNotif_StatAllowed(t *testing.T) {
	const pid = 200
	const addr = uint64(0x400)

	auth := &recordingAuthEngine{verdict: Allow}
	resp := &recordingResponder{}
	s, procRoot := supervisorWithFakeProc(t, auth, resp)

	fakeProcPid(t, pid, "/home", nil)
	// Re-use procRoot from the supervisor so we write to the right place.
	procRoot2 := fakeProcPid(t, pid, "/home", nil)
	_ = procRoot2
	// Write the /proc/<pid> structure under the supervisor's procRoot.
	pidDir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/home", filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}
	writeMemString(t, procRoot, pid, addr, "/etc/passwd")

	req := buildReq(t, "stat", []uint64{addr, 0x500})
	s.handleNotif(context.Background(), req)

	r, ok := resp.first()
	if !ok {
		t.Fatal("no response recorded")
	}
	if r.Flags != libseccomp.NotifRespFlagContinue {
		t.Errorf("allow: Flags %d, want %d (NotifRespFlagContinue)", r.Flags, libseccomp.NotifRespFlagContinue)
	}
	if r.Error != 0 {
		t.Errorf("allow: Error %d, want 0", r.Error)
	}

	ev, ok2 := auth.first()
	if !ok2 {
		t.Fatal("auth not consulted")
	}
	if ev.Required != CapStat {
		t.Errorf("event.Required %v, want CapStat", ev.Required)
	}
	if ev.Path != "/etc/passwd" {
		t.Errorf("event.Path %q, want /etc/passwd", ev.Path)
	}
}

func TestHandleNotif_StatDenied(t *testing.T) {
	const pid = 201
	const addr = uint64(0x400)

	auth := &recordingAuthEngine{verdict: Deny}
	resp := &recordingResponder{}
	s, procRoot := supervisorWithFakeProc(t, auth, resp)

	pidDir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/root", filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}
	writeMemString(t, procRoot, pid, addr, "/root/secret")

	req := buildReq(t, "stat", []uint64{addr, 0x500})
	req.Pid = pid
	s.handleNotif(context.Background(), req)

	r, ok := resp.first()
	if !ok {
		t.Fatal("no response recorded")
	}
	if r.Error != int32(syscallEPERM) {
		t.Errorf("deny: Error %d, want EPERM (%d)", r.Error, syscallEPERM)
	}
	if r.Flags != 0 {
		t.Errorf("deny: Flags %d, want 0", r.Flags)
	}
}

func TestHandleNotif_OpenatReadClassification(t *testing.T) {
	const pid = 202
	const addr = uint64(0x400)

	auth := &recordingAuthEngine{verdict: Allow}
	resp := &recordingResponder{}
	s, procRoot := supervisorWithFakeProc(t, auth, resp)

	pidDir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/workspace", filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}
	writeMemString(t, procRoot, pid, addr, "/workspace/main.go")

	// openat(AT_FDCWD, path, O_RDONLY) — expect CapRead event.
	// (For this test we disable fdReturn path by overriding via a modified supervisor.)
	// We patch notifAddFd by making the open fail gracefully with fallback.
	s.Enforcing = true
	req := buildReq(t, "openat", []uint64{
		atFDCWDArg,
		addr,
		unix.O_RDONLY,
		0,
	})
	req.Pid = pid
	s.handleNotif(context.Background(), req)

	ev, ok := auth.first()
	if !ok {
		t.Fatal("auth not consulted")
	}
	if ev.Required != CapRead {
		t.Errorf("event.Required %v, want CapRead", ev.Required)
	}
}

func TestHandleNotif_OpenatWriteClassification(t *testing.T) {
	const pid = 203
	const addr = uint64(0x400)

	auth := &recordingAuthEngine{verdict: Deny}
	resp := &recordingResponder{}
	s, procRoot := supervisorWithFakeProc(t, auth, resp)

	pidDir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}
	writeMemString(t, procRoot, pid, addr, "/tmp/out.txt")

	req := buildReq(t, "openat", []uint64{
		atFDCWDArg,
		addr,
		unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC,
		0o644,
	})
	req.Pid = pid
	s.handleNotif(context.Background(), req)

	ev, ok := auth.first()
	if !ok {
		t.Fatal("auth not consulted")
	}
	if ev.Required != CapWrite {
		t.Errorf("event.Required %v, want CapWrite", ev.Required)
	}
}

func TestHandleNotif_ProcReadFailure_DeniesAndNocrash(t *testing.T) {
	// /proc/<pid>/mem doesn't exist → handleNotif should log+deny, never crash.
	auth := &recordingAuthEngine{verdict: Allow}
	resp := &recordingResponder{}
	procRoot := t.TempDir() // no pid dir

	s := &SeccompSupervisor{
		Auth:         auth,
		Enforcing:    true,
		procRoot:     procRoot,
		notifRespFn:  resp.respond,
		notifValidFn: func(_ libseccomp.ScmpFd, _ uint64) error { return nil },
	}

	req := buildReq(t, "stat", []uint64{0x9999, 0})
	req.Pid = 9999
	s.handleNotif(context.Background(), req) // must not panic

	r, ok := resp.first()
	if !ok {
		t.Fatal("no response recorded")
	}
	if r.Error != int32(syscallEPERM) {
		t.Errorf("proc failure: Error %d, want EPERM", r.Error)
	}
}

func TestHandleNotif_PermissiveAllowsDenied(t *testing.T) {
	const pid = 204
	const addr = uint64(0x400)

	auth := &recordingAuthEngine{verdict: Deny}
	resp := &recordingResponder{}
	s, procRoot := supervisorWithFakeProc(t, auth, resp)
	s.Enforcing = false // permissive mode

	pidDir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}
	writeMemString(t, procRoot, pid, addr, "/root/secret")

	req := buildReq(t, "stat", []uint64{addr, 0x500})
	req.Pid = pid
	s.handleNotif(context.Background(), req)

	r, ok := resp.first()
	if !ok {
		t.Fatal("no response")
	}
	// Permissive: should be allowed (continue), not denied.
	if r.Flags != libseccomp.NotifRespFlagContinue {
		t.Errorf("permissive: Flags %d, want NotifRespFlagContinue", r.Flags)
	}
}

// TestRun_DispatchesPerNotifGoroutine verifies that the Run loop dispatches
// each notification to its own handler goroutine (TR171) without blocking.
func TestRun_DispatchesPerNotifGoroutine(t *testing.T) {
	const numNotifs = 3
	const pid = 205

	auth := &recordingAuthEngine{verdict: Deny}
	resp := &recordingResponder{}
	procRoot := t.TempDir() // empty /proc → all handlers will deny quickly

	dispatched := make(chan uint64, numNotifs)

	s := &SeccompSupervisor{
		Auth:         auth,
		Enforcing:    true,
		procRoot:     procRoot,
		notifRespFn:  resp.respond,
		notifValidFn: func(_ libseccomp.ScmpFd, _ uint64) error { return nil },
	}

	sc, err := libseccomp.GetSyscallFromName("stat")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	call := 0
	s.notifRecvFn = func(_ libseccomp.ScmpFd) (*libseccomp.ScmpNotifReq, error) {
		if call >= numNotifs {
			// Block until ctx is cancelled, then return an error so Run exits.
			<-ctx.Done()
			return nil, fmt.Errorf("listener closed: %w", ctx.Err())
		}
		id := uint64(call + 1)
		call++
		dispatched <- id
		return &libseccomp.ScmpNotifReq{
			ID:  id,
			Pid: pid,
			Data: libseccomp.ScmpNotifData{
				Syscall: sc,
				Args:    []uint64{0x1234},
			},
		}, nil
	}

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Wait for all notifications to be dispatched.
	seen := make(map[uint64]bool)
	for len(seen) < numNotifs {
		id := <-dispatched
		seen[id] = true
	}

	// Cancel ctx — the mock recv unblocks, returns an error, and Run exits cleanly.
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run returned error after ctx cancel: %v", err)
	}

	if len(seen) != numNotifs {
		t.Errorf("dispatched %d notifications, want %d", len(seen), numNotifs)
	}
}

// TestHandleNotif_CancelledNotification verifies that idValid failure causes
// the handler to skip the response without crashing.
func TestHandleNotif_CancelledNotification(t *testing.T) {
	const pid = 206
	const addr = uint64(0x400)

	auth := &recordingAuthEngine{verdict: Allow}
	resp := &recordingResponder{}

	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}
	writeMemString(t, procRoot, pid, addr, "/bin/ls")

	s := &SeccompSupervisor{
		Auth:         auth,
		Enforcing:    true,
		procRoot:     procRoot,
		notifRespFn:  resp.respond,
		// NotifIDValid always returns error = notification cancelled.
		notifValidFn: func(_ libseccomp.ScmpFd, _ uint64) error {
			return fmt.Errorf("notification cancelled")
		},
	}

	req := buildReq(t, "stat", []uint64{addr, 0x500})
	req.Pid = pid
	s.handleNotif(context.Background(), req)

	// No response should be recorded since idValid failed.
	if _, ok := resp.first(); ok {
		t.Error("response recorded despite cancelled notification")
	}
}

// syscallEPERM is the expected error code for a denied syscall.
const syscallEPERM = 1 // syscall.EPERM
