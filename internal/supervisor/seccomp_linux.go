//go:build linux

// Package supervisor: seccomp user-notification supervisor loop (COMP2, FT6).
//
// SeccompSupervisor holds the listener fd received from the launcher via
// SCM_RIGHTS. It loops calling NotifReceive, dispatches each notification to
// its own handler goroutine (TR171), and applies allow/deny decisions from
// the AuthEngine.
//
// Design references: .plans/rampart/tdd/seccomp-filter.org TR152-TR177.
package supervisor

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// Capability represents the access level required by a filtered syscall
// (TR152.1). The hierarchy is: exec → read → stat; write → read → stat.
type Capability int

const (
	CapStat  Capability = iota // path metadata only
	CapRead                    // open for reading
	CapWrite                   // create, modify, delete
	CapExec                    // execute binary
)

func (c Capability) String() string {
	switch c {
	case CapStat:
		return "stat"
	case CapRead:
		return "read"
	case CapWrite:
		return "write"
	case CapExec:
		return "exec"
	default:
		return fmt.Sprintf("capability(%d)", int(c))
	}
}

// ViolationEvent describes a filtered syscall that the AuthEngine must decide.
type ViolationEvent struct {
	PID      uint32
	Syscall  string
	Path     string     // resolved absolute path
	Required Capability // minimum capability needed
	NotifID  uint64     // for the supervisor to correlate responses
}

// Decision indicates whether the AuthEngine permits or denies the syscall.
type Decision bool

const (
	Allow Decision = true
	Deny  Decision = false
)

// AuthEngine is consulted for every intercepted syscall (TR82, FT12 soft-dep).
type AuthEngine interface {
	Authorize(ctx context.Context, ev ViolationEvent) Decision
}

// DenyAllEngine denies every syscall. Useful as a safe default.
type DenyAllEngine struct{}

func (DenyAllEngine) Authorize(_ context.Context, _ ViolationEvent) Decision { return Deny }

// AllowAllEngine allows every syscall. Useful for permissive mode / tests.
type AllowAllEngine struct{}

func (AllowAllEngine) Authorize(_ context.Context, _ ViolationEvent) Decision { return Allow }

// syscallProfile describes how to extract (dirfd, path-ptr, open-flags) from
// the notification args and what capability the syscall requires.
type syscallProfile struct {
	dirfdIdx  int  // arg index for dirfd; -1 = no dirfd (use AT_FDCWD)
	pathIdx   int  // arg index for the path pointer
	howPtrIdx int  // arg index for *open_how ptr (openat2 only); -1 = unused
	flagsIdx  int  // arg index for flags (open-family); -1 = unused
	modeIdx   int  // arg index for mode; -1 = unused
	baseCap   Capability
	fdReturn  bool // true = open-family → use SECCOMP_IOCTL_NOTIF_ADDFD
}

// syscallProfiles maps syscall name → profile. All path-taking syscalls in
// the filter must have an entry (TR153-TR156).
var syscallProfiles = map[string]syscallProfile{
	// Stat (TR153)
	"fstatat":    {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	"newfstatat": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	"statx":      {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	"stat":       {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	"lstat":      {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	// Access (TR153)
	"faccessat":  {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	"faccessat2": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	"access":     {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	// Symlink read (TR153)
	"readlinkat": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	"readlink":   {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapStat},
	// Open-family: cap depends on flags (TR152.2); fd-returning (TR165)
	"openat":  {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: 2, modeIdx: 3, baseCap: CapRead, fdReturn: true},
	"openat2": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: 2, flagsIdx: -1, modeIdx: -1, baseCap: CapRead, fdReturn: true},
	"open":    {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: 1, modeIdx: 2, baseCap: CapRead, fdReturn: true},
	"creat":   {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: 1, baseCap: CapWrite, fdReturn: true},
	// Unlink (TR154)
	"unlinkat": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"unlink":   {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"rmdir":    {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	// Rename (TR154) — use old-path as primary event path
	"renameat2": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"renameat":  {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"rename":    {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	// Link / symlink create (TR154)
	// linkat(olddirfd, oldpath, newdirfd, newpath, flags) — report newpath
	"linkat":    {dirfdIdx: 2, pathIdx: 3, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"link":      {dirfdIdx: -1, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	// symlinkat(target, newdirfd, linkpath) — report linkpath
	"symlinkat": {dirfdIdx: 1, pathIdx: 2, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"symlink":   {dirfdIdx: -1, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	// Mkdir / mknod (TR154)
	"mkdirat": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"mkdir":   {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"mknodat": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"mknod":   {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	// Chmod / chown (TR155)
	"fchmodat":  {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"fchmodat2": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"fchownat":  {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"chmod":     {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"chown":     {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"lchown":    {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	// Truncate (TR155)
	"truncate":   {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	"truncate64": {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapWrite},
	// Exec (TR156)
	"execve":   {dirfdIdx: -1, pathIdx: 0, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapExec},
	"execveat": {dirfdIdx: 0, pathIdx: 1, howPtrIdx: -1, flagsIdx: -1, modeIdx: -1, baseCap: CapExec},
}

// openFlagsWriteMask covers flags that indicate a write operation (TR152.2).
const openFlagsWriteMask = unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC | unix.O_APPEND

// classifyOpenCap returns the capability implied by open-family flags (TR152.2).
func classifyOpenCap(flags uint64) Capability {
	if flags&unix.O_PATH != 0 {
		return CapStat
	}
	if flags&openFlagsWriteMask != 0 {
		return CapWrite
	}
	return CapRead
}

// seccompNotifAddFd mirrors Linux's struct seccomp_notif_addfd (linux/seccomp.h).
// Used with SECCOMP_IOCTL_NOTIF_ADDFD ioctl (TR165).
type seccompNotifAddFd struct {
	id         uint64 // notification ID
	flags      uint32 // SECCOMP_ADDFD_FLAG_SEND = 0x2
	srcfd      uint32 // supervisor fd to duplicate into tracee
	newfd      uint32 // desired fd number in tracee (0 = allocate)
	newfdFlags uint32 // fd flags for new fd (e.g. O_CLOEXEC)
}

// SeccompSupervisor receives seccomp user notifications and mediates
// filesystem/exec access for the sandboxed agent.
type SeccompSupervisor struct {
	// ListenerFd is the seccomp user-notification fd from the launcher.
	ListenerFd libseccomp.ScmpFd
	// Auth is the authorization engine. Must not be nil.
	Auth AuthEngine
	// Enforcing controls deny behaviour: true=EPERM, false=allow+log (TR172).
	Enforcing bool
	// Logger is the diagnostic sink.
	Logger *slog.Logger

	// procRoot is "/proc" in production; overridden in tests.
	procRoot string
	// notifRecvFn/notifRespFn/notifValidFn are overridden in tests.
	notifRecvFn  func(libseccomp.ScmpFd) (*libseccomp.ScmpNotifReq, error)
	notifRespFn  func(libseccomp.ScmpFd, *libseccomp.ScmpNotifResp) error
	notifValidFn func(libseccomp.ScmpFd, uint64) error
}

func (s *SeccompSupervisor) procDir() string {
	if s.procRoot != "" {
		return s.procRoot
	}
	return "/proc"
}

func (s *SeccompSupervisor) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *SeccompSupervisor) recv() (*libseccomp.ScmpNotifReq, error) {
	if s.notifRecvFn != nil {
		return s.notifRecvFn(s.ListenerFd)
	}
	return libseccomp.NotifReceive(s.ListenerFd)
}

func (s *SeccompSupervisor) respond(resp *libseccomp.ScmpNotifResp) error {
	if s.notifRespFn != nil {
		return s.notifRespFn(s.ListenerFd, resp)
	}
	return libseccomp.NotifRespond(s.ListenerFd, resp)
}

func (s *SeccompSupervisor) idValid(id uint64) error {
	if s.notifValidFn != nil {
		return s.notifValidFn(s.ListenerFd, id)
	}
	return libseccomp.NotifIDValid(s.ListenerFd, id)
}

// Run is the notification dispatch loop (TR171). It blocks until ctx is
// cancelled or the listener fd is closed.
func (s *SeccompSupervisor) Run(ctx context.Context) error {
	for {
		req, err := s.recv()
		if err != nil {
			// If ctx is done the caller closed the fd intentionally.
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return fmt.Errorf("seccomp notif receive: %w", err)
		}
		go s.handleNotif(ctx, req)
	}
}

// handleNotif processes a single seccomp notification in its own goroutine.
func (s *SeccompSupervisor) handleNotif(ctx context.Context, req *libseccomp.ScmpNotifReq) {
	syscallName, err := req.Data.Syscall.GetName()
	if err != nil {
		s.log().Warn("unknown syscall number", "nr", int32(req.Data.Syscall), "pid", req.Pid)
		s.denyNotif(req.ID)
		return
	}

	prof, ok := syscallProfiles[syscallName]
	if !ok {
		s.log().Warn("unprofiledqsyscall", "syscall", syscallName, "pid", req.Pid)
		s.denyNotif(req.ID)
		return
	}

	args := req.Data.Args

	// Read the open flags to determine capability (TR152.2).
	cap, openFlags, err := s.classifyCapability(req.Pid, prof, args)
	if err != nil {
		s.log().Warn("capability classification failed", "syscall", syscallName, "pid", req.Pid, "err", err)
		s.denyNotif(req.ID)
		return
	}

	// Resolve the path from /proc/<pid>/mem (TR163).
	path, err := s.readPath(req.Pid, prof, args)
	if err != nil {
		// TR175: /proc read failure → log + deny, never crash.
		s.log().Warn("path read failed", "syscall", syscallName, "pid", req.Pid, "err", err)
		s.denyNotif(req.ID)
		return
	}

	// Validate notification before consulting auth (TR164).
	if err := s.idValid(req.ID); err != nil {
		return // notification cancelled (process died or timed out)
	}

	ev := ViolationEvent{
		PID:      req.Pid,
		Syscall:  syscallName,
		Path:     path,
		Required: cap,
		NotifID:  req.ID,
	}

	dec := s.Auth.Authorize(ctx, ev)

	// Validate again before responding (TOCTOU, TR164).
	if err := s.idValid(req.ID); err != nil {
		return
	}

	if dec == Allow {
		if prof.fdReturn {
			// Use addfd with SEND flag for TOCTOU-safe fd injection (TR165).
			flags := int(openFlags) &^ unix.O_NOFOLLOW // supervisor opens resolved path
			var mode uint32
			if prof.modeIdx >= 0 && int(prof.modeIdx) < len(args) {
				mode = uint32(args[prof.modeIdx])
			}
			if err := s.notifAddFd(req.ID, path, flags, mode); err != nil {
				// TR176: addfd failure → fall back to direct response.
				s.log().Warn("SECCOMP_IOCTL_NOTIF_ADDFD failed, falling back", "err", err)
				s.allowNotif(req.ID)
			}
		} else {
			s.allowNotif(req.ID)
		}
	} else {
		if !s.Enforcing {
			// Permissive mode: allow but log (TR172).
			s.log().Info("permissive: allowing denied syscall", "path", path, "cap", cap, "syscall", syscallName)
			s.allowNotif(req.ID)
		} else {
			s.denyNotif(req.ID)
		}
	}
}

// classifyCapability returns the required capability and the effective open
// flags for this notification. For the open-family, flags are read from
// the notification args or from *open_how in process memory.
func (s *SeccompSupervisor) classifyCapability(pid uint32, prof syscallProfile, args []uint64) (Capability, uint64, error) {
	if prof.flagsIdx >= 0 && prof.flagsIdx < len(args) {
		flags := args[prof.flagsIdx]
		return classifyOpenCap(flags), flags, nil
	}
	if prof.howPtrIdx >= 0 && prof.howPtrIdx < len(args) {
		// openat2: flags are the first 8 bytes of struct open_how.
		howPtr := args[prof.howPtrIdx]
		flagBytes, err := s.readNBytes(pid, howPtr, 8)
		if err != nil {
			return prof.baseCap, 0, fmt.Errorf("reading open_how flags: %w", err)
		}
		flags := binary.NativeEndian.Uint64(flagBytes)
		return classifyOpenCap(flags), flags, nil
	}
	return prof.baseCap, 0, nil
}

// readPath reads the pathname from /proc/<pid>/mem and resolves it against
// the dirfd (AT_FDCWD → /proc/<pid>/cwd, or /proc/<pid>/fd/<n>) (TR163, TR167).
func (s *SeccompSupervisor) readPath(pid uint32, prof syscallProfile, args []uint64) (string, error) {
	if prof.pathIdx >= len(args) {
		return "", fmt.Errorf("pathIdx %d out of range (args len %d)", prof.pathIdx, len(args))
	}
	pathPtr := args[prof.pathIdx]

	rawPath, err := s.readString(pid, pathPtr)
	if err != nil {
		return "", fmt.Errorf("reading path string: %w", err)
	}

	if filepath.IsAbs(rawPath) {
		return filepath.Clean(rawPath), nil
	}

	// Relative path: resolve against dirfd.
	baseDir, err := s.resolveDirfd(pid, prof, args)
	if err != nil {
		return "", fmt.Errorf("resolving dirfd: %w", err)
	}
	return filepath.Clean(filepath.Join(baseDir, rawPath)), nil
}

// resolveDirfd returns the absolute directory the dirfd refers to (TR167).
func (s *SeccompSupervisor) resolveDirfd(pid uint32, prof syscallProfile, args []uint64) (string, error) {
	procDir := s.procDir()

	// No dirfd field or AT_FDCWD → use CWD.
	if prof.dirfdIdx < 0 || (prof.dirfdIdx < len(args) && int32(args[prof.dirfdIdx]) == int32(unix.AT_FDCWD)) {
		return os.Readlink(fmt.Sprintf("%s/%d/cwd", procDir, pid))
	}

	if prof.dirfdIdx >= len(args) {
		return "", fmt.Errorf("dirfdIdx %d out of range (args len %d)", prof.dirfdIdx, len(args))
	}

	fd := args[prof.dirfdIdx]
	return os.Readlink(fmt.Sprintf("%s/%d/fd/%d", procDir, pid, fd))
}

// readString reads a null-terminated string from /proc/<pid>/mem at addr.
func (s *SeccompSupervisor) readString(pid uint32, addr uint64) (string, error) {
	const maxPath = 4096
	data, err := s.readNBytes(pid, addr, maxPath)
	if err != nil {
		return "", err
	}
	for i, b := range data {
		if b == 0 {
			return string(data[:i]), nil
		}
	}
	return "", fmt.Errorf("path string not null-terminated within %d bytes at 0x%x", maxPath, addr)
}

// readNBytes reads n bytes from /proc/<pid>/mem starting at addr.
func (s *SeccompSupervisor) readNBytes(pid uint32, addr uint64, n int) ([]byte, error) {
	path := fmt.Sprintf("%s/%d/mem", s.procDir(), pid)
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	buf := make([]byte, n)
	got, err := f.ReadAt(buf, int64(addr))
	if err != nil && got == 0 {
		return nil, fmt.Errorf("ReadAt %s+0x%x: %w", path, addr, err)
	}
	return buf[:got], nil
}

// allowNotif responds to the notification with SECCOMP_USER_NOTIF_FLAG_CONTINUE
// so the kernel continues the syscall as-is (TR166).
func (s *SeccompSupervisor) allowNotif(id uint64) {
	resp := &libseccomp.ScmpNotifResp{
		ID:    id,
		Flags: libseccomp.NotifRespFlagContinue,
	}
	if err := s.respond(resp); err != nil {
		s.log().Warn("NotifRespond allow failed", "id", id, "err", err)
	}
}

// denyNotif responds to the notification with EPERM (TR166).
func (s *SeccompSupervisor) denyNotif(id uint64) {
	resp := &libseccomp.ScmpNotifResp{
		ID:    id,
		Error: int32(syscall.EPERM),
	}
	if err := s.respond(resp); err != nil {
		s.log().Warn("NotifRespond deny failed", "id", id, "err", err)
	}
}

// notifAddFd opens path in the supervisor's address space and installs the
// resulting fd into the tracee via SECCOMP_IOCTL_NOTIF_ADDFD + SEND (TR165).
// The ioctl acts as both the addfd operation and the notification response.
func (s *SeccompSupervisor) notifAddFd(notifID uint64, path string, flags int, mode uint32) error {
	fd, err := syscall.Open(path, flags, mode)
	if err != nil {
		return fmt.Errorf("supervisor open %q: %w", path, err)
	}
	defer syscall.Close(fd)

	addfd := seccompNotifAddFd{
		id:    notifID,
		flags: unix.SECCOMP_ADDFD_FLAG_SEND,
		srcfd: uint32(fd),
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(s.ListenerFd),
		unix.SECCOMP_IOCTL_NOTIF_ADDFD,
		uintptr(unsafe.Pointer(&addfd)))
	if errno != 0 {
		return fmt.Errorf("SECCOMP_IOCTL_NOTIF_ADDFD: %w", errno)
	}
	return nil
}
