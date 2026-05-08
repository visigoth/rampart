// Package supervisor implements the COMP2 sandbox supervisor lifecycle:
// startup ordering, concurrent subsystem management via errgroup, signal
// handling, graceful shutdown, and exit code propagation.
//
// Design references: .plans/rampart/tdd/supervisor-lifecycle.org TR36-TR58.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

// Subsystem is a long-running supervisor component. Each implementation is
// started as a goroutine inside the errgroup. Run must return when ctx is
// cancelled; it may also return early on fatal errors.
type Subsystem interface {
	// Name returns a human-readable name for diagnostics.
	Name() string
	// Run starts the subsystem. Returns nil on clean shutdown, or an error
	// if the subsystem terminates abnormally.
	Run(ctx context.Context) error
}

// ErrorClass categorizes subsystem errors for the error handler.
type ErrorClass int

const (
	ErrorFatal       ErrorClass = iota // ends the session
	ErrorRecoverable                   // log and degrade
)

// SubsystemSpec bundles a Subsystem with its error classification.
type SubsystemSpec struct {
	S     Subsystem
	Class ErrorClass
}

// Config holds all the inputs the supervisor needs after policy compilation
// (Phase 1). Subsystems and Cmd must be populated before calling Run.
type Config struct {
	// Cmd is the child process to launch and supervise. Required.
	Cmd *exec.Cmd

	// FatalSubsystems are started in Phase 4 (monitoring) before Cmd.
	// Any error from these ends the session (TR53-TR55).
	FatalSubsystems []Subsystem

	// RecoverableSubsystems are started in Phase 4 too. Errors are logged
	// but do not end the session (TR56-TR57).
	RecoverableSubsystems []Subsystem

	// Verbose enables diagnostic output.
	Verbose bool

	// Logger is the sink for diagnostics. Defaults to slog.Default() if nil.
	Logger *slog.Logger

	// GracePeriod is how long to wait for the child after SIGTERM before
	// SIGKILL (TR46). Defaults to 5s.
	GracePeriod time.Duration

	// ErrGroupTimeout bounds how long errgroup.Wait() blocks during shutdown
	// (TR47). Defaults to 5s.
	ErrGroupTimeout time.Duration

	// DoubleIntInterval is how long after the first SIGINT a second SIGINT
	// triggers a hard kill (TR49). Defaults to 2s.
	DoubleIntInterval time.Duration

	// PostStartHook, if non-nil, is invoked after Cmd.Start() succeeds with
	// the freshly-started child's PID. Subsystems it returns are launched as
	// additional fatal subsystems alongside FatalSubsystems. The hook exists
	// because subsystems like the platform violation monitor depend on the
	// child's PID, which is only known after Cmd.Start(). A non-nil error
	// kills the child and ends the session with ExitCode 1.
	PostStartHook func(pid int) ([]Subsystem, error)

	// ChildExitInfo, if non-nil, receives the child's exit info once the
	// supervisor's cmd.Wait() returns. PostStartHook subsystems (e.g. the
	// macOS violation monitor) read from this channel instead of calling
	// Wait4 themselves, which would race with the supervisor's own cmd.Wait
	// and cause double-reap (one side gets ECHILD).
	//
	// The channel must be buffered (>=1) — the supervisor sends with a
	// non-blocking select so a missing reader does not block the wait
	// goroutine. The sole consumer is typically the Monitor subsystem.
	ChildExitInfo chan<- ChildExit
}

// ChildExit captures the result of cmd.Wait() for distribution to
// post-start subsystems that need to observe the child's termination.
type ChildExit struct {
	// ExitStatus is the child's exit code (0 on clean exit). Zero when the
	// child was terminated by a signal.
	ExitStatus int
	// Signal is the terminating signal number (non-zero only when the child
	// was killed by a signal — e.g. SIGKILL on macOS Seatbelt violation).
	Signal int
	// Err is non-nil only when cmd.Wait() returned an error that was
	// neither a normal *exec.ExitError nor an exec.ExitError carrying a
	// WaitStatus. Subsystems should treat this as a wait failure.
	Err error
}

func (c *Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *Config) gracePeriod() time.Duration {
	if c.GracePeriod > 0 {
		return c.GracePeriod
	}
	return 5 * time.Second
}

func (c *Config) errGroupTimeout() time.Duration {
	if c.ErrGroupTimeout > 0 {
		return c.ErrGroupTimeout
	}
	return 5 * time.Second
}

func (c *Config) doubleIntInterval() time.Duration {
	if c.DoubleIntInterval > 0 {
		return c.DoubleIntInterval
	}
	return 2 * time.Second
}

// Result carries the supervisor's outcome after Run returns.
type Result struct {
	// ExitCode is the child's exit code, or a non-zero value if rampart
	// itself failed (TR52).
	ExitCode int
	// Err is the cause of a non-zero exit, if any.
	Err error
}

// Run executes the full supervisor lifecycle according to TR38 (startup) and
// TR45 (shutdown). It blocks until the session ends and returns a Result
// describing the outcome.
//
// Startup phases (TR38):
//
//	Phase 1: config compilation (assumed done — Cmd and subsystems pre-built)
//	Phase 2: support infrastructure (session socket open, proxy listener)
//	Phase 3: UI setup (tmux pane creation)
//	Phase 4: monitoring (session socket listener, auth engine, platform monitor)
//	Phase 5: child launch
//	Phase 6: wait (errgroup.Wait)
//
// For this implementation the phases are represented by the subsystem slices
// in Config; actual infra setup (proxy port, socket path, etc.) is done by
// the subsystems themselves.
func Run(ctx context.Context, cfg Config) Result {
	log := cfg.logger()

	if cfg.Verbose {
		log.Info("supervisor starting")
	}

	// --- Phase 5: Start child process ---
	if err := cfg.Cmd.Start(); err != nil {
		return Result{ExitCode: 1, Err: fmt.Errorf("starting child process: %w", err)}
	}

	childPID := cfg.Cmd.Process.Pid
	if cfg.Verbose {
		log.Info("child started", "pid", childPID)
	}

	// Post-start hook (e.g. platform monitor that needs the child's PID).
	// Errors here are fatal: kill the child and bail before wiring goroutines.
	postStartSubs, postStartErr := callPostStart(cfg, childPID)
	if postStartErr != nil {
		_ = cfg.Cmd.Process.Kill()
		_, _ = cfg.Cmd.Process.Wait()
		return Result{ExitCode: 1, Err: fmt.Errorf("post-start hook: %w", postStartErr)}
	}

	// cmd.Wait() is blocking and not context-aware; run it in a goroutine
	// and communicate the result via a buffered channel. We also broadcast
	// the parsed exit info to any optional ChildExitInfo subscriber so
	// post-start subsystems can observe termination without calling Wait4
	// themselves (which would race with this cmd.Wait and double-reap).
	childResult := make(chan error, 1)
	go func() {
		err := cfg.Cmd.Wait()
		if cfg.ChildExitInfo != nil {
			info := childExitFromWait(err, cfg.Cmd)
			select {
			case cfg.ChildExitInfo <- info:
			default:
			}
		}
		childResult <- err
	}()

	// --- Set up signal handling (TR48-TR51) ---
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	// SIGPIPE: ignored (TR51) — Go default handles writes to closed pipes.
	signal.Ignore(syscall.SIGPIPE)
	defer signal.Stop(sigCh)

	// Context for subsystems and signal handler. We use a manual cancel
	// (not errgroup.WithContext) so the child goroutine can cancel all others
	// when the child exits cleanly (non-error exit doesn't cancel errgroup ctx).
	egCtx, cancelEg := context.WithCancel(ctx)
	defer cancelEg()

	eg := new(errgroup.Group)

	var childExitCode int32
	// killMode 1 = hard kill immediately (double-SIGINT), 0 = graceful.
	// Must be stored before cancelEg() to be visible to the monitor goroutine.
	var killMode atomic.Int32

	captureExit := func(err error) {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			atomic.StoreInt32(&childExitCode, int32(exitErr.ExitCode()))
		}
	}

	// Monitor goroutine: owns the child process lifecycle and shutdown (TR46).
	eg.Go(func() error {
		select {
		case waitErr := <-childResult:
			// Child exited naturally (before any shutdown signal).
			captureExit(waitErr)
			cancelEg() // stop all subsystems and signal handler
			if waitErr != nil && !isExitError(waitErr) {
				return fmt.Errorf("child wait: %w", waitErr)
			}
			return nil

		case <-egCtx.Done():
			// Shutdown triggered by signal, fatal subsystem, or parent ctx.
			if killMode.Load() == 1 {
				// Hard kill: second SIGINT within interval (TR49).
				_ = cfg.Cmd.Process.Kill()
			} else {
				// Graceful: SIGTERM → grace period → SIGKILL (TR46).
				_ = cfg.Cmd.Process.Signal(syscall.SIGTERM)
				timer := time.NewTimer(cfg.gracePeriod())
				defer timer.Stop()
				select {
				case waitErr := <-childResult:
					captureExit(waitErr)
					return nil
				case <-timer.C:
					log.Warn("child did not exit after grace period — killing", "grace", cfg.gracePeriod())
					_ = cfg.Cmd.Process.Kill()
				}
			}
			captureExit(<-childResult)
			return nil
		}
	})

	// Fatal subsystems (TR53-TR55): errors end the session. Includes any
	// post-start subsystems registered with the child's PID.
	allFatal := append([]Subsystem(nil), cfg.FatalSubsystems...)
	allFatal = append(allFatal, postStartSubs...)
	for _, sub := range allFatal {
		s := sub // capture
		eg.Go(func() error {
			if err := s.Run(egCtx); err != nil && !isContextDone(err) {
				cancelEg()
				return fmt.Errorf("subsystem %s: %w", s.Name(), err)
			}
			return nil
		})
	}

	// Recoverable subsystems (TR56-TR57): errors are logged, don't end session.
	for _, sub := range cfg.RecoverableSubsystems {
		s := sub
		eg.Go(func() error {
			if err := s.Run(egCtx); err != nil && !isContextDone(err) {
				log.Warn("recoverable subsystem failed (continuing)", "name", s.Name(), "err", err)
			}
			return nil // never propagate
		})
	}

	// Signal handler goroutine (TR48-TR51).
	var firstSIGINT atomic.Int64 // UnixNano of first SIGINT, 0 if not seen
	eg.Go(func() error {
		for {
			select {
			case <-egCtx.Done():
				return nil
			case sig := <-sigCh:
				switch sig {
				case syscall.SIGINT:
					now := time.Now().UnixNano()
					prev := firstSIGINT.Swap(now)
					if prev != 0 && time.Duration(now-prev) < cfg.doubleIntInterval() {
						// Second SIGINT within interval: hard kill (TR49).
						log.Warn("second SIGINT — hard kill")
						killMode.Store(1) // must precede cancelEg
						cancelEg()
						return fmt.Errorf("killed by second SIGINT")
					}
					log.Info("SIGINT received — graceful shutdown")
					cancelEg()
					return errGraceful
				case syscall.SIGTERM, syscall.SIGHUP:
					// SIGHUP treated as SIGTERM (TR50).
					log.Info("signal received — graceful shutdown", "signal", sig)
					cancelEg()
					return errGraceful
				}
			}
		}
	})

	waitErr := eg.Wait()
	exitCode := int(atomic.LoadInt32(&childExitCode))

	// Double SIGINT: exit 130 (TR49).
	if waitErr != nil && waitErr.Error() == "killed by second SIGINT" {
		return Result{ExitCode: 130, Err: waitErr}
	}

	// Graceful shutdown triggered by signal — exit with child's code.
	if errors.Is(waitErr, errGraceful) {
		if cfg.Verbose {
			log.Info("graceful shutdown complete", "exit_code", exitCode)
		}
		return Result{ExitCode: exitCode}
	}

	// Rampart error (fatal subsystem failed or other non-normal termination).
	if waitErr != nil {
		return Result{ExitCode: 1, Err: waitErr}
	}

	return Result{ExitCode: exitCode}
}

// childExitFromWait converts an *exec.Cmd.Wait() error into a ChildExit
// for broadcast to ChildExitInfo subscribers.
func childExitFromWait(err error, cmd *exec.Cmd) ChildExit {
	if err == nil {
		if cmd.ProcessState != nil {
			return ChildExit{ExitStatus: cmd.ProcessState.ExitCode()}
		}
		return ChildExit{}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if ok && ws.Signaled() {
			return ChildExit{Signal: int(ws.Signal())}
		}
		return ChildExit{ExitStatus: ee.ExitCode()}
	}
	return ChildExit{Err: err}
}

// callPostStart runs cfg.PostStartHook if set, returning its subsystems and error.
func callPostStart(cfg Config, pid int) ([]Subsystem, error) {
	if cfg.PostStartHook == nil {
		return nil, nil
	}
	return cfg.PostStartHook(pid)
}

// errGraceful is a sentinel returned by the signal goroutine to signal a
// clean shutdown (SIGINT/SIGTERM/SIGHUP). It is not an error in the
// operational sense.
var errGraceful = errors.New("graceful shutdown")

// isExitError returns true if err is an *exec.ExitError (child exited
// non-zero). This is normal operation, not an error of the supervisor.
func isExitError(err error) bool {
	var e *exec.ExitError
	return errors.As(err, &e)
}

// isContextDone returns true if err indicates the context was cancelled.
func isContextDone(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// StartupPhase tracks which phases have been completed so cleanup can be
// ordered correctly on failure (TR39).
type StartupPhase int

const (
	PhaseNone    StartupPhase = iota
	PhaseConfig               // configs loaded and policy compiled
	PhaseInfra                // support infrastructure started
	PhaseUI                   // UI (tmux pane) ready
	PhaseMonitor              // monitoring goroutines running
	PhaseChild                // child process started
)

// LogWriter wraps an io.Writer as a slog handler target for test injection.
func LogWriter(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
