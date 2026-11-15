//go:build linux

package nativefixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	c "pluto/internal/testsupport/nativeprocess/custody"
)

type capture struct {
	mu             sync.Mutex
	file           *os.File
	prefix         bytes.Buffer
	hash           hash.Hash
	count, maximum int64
	failure        error
}

func newCapture(dir, name string, maximum int64) (*capture, error) {
	fd, e := unix.Open(filepath.Join(dir, name), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	return &capture{file: os.NewFile(uintptr(fd), name), hash: sha256.New(), maximum: maximum}, nil
}
func (w *capture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count += int64(len(p))
	_, _ = w.hash.Write(p)
	n := len(p)
	remaining := w.maximum - int64(w.prefix.Len())
	if remaining < 0 {
		remaining = 0
	}
	if int64(n) > remaining {
		n = int(remaining)
	}
	if n > 0 {
		_, _ = w.prefix.Write(p[:n])
		if w.failure == nil {
			written, e := w.file.Write(p[:n])
			if e == nil && written != n {
				e = io.ErrShortWrite
			}
			w.failure = e
		}
	}
	// Continue real drains even after a prefix/disk failure. Never close pipes to fake join.
	return len(p), nil
}
func (w *capture) finish() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := errors.Join(w.failure, w.file.Sync(), w.file.Close())
	w.failure = e
	return e
}
func (w *capture) view() ([]byte, int64, string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.prefix.Bytes()...), w.count, hex.EncodeToString(w.hash.Sum(nil)), w.count > w.maximum
}

type actor struct {
	mu                                  sync.Mutex
	owner                               *Owner
	id, fixture, role, action, evidence string
	artifact                            Artifact
	view                                fileView
	cmd                                 *exec.Cmd
	fd                                  int
	done                                chan struct{}
	deadline                            time.Time
	result                              Result
	strong                              *observed
	out, errout                         *capture
	combined                            bool
	stopRequested                       bool
	crashRequested                      bool
	waitOnce                            sync.Once
	waitAt                              time.Time
	joinWatchOnce                       sync.Once
}

func (o *Owner) startActor(f *fixture, role, action string, a Artifact, args, env []string, due time.Time, combined bool) (*actor, error) {
	return o.startActorCore(f, role, action, a, args, env, due, combined, false)
}
func (o *Owner) startCollector(f *fixture, a Artifact, args []string, due time.Time) (*actor, error) {
	return o.startActorCore(f, "collector", "copy", a, args, o.manifest.Environment, due, true, true)
}
func (o *Owner) startActorCore(f *fixture, role, action string, a Artifact, args, env []string, due time.Time, combined, collector bool) (*actor, error) {
	// Reserve/register BEFORE Start. The loaded owner is the sole forker, so no
	// native process can exist in a post-Start handoff gap in a Go-test client.
	o.mu.Lock()
	if !collector && (o.closed || (f != nil && f.closed)) {
		o.mu.Unlock()
		return nil, errors.New("product admission closed")
	}
	if f != nil {
		active := 0
		for _, a := range o.actors {
			if a.fixture == f.id {
				select {
				case <-a.done:
				default:
					active++
				}
			}
		}
		if active >= 2 {
			o.mu.Unlock()
			return nil, errors.New("at most daemon plus one transient per fixture")
		}
	}
	if collector && (f == nil || !f.closed || o.manifest.Cases[f.name].CopyMs <= 0 || time.Now().UnixMilli() >= o.manifest.ExpiresUnixMs) {
		o.mu.Unlock()
		return nil, errors.New("independent collector admission refused")
	}
	o.nextActor++
	id := fmt.Sprintf("a-%06d", o.nextActor)
	x := &actor{owner: o, id: id, role: role, action: action, artifact: a, fd: -1, done: make(chan struct{}), deadline: due, combined: combined}
	if f != nil {
		x.fixture = f.id
	}
	x.evidence = filepath.Join(o.manifest.EvidenceRoot, id)
	o.actors[id] = x
	o.mu.Unlock()
	failedStart := func(e error) (*actor, error) {
		x.mu.Lock()
		x.result = Result{ID: id, Fixture: x.fixture, Evidence: x.evidence, LifecycleError: "START_REFUSED: " + e.Error()}
		close(x.done)
		x.mu.Unlock()
		o.fail(e)
		return x, e
	}
	if e := privateDirectory(x.evidence, true); e != nil {
		return failedStart(e)
	}
	if e := selfProfile(); e != nil {
		return failedStart(e)
	}
	ns, e := namespaces(os.Getpid())
	if e != nil || ns != o.namespaces {
		return failedStart(errors.New("owner namespace changed"))
	}
	first, e := fingerprint(a, a.Path, false)
	if e != nil {
		return failedStart(e)
	}
	second, e := fingerprint(a, a.Path, false)
	if e != nil || first != second {
		return failedStart(errors.New("candidate changed before Start"))
	}
	x.view = first
	if !due.IsZero() && !time.Now().Before(due) {
		return failedStart(errors.New("existing deadline already expired before Start"))
	}
	cmd := exec.Command(a.Path, args...)
	cmd.Env = append([]string(nil), env...)
	cmd.Dir = o.manifest.RetainedRoot
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &x.fd, Setpgid: true, Pgid: 0}
	// No CommandContext, Cancel, WaitDelay, SetCredential, Ptrace, group signal or shell.
	x.cmd = cmd
	x.out, e = newCapture(x.evidence, "stdout-prefix.log", o.manifest.OutputPrefixBytes)
	if e != nil {
		return failedStart(e)
	}
	if combined {
		cmd.Stdout = x.out
		cmd.Stderr = x.out
	} else {
		x.errout, e = newCapture(x.evidence, "stderr-prefix.log", o.manifest.OutputPrefixBytes)
		if e != nil {
			_ = x.out.finish()
			return failedStart(e)
		}
		cmd.Stdout = x.out
		cmd.Stderr = x.errout
	}
	if e = durableNew(x.evidence, "prepared-before-Start.json", map[string]any{"role": role, "action": action, "artifact": a, "inode": first, "args": append([]string{a.Path}, args...), "parent": o.birth, "profile": "10001/groups[]/all5cap0/NNP1/seccomp2 inherited; launch intent not observed child tuple", "namespace": ns, "deadline": due}); e != nil {
		_ = x.out.finish()
		if x.errout != nil {
			_ = x.errout.finish()
		}
		return failedStart(e)
	}
	// Guard the final admission interval and Start under the same owner lock as Close.
	o.mu.Lock()
	if !collector && (o.closed || (f != nil && f.closed)) {
		o.mu.Unlock()
		_ = x.out.finish()
		if x.errout != nil {
			_ = x.errout.finish()
		}
		return failedStart(errors.New("admission closed before Start"))
	}
	if time.Now().UnixMilli() >= o.manifest.ExpiresUnixMs {
		o.mu.Unlock()
		_ = x.out.finish()
		if x.errout != nil {
			_ = x.errout.finish()
		}
		return failedStart(errors.New("Root admission expired immediately before Start"))
	}
	x.result = Result{ID: id, Fixture: x.fixture, Evidence: x.evidence}
	e = guardedStart(func() error {
		startErr := cmd.Start()
		if startErr == nil {
			x.mu.Lock()
			x.result.IntentProven = true
			x.result.Actual.PID = cmd.Process.Pid
			x.mu.Unlock()
		}
		return startErr
	}, func() bool { return cmd.Process != nil }, func() { x.waitOnce.Do(func() { go x.wait() }) })
	o.mu.Unlock()
	if e != nil {
		if cmd.Process != nil {
			x.mu.Lock()
			x.result.LifecycleError = "START_FAILURE_WITH_OWNED_CHILD: " + e.Error()
			x.mu.Unlock()
			o.fail(e)
			return x, e
		}
		_ = x.out.finish()
		if x.errout != nil {
			_ = x.errout.finish()
		}
		return failedStart(e)
	}
	// Start owns its original process handle and SAME Start fd now. Ownership
	// already existed before this first post-Start instruction and any metadata.
	x.mu.Lock()
	fdAvailable := x.fd >= 0
	alreadyWaited := x.result.Actual.Observed
	x.mu.Unlock()
	if !fdAvailable && !alreadyWaited {
		o.fail(errors.New("atomic pidfd unavailable; no fallback"))
		x.mu.Lock()
		x.result.LifecycleError = "ATOMIC_PIDFD_UNAVAILABLE"
		x.mu.Unlock()
		return x, errors.New("atomic pidfd required")
	}
	x.mu.Lock()
	actual, e := observe(cmd.Process.Pid, x.fd, a, cmd.Args, o.birth, o.namespaces, first)
	if e == nil {
		x.strong = &actual
		x.result.StrongTupleObserved = true
	}
	x.mu.Unlock()
	if e == nil {
		if e = durableNew(x.evidence, "observed-after-exec.json", actual); e != nil {
			o.fail(e)
			x.mu.Lock()
			x.result.LifecycleError = e.Error()
			x.mu.Unlock()
		}
	} else if role == "daemon" || role == "adoption-fault" || role == "go-test" {
		// Long-lived/held roles require actual proof before readiness/signal.
		o.fail(e)
		x.mu.Lock()
		x.result.LifecycleError = "REQUIRED_LIVE_TUPLE: " + e.Error()
		x.mu.Unlock()
	}
	if !due.IsZero() {
		o.observers.Add(1)
		go func() {
			defer o.observers.Done()
			timer := time.NewTimer(time.Until(due))
			defer timer.Stop()
			select {
			case <-x.done:
				return
			case <-timer.C:
				x.expire("existing action deadline")
			}
		}()
	}
	return x, eForRequiredRole(role, e)
}
func eForRequiredRole(role string, e error) error {
	if role == "daemon" || role == "adoption-fault" || role == "go-test" {
		return e
	}
	return nil
}

func (x *actor) expire(reason string) {
	x.expireKind(reason, false)
}
func (x *actor) expireKind(reason string, forceBarrier bool) {
	x.mu.Lock()
	if !forceBarrier && !x.waitAt.IsZero() {
		x.mu.Unlock()
		return
	}
	x.result.DeadlineExpired = true
	x.mu.Unlock()
	x.owner.closeAdmission(x.fixture)
	_, e := fmt.Fprintf(os.Stderr, "NATIVE_DEADLINE_FAIL_PENDING id=%s reason=%q noKill=true\n", x.id, reason)
	if e != nil {
		x.owner.fail(e)
	}
	// Deadline never authorizes a new signal. The sole loaded owner keeps real join.
}
func (x *actor) wait() {
	err := x.cmd.Wait() // original handle; also joins the real Go IO drains
	waitAt := time.Now()
	x.mu.Lock()
	x.waitAt = waitAt
	x.mu.Unlock()
	state := x.cmd.ProcessState
	a := Actual{PID: x.cmd.Process.Pid, Observed: state != nil}
	if state != nil {
		a.Exited = state.Exited()
		a.ExitCode = state.ExitCode()
		if w, ok := state.Sys().(syscall.WaitStatus); ok {
			a.RawStatus = uint32(w)
			a.Signaled = w.Signaled()
			if a.Signaled {
				a.Signal = int(w.Signal())
			}
		}
	}
	// The actual numeric/raw outcome is FIRST. Never infer shell137 or code0.
	_, rawErr := fmt.Fprintf(os.Stderr, "NATIVE_ACTUAL_WAIT id=%s actual=%+v\n", x.id, a)
	numericErr := durableNew(x.evidence, "actual-wait.json", a)
	outErr := x.out.finish()
	if x.errout != nil {
		outErr = errors.Join(outErr, x.errout.finish())
	}
	prefix, n, h, truncated := x.out.view()
	var ep []byte
	var en int64
	var eh string
	var et bool
	if x.errout != nil {
		ep, en, eh, et = x.errout.view()
	}
	x.mu.Lock()
	if !x.deadline.IsZero() && !waitAt.Before(x.deadline) {
		x.result.DeadlineExpired = true
	}
	x.result.Actual = a
	x.result.NumericDurable = numericErr == nil && rawErr == nil
	x.result.DrainsJoined = true
	x.result.CombinedMode = x.combined
	x.result.StdoutPrefixBytes = int64(len(prefix))
	x.result.StdoutPrefixSHA = SHA(prefix)
	x.result.StderrPrefixBytes = int64(len(ep))
	x.result.StderrPrefixSHA = SHA(ep)
	if x.combined {
		x.result.Combined = prefix
	} else {
		x.result.Stdout = prefix
		x.result.Stderr = ep
	}
	x.result.Truncated = truncated || et
	life := lifecycleError(a, x.result.DeadlineExpired, x.result.JoinWatchdogExpired, x.result.NumericDurable, true, outErr == nil && !x.result.Truncated)
	if x.result.LifecycleError == "" {
		x.result.LifecycleError = life
	}
	x.result.DomainError = domainError(a)
	if x.crashRequested && (!a.Signaled || a.Signal != 9) {
		x.result.LifecycleError = "EXPLICIT_FAULT_NOT_OBSERVED"
	}
	if x.fd >= 0 {
		_ = unix.Close(x.fd)
		x.fd = -1
	}
	result := x.result
	x.mu.Unlock()
	metaErr := durableNew(x.evidence, "joined-streams.json", map[string]any{"actual_wait_durable": result.NumericDurable, "stdout_total_bytes": n, "stdout_full_sha256": h, "stderr_total_bytes": en, "stderr_full_sha256": eh, "stdout_stored_prefix_bytes": len(prefix), "stdout_stored_prefix_sha256": SHA(prefix), "stderr_stored_prefix_bytes": len(ep), "stderr_stored_prefix_sha256": SHA(ep), "wait_error": fmt.Sprint(err), "output_error": fmt.Sprint(outErr), "numeric_error": fmt.Sprint(errors.Join(rawErr, numericErr)), "result": result})
	if metaErr != nil {
		x.mu.Lock()
		x.result.LifecycleError = "CLOSURE_REPORT_FAILURE: " + metaErr.Error()
		x.mu.Unlock()
		x.owner.fail(metaErr)
	}
	if result.LifecycleError != "" {
		x.owner.fail(errors.New(result.LifecycleError))
	}
	close(x.done)
}
func (x *actor) snapshot() Result {
	x.mu.Lock()
	defer x.mu.Unlock()
	r := x.result
	r.Stdout = append([]byte(nil), r.Stdout...)
	r.Stderr = append([]byte(nil), r.Stderr...)
	r.Combined = append([]byte(nil), r.Combined...)
	return r
}
func (x *actor) join() Result { <-x.done; return x.snapshot() }

func (x *actor) signal(signal int, fault *Fault, barrier bool) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	select {
	case <-x.done:
		return nil
	default:
	}
	if x.stopRequested {
		if fault != nil && !x.crashRequested {
			return errors.New("ordinary stop cannot be escalated to a fault")
		}
		return nil
	}
	if !x.result.IntentProven || x.result.DeadlineExpired || x.result.JoinWatchdogExpired || x.fd < 0 || x.strong == nil {
		return errors.New("no strong live signal custody or expired actor")
	}
	if fault == nil && signal != 15 {
		return errors.New("ordinary only TERM")
	}
	if fault != nil {
		if signal != 9 || !barrier || !fault.BarrierRequired || !validSHA(fault.BackupSHA) {
			return errors.New("exact fault/barrier/backup required")
		}
		if e := publicReadonly(fault.BackupPath, 0444); e != nil {
			return e
		}
		raw, e := boundedRead(fault.BackupPath, MaxPacket, true)
		if e != nil || SHA(raw) != fault.BackupSHA {
			return errors.New("Root coherent-backup receipt unavailable/mismatched")
		}
	}
	before, e := observe(x.cmd.Process.Pid, x.fd, x.artifact, x.cmd.Args, x.owner.birth, x.owner.namespaces, x.view)
	if e != nil {
		return e
	}
	after, e := observe(x.cmd.Process.Pid, x.fd, x.artifact, x.cmd.Args, x.owner.birth, x.owner.namespaces, x.view)
	if e != nil {
		return e
	}
	handle := c.Handle{OwnStartPID: x.cmd.Process.Pid, AtomicPIDFD: true, FD: x.fd}
	if e = c.CheckTuple(x.strong.Core, before.Core, after.Core, handle); e != nil {
		return e
	}
	if before.Group != after.Group || before.Session != after.Session || before.Namespaces != after.Namespaces {
		return errors.New("signal group/namespace changed")
	}
	if e = unix.PidfdSendSignal(x.fd, unix.Signal(signal), nil, 0); e != nil {
		return e
	}
	x.stopRequested = true
	if fault != nil {
		x.crashRequested = true
	}
	return nil
}
func (x *actor) ordinaryStopAndJoin() Result {
	select {
	case <-x.done:
		return x.join()
	default:
	}
	if e := x.signal(15, nil, false); e != nil {
		x.owner.fail(e)
	}
	x.joinWatchdog()
	return x.join()
}
func (x *actor) joinWatchdog() {
	x.joinWatchOnce.Do(func() {
		x.owner.observers.Add(1)
		until := time.Now().Add(10 * time.Second)
		go func() {
			defer x.owner.observers.Done()
			timer := time.NewTimer(time.Until(until))
			defer timer.Stop()
			select {
			case <-x.done:
				return
			case <-timer.C:
				x.mu.Lock()
				if !x.waitAt.IsZero() && x.waitAt.Before(until) {
					x.mu.Unlock()
					return
				}
				x.result.JoinWatchdogExpired = true
				x.mu.Unlock()
				x.owner.closeAdmission(x.fixture)
				_, e := fmt.Fprintf(os.Stderr, "NATIVE_JOIN_WATCHDOG_FAIL id=%s noKill=true\n", x.id)
				if e != nil {
					x.owner.fail(e)
				}
			}
		}()
	})
}
