//go:build linux

package nativefixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type Client struct {
	manifest  Manifest
	path, pin string
	parentPID int
}

// All clients in the same admitted Go actor share one replay namespace.
var callerSequence atomic.Uint64

func (c *Client) nextRequestSequence() uint64 { return callerSequence.Add(1) }

type Scope struct {
	client         *Client
	Case, ID, Base string
	mu             sync.Mutex
	closed         bool
	children       map[string]*Child
	releases       []func()
	deadlines      map[uint64]time.Time
	nextDeadline   uint64
	goRoutines     sync.WaitGroup
	inflight       sync.WaitGroup
}
type Child struct {
	scope                  *Scope
	ID                     string
	mu                     sync.Mutex
	result                 Result
	done                   chan struct{}
	waitDone               chan struct{}
	waitStarted            bool
	waitOnce, completeOnce sync.Once
}

// PreparedCheckpointPaths returns only the paths admitted for this exact scope.
// The receipt remains unavailable until the independent restore worker succeeds.
func (s *Scope) PreparedCheckpointPaths() (root, receipt string, err error) {
	const name = "TestStage3C12NativeReviewedPolicyScopesAndRestart"
	if s.Case != name {
		return "", "", errors.New("PREPARED checkpoint is bound to its original testcase")
	}
	fault, ok := s.client.manifest.Cases[s.Case].Faults[FaultSite(s.Case)]
	if !ok || fault.CheckpointRoot == "" {
		return "", "", errors.New("Root-admitted PREPARED checkpoint paths required")
	}
	return fault.CheckpointRoot, fault.BackupPath, nil
}

func ClientFromEnvironment() (*Client, error) {
	p, pin := os.Getenv("EXOCORTEX_NATIVE_OWNER_MANIFEST"), os.Getenv("EXOCORTEX_NATIVE_OWNER_MANIFEST_SHA")
	if p == "" || pin == "" {
		return nil, errors.New("Root-reviewed loaded native owner required; no exec fallback")
	}
	if e := publicReadonly(p, 0444); e != nil {
		return nil, e
	}
	raw, e := boundedRead(p, MaxPacket, true)
	if e != nil {
		return nil, e
	}
	m, e := DecodeManifest(raw, pin, time.Now().UnixMilli())
	if e != nil {
		return nil, e
	}
	if e = selfProfile(); e != nil {
		return nil, e
	}
	if _, e = fingerprint(m.GoTest, fmt.Sprintf("/proc/%d/exe", os.Getpid()), true); e != nil {
		return nil, e
	}
	ns, e := namespaces(os.Getpid())
	if e != nil || ns != m.Namespaces {
		return nil, errors.New("caller outside admitted container namespaces")
	}
	b, e := birth(os.Getpid())
	if e != nil {
		return nil, e
	}
	if _, e = fingerprint(m.Owner, fmt.Sprintf("/proc/%d/exe", b.PPID), true); e != nil {
		return nil, e
	}
	return &Client{manifest: m, path: p, pin: pin, parentPID: b.PPID}, nil
}
func (c *Client) rpc(r Request) (Result, error) {
	sequence := c.nextRequestSequence()
	r.Schema = "nativefixture.rpc.v2"
	r.Scope = c.manifest.Scope
	r.Nonce = c.manifest.Nonce
	r.Sequence = sequence
	raw, e := json.Marshal(r)
	if e != nil {
		return Result{}, e
	}
	if len(raw) > MaxPacket {
		return Result{}, errors.New("bounded typed request")
	}
	if e = withinPrivate(c.manifest.RetainedRoot, c.manifest.Socket, false); e != nil {
		return Result{}, e
	}
	conn, e := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: c.manifest.Socket, Net: "unixpacket"})
	if e != nil {
		return Result{}, e
	}
	defer conn.Close()
	if e = passCred(conn); e != nil {
		return Result{}, e
	}
	// This client never sends a PID, process handle, fd or arbitrary executable.
	n, _, e := conn.WriteMsgUnix(raw, nil, nil)
	if e != nil || n != len(raw) {
		return Result{}, errors.Join(e, errors.New("request write incomplete"))
	}
	buf := make([]byte, MaxPacket+1)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, on, flags, _, e := conn.ReadMsgUnix(buf, oob)
	// Inventory and close every delivered right even on truncated/error responses.
	credential, credentialErr := peerCredentials(oob[:on])
	if e != nil {
		return Result{}, errors.Join(e, credentialErr)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > MaxPacket {
		return Result{}, errors.Join(errors.New("response truncated"), credentialErr)
	}
	if credentialErr != nil || int(credential.Pid) != c.parentPID {
		return Result{}, errors.New("response is not actual own loaded parent")
	}
	var response Response
	if e = strictJSON(buf[:n], &response); e != nil {
		return Result{}, e
	}
	if response.Sequence != sequence {
		return Result{}, errors.New("response sequence mismatch")
	}
	if response.Error != "" {
		return response.Result, errors.New(response.Error)
	}
	return response.Result, nil
}
func (c *Client) NewScope(testName string) (*Scope, error) {
	if _, ok := c.manifest.Cases[testName]; !ok {
		return nil, errors.New("exact native test case not admitted")
	}
	r, e := c.rpc(Request{Operation: "fixture", Case: testName})
	if e != nil {
		return nil, e
	}
	if !beneath(c.manifest.RetainedRoot, r.Base) || filepath.Base(r.Base) != r.Fixture {
		return nil, errors.New("returned fixture outside admitted root")
	}
	return &Scope{client: c, Case: testName, ID: r.Fixture, Base: r.Base, children: map[string]*Child{}, deadlines: map[uint64]time.Time{}}, nil
}
func (s *Scope) req(op string) Request { return Request{Operation: op, Case: s.Case, Fixture: s.ID} }
func (s *Scope) Artifact(role string) (Artifact, error) {
	if role == "domain" || role == "daemon" || role == "adoption-fault" || role == "batch-current" || role == "remount-current" {
		role = "current"
	}
	a, ok := s.client.manifest.Artifacts[role]
	if !ok {
		return Artifact{}, errors.New("exact role artifact missing")
	}
	return a, nil
}
func (s *Scope) TempDir() (string, error) { r, e := s.client.rpc(s.req("temp")); return r.Base, e }
func (s *Scope) Bind(config, state, ca string) error {
	r := s.req("bind")
	r.Config = config
	r.State = state
	r.Profile = ca
	_, e := s.client.rpc(r)
	return e
}
func (s *Scope) RegisterRelease(release func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var once sync.Once
	s.releases = append(s.releases, func() { once.Do(release) })
}
func (s *Scope) PushDeadline(until time.Time) func() {
	s.mu.Lock()
	s.nextDeadline++
	id := s.nextDeadline
	s.deadlines[id] = until
	s.mu.Unlock()
	return func() { s.mu.Lock(); delete(s.deadlines, id); s.mu.Unlock() }
}
func (s *Scope) due(ctx context.Context, key string) (time.Time, error) {
	maximum, ok := s.client.manifest.Cases[s.Case].Actions[key]
	if !ok || maximum <= 0 {
		return time.Time{}, errors.New("explicit existing enclosing action budget absent")
	}
	until := time.Now().Add(time.Duration(maximum) * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return time.Time{}, errors.New("scope admission closed")
	}
	for _, d := range s.deadlines {
		if d.Before(until) {
			until = d
		}
	}
	if !time.Now().Before(until) {
		return time.Time{}, errors.New("original enclosing deadline already expired")
	}
	return until, nil
}
func (s *Scope) Start(ctx context.Context, role, action, profile, digest string) (*Child, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("scope closed; no new actor")
	}
	s.inflight.Add(1)
	s.mu.Unlock()
	defer s.inflight.Done()
	key := action
	if role != "domain" && role != "daemon" && role != "adoption-fault" {
		key = role
	}
	due, e := s.due(ctx, key)
	if e != nil {
		return nil, e
	}
	r := s.req("spawn")
	r.Role = role
	r.Action = action
	r.Profile = profile
	r.Digest = digest
	if role != "daemon" {
		r.DeadlineUnixMs = due.UnixMilli()
	}
	result, e := s.client.rpc(r)
	if result.ID == "" {
		return nil, e
	}
	child := &Child{scope: s, ID: result.ID, result: result, done: make(chan struct{}), waitDone: make(chan struct{})}
	s.mu.Lock()
	s.children[child.ID] = child
	s.mu.Unlock()
	if e != nil {
		child.ensureWait()
		return child, e
	}
	if role != "daemon" {
		child.ensureWait()
		s.mu.Lock()
		s.goRoutines.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.goRoutines.Done()
			select {
			case <-ctx.Done():
				select {
				case <-child.done:
					return
				default:
				}
				_ = child.actionDeadline()
			case <-child.done:
			}
		}()
	}
	return child, nil
}
func (s *Scope) Run(ctx context.Context, role, action, profile, digest string) Result {
	child, e := s.Start(ctx, role, action, profile, digest)
	if child == nil {
		return Result{LifecycleError: fmt.Sprint(e)}
	}
	r := child.Join()
	if e != nil && r.LifecycleError == "" {
		r.LifecycleError = e.Error()
	}
	return r
}
func (c *Child) ensureWait() {
	select {
	case <-c.done:
		return
	default:
	}
	c.waitOnce.Do(func() {
		c.mu.Lock()
		c.waitStarted = true
		c.mu.Unlock()
		go func() {
			defer close(c.waitDone)
			r := c.scope.req("wait")
			r.Actor = c.ID
			result, e := c.scope.client.rpc(r)
			if e != nil {
				result.LifecycleError = "WAIT_RPC_FAILURE_ACTUAL_NOT_INFERRED: " + e.Error()
			}
			c.complete(result)
		}()
	})
}
func (c *Child) complete(r Result) {
	c.completeOnce.Do(func() {
		if r.NumericDurable && r.DrainsJoined {
			read := func(name string, n int64, sha string) ([]byte, error) {
				p := filepath.Join(r.Evidence, name)
				if !beneath(c.scope.client.manifest.EvidenceRoot, p) {
					return nil, errors.New("owned output path")
				}
				b, e := boundedRead(p, c.scope.client.manifest.OutputPrefixBytes, true)
				if e != nil {
					return nil, e
				}
				if int64(len(b)) != n || SHA(b) != sha {
					return nil, errors.New("exact output prefix mismatch")
				}
				return b, nil
			}
			out, e := read("stdout-prefix.log", r.StdoutPrefixBytes, r.StdoutPrefixSHA)
			if e != nil {
				r.LifecycleError = "OUTPUT_READBACK: " + e.Error()
			}
			if r.CombinedMode {
				r.Combined = out
			} else {
				r.Stdout = out
				errout, e := read("stderr-prefix.log", r.StderrPrefixBytes, r.StderrPrefixSHA)
				if e != nil {
					r.LifecycleError = "STDERR_READBACK: " + e.Error()
				}
				r.Stderr = errout
			}
		}
		c.mu.Lock()
		c.result = r
		c.mu.Unlock()
		close(c.done)
	})
}
func (c *Child) Join() Result {
	c.ensureWait()
	<-c.done
	c.mu.Lock()
	waitStarted := c.waitStarted
	c.mu.Unlock()
	if waitStarted {
		<-c.waitDone
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.result
}
func (c *Child) actionDeadline() error {
	r := c.scope.req("deadline")
	r.Actor = c.ID
	r.Action = "existing-action"
	_, e := c.scope.client.rpc(r)
	return e
}
func (c *Child) FailDeadline(_ string) error {
	c.scope.mu.Lock()
	c.scope.closed = true
	c.scope.mu.Unlock()
	r := c.scope.req("deadline")
	r.Actor = c.ID
	r.Action = "barrier"
	_, e := c.scope.client.rpc(r)
	return e
}
func (c *Child) Stop() Result {
	r := c.scope.req("stop")
	r.Actor = c.ID
	result, e := c.scope.client.rpc(r)
	if e != nil {
		result.LifecycleError = e.Error()
	}
	c.complete(result)
	return c.Join()
}
func (c *Child) Crash(site string, barrier bool) Result {
	r := c.scope.req("crash")
	r.Actor = c.ID
	r.Action = site
	r.BarrierObserved = barrier
	result, e := c.scope.client.rpc(r)
	if e != nil {
		result.LifecycleError = e.Error()
	}
	if result.NumericDurable {
		c.complete(result)
	} else if e != nil {
		c.scope.releaseGates()
		_ = c.scope.Close()
	}
	return c.Join()
}
func (s *Scope) releaseGates() {
	s.mu.Lock()
	releases := append([]func(){}, s.releases...)
	s.mu.Unlock()
	for _, release := range releases {
		release()
	}
}
func (s *Scope) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.inflight.Wait()
	s.mu.Lock()
	children := make([]*Child, 0, len(s.children))
	for _, c := range s.children {
		children = append(children, c)
	}
	s.mu.Unlock()
	s.releaseGates()
	_, e := s.client.rpc(s.req("close"))
	for _, child := range children {
		r := child.Join()
		if r.LifecycleError != "" {
			e = errors.Join(e, errors.New(r.LifecycleError))
		}
	}
	s.goRoutines.Wait()
	return e
}

// Registers the other fixture goroutine before it can outlive a Fatal branch.
func (s *Scope) Go(fn func()) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("goroutine admission closed")
	}
	s.goRoutines.Add(1)
	s.mu.Unlock()
	go func() { defer s.goRoutines.Done(); fn() }()
	return nil
}
func (s *Scope) Copy(mode, source, destination string) Result {
	if e := s.Close(); e != nil {
		return Result{LifecycleError: e.Error()}
	}
	r := s.req("copy")
	r.Action = mode
	r.CopySource = source
	r.CopyDestination = destination
	result, e := s.client.rpc(r)
	if e != nil {
		result.LifecycleError = e.Error()
	}
	completed := &Child{scope: s, ID: result.ID, done: make(chan struct{}), waitDone: make(chan struct{})}
	completed.complete(result)
	completed.mu.Lock()
	defer completed.mu.Unlock()
	return completed.result
}
