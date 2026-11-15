//go:build linux

package nativefixture

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	c "pluto/internal/testsupport/nativeprocess/custody"
)

type fixture struct {
	id, name, base, config, state, ca string
	closed                            bool
	temporary                         int
}
type Owner struct {
	mu                     sync.Mutex
	manifest               Manifest
	manifestPath, pin      string
	birth                  c.Birth
	namespaces             [3]string
	actors                 map[string]*actor
	fixtures               map[string]*fixture
	caseCounts             map[string]int
	nextActor, nextFixture int
	closed                 bool
	failures               []string
	goTest                 *actor
	ledger                 ReplayLedger
	listener               *net.UnixListener
	handlers               sync.WaitGroup
	acceptDone             chan struct{}
	handlerSlots           chan struct{}
	observers              sync.WaitGroup
}

func NewOwner(manifestPath, pin string) (*Owner, error) {
	if !cleanAbsolute(manifestPath) || filepath.Dir(manifestPath) != "/" {
		return nil, errors.New("Root-level manifest only")
	}
	if e := publicReadonly(manifestPath, 0444); e != nil {
		return nil, e
	}
	raw, e := boundedRead(manifestPath, MaxPacket, true)
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
	if _, e = os.Stat("/.dockerenv"); e != nil {
		return nil, errors.New("owned container prerequisite")
	}
	hostname, e := os.Hostname()
	if e != nil || hostname != m.Hostname {
		return nil, errors.New("actual container hostname mismatch")
	}
	if _, e = fingerprint(m.Owner, fmt.Sprintf("/proc/%d/exe", os.Getpid()), true); e != nil {
		return nil, e
	}
	b, e := birth(os.Getpid())
	if e != nil {
		return nil, e
	}
	ns, e := namespaces(os.Getpid())
	if e != nil {
		return nil, e
	}
	if ns != m.Namespaces {
		return nil, errors.New("Root-admitted own namespaces required")
	}
	if e = privateDirectory(m.RetainedRoot, false); e != nil {
		return nil, e
	}
	if _, e = os.Lstat(m.EvidenceRoot); !os.IsNotExist(e) {
		return nil, errors.New("new-only evidence root")
	}
	if e = privateDirectory(m.EvidenceRoot, true); e != nil {
		return nil, e
	}
	if _, e = os.Lstat(m.Socket); !os.IsNotExist(e) {
		return nil, errors.New("new-only owned socket")
	}
	if !beneath(m.RetainedRoot, m.Socket) || len(m.RetainedRoot) > 65 {
		return nil, errors.New("bounded same retained socket namespace")
	}
	return &Owner{manifest: m, manifestPath: manifestPath, pin: pin, birth: b, namespaces: ns, actors: map[string]*actor{}, fixtures: map[string]*fixture{}, caseCounts: map[string]int{}, handlerSlots: make(chan struct{}, 16)}, nil
}
func (o *Owner) fail(e error) {
	if e == nil {
		return
	}
	o.mu.Lock()
	o.failures = append(o.failures, e.Error())
	o.closed = true
	o.mu.Unlock()
}
func (o *Owner) closeAdmission(fixtureID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	if f := o.fixtures[fixtureID]; f != nil {
		f.closed = true
	}
}

// Run owns the compiled Go test actor from its own Start, before Go can request
// any CLI. A Go test global panic cannot destroy this loaded owner or its child
// registry. This is a sole-spawn implementation, not a later subreaper adoption.
func (o *Owner) Run() (outcome int) {
	outcome = 1
	defer func() {
		if p := recover(); p != nil {
			o.fail(fmt.Errorf("owner panic retained: %v", p))
		}
		o.closeAdmission("")
		o.closeAllProducts()
		if o.acceptDone == nil && o.listener != nil {
			_ = o.listener.Close()
		}
		if o.goTest != nil {
			_ = o.goTest.join()
		}
		if o.listener != nil {
			_ = o.listener.Close()
		}
		if o.acceptDone != nil {
			<-o.acceptDone
		}
		o.handlers.Wait()
		o.closeAllProducts()
		o.observers.Wait()
	}()
	ln, e := net.ListenUnix("unixpacket", &net.UnixAddr{Name: o.manifest.Socket, Net: "unixpacket"})
	if e != nil {
		o.fail(e)
		return
	}
	ln.SetUnlinkOnClose(false)
	o.listener = ln
	listenerFD, e := ln.SyscallConn()
	if e != nil {
		o.fail(e)
		return
	}
	var passErr error
	if e = listenerFD.Control(func(fd uintptr) { passErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); e != nil || passErr != nil {
		o.fail(errors.Join(e, passErr))
		return
	}
	if e = os.Chmod(o.manifest.Socket, 0600); e != nil {
		o.fail(e)
		return
	} // only own NEW socket
	env := append([]string(nil), o.manifest.Environment...)
	for _, item := range env {
		if strings.HasPrefix(item, "EXOCORTEX_NATIVE_OWNER_") {
			o.fail(errors.New("no conflicting owner env"))
			return
		}
	}
	env = append(env, "EXOCORTEX_NATIVE_OWNER_MANIFEST="+o.manifestPath, "EXOCORTEX_NATIVE_OWNER_MANIFEST_SHA="+o.pin)
	g, e := o.startActor(nil, "go-test", "go-test", o.manifest.GoTest, o.manifest.GoArgs, env, time.Time{}, true)
	o.goTest = g
	if e != nil {
		o.fail(e)
		return
	}
	g.mu.Lock()
	strong := g.strong != nil
	g.mu.Unlock()
	if !strong {
		o.fail(errors.New("actual Go test tuple required before RPC admission"))
		return
	}
	o.acceptDone = make(chan struct{})
	go o.accept()
	result := g.join()
	o.closeAdmission("")
	o.closeAllProducts()
	_ = ln.Close()
	<-o.acceptDone
	o.handlers.Wait()
	o.mu.Lock()
	failures := append([]string(nil), o.failures...)
	o.mu.Unlock()
	if e = durableNew(o.manifest.EvidenceRoot, "owner-final.json", map[string]any{"go_actual": result.Actual, "go_lifecycle": result.LifecycleError, "failures": failures, "all_products_joined": true, "no_adopted_children": true}); e != nil {
		o.fail(e)
		return
	}
	if len(failures) == 0 && result.LifecycleError == "" && result.Actual.Exited {
		outcome = result.Actual.ExitCode
	}
	return
}
func (o *Owner) accept() {
	defer close(o.acceptDone)
	for {
		conn, e := o.listener.AcceptUnix()
		if e != nil {
			return
		}
		o.handlerSlots <- struct{}{}
		o.handlers.Add(1)
		go func() {
			defer o.handlers.Done()
			defer func() { <-o.handlerSlots }()
			defer conn.Close()
			if e := o.serveOne(conn); e != nil {
				o.fail(e)
			}
		}()
	}
}
func passCred(conn *net.UnixConn) error {
	raw, e := conn.SyscallConn()
	if e != nil {
		return e
	}
	var se error
	e = raw.Control(func(fd uintptr) { se = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
	return errors.Join(e, se)
}
func peerCredentials(oob []byte) (*unix.Ucred, error) {
	msgs, e := unix.ParseSocketControlMessage(oob)
	if e != nil {
		return nil, e
	}
	records := []CredentialRecord{}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_RIGHTS {
			fds, e := unix.ParseUnixRights(&m)
			if e != nil {
				records = append(records, CredentialRecord{Kind: "invalid"})
			} else {
				records = append(records, CredentialRecord{Kind: "rights", FDs: fds})
			}
			continue
		}
		if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_CREDENTIALS {
			v, e := unix.ParseUnixCredentials(&m)
			if e != nil {
				records = append(records, CredentialRecord{Kind: "invalid"})
			} else {
				records = append(records, CredentialRecord{Kind: "credentials", PID: int(v.Pid), UID: v.Uid, GID: v.Gid})
			}
			continue
		}
		records = append(records, CredentialRecord{Kind: "invalid"})
	}
	plan := PlanCredentials(records)
	for _, fd := range plan.CloseFDs {
		_ = unix.Close(fd)
	}
	if plan.Error != nil {
		return nil, plan.Error
	}
	return &unix.Ucred{Pid: int32(plan.PID), Uid: plan.UID, Gid: plan.GID}, nil
}
func (o *Owner) serveOne(conn *net.UnixConn) error {
	if e := passCred(conn); e != nil {
		return e
	}
	// Finite REQUEST admission wait only. It is cleared before any real join.
	if e := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
		return e
	}
	raw := make([]byte, MaxPacket+1)
	control := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(8*4))
	n, on, flags, _, e := conn.ReadMsgUnix(raw, control)
	cred, credentialErr := peerCredentials(control[:on])
	if e != nil {
		return errors.Join(e, credentialErr)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > MaxPacket {
		return errors.Join(errors.New("truncated/oversized message refused"), credentialErr)
	}
	if credentialErr != nil {
		return credentialErr
	}
	var request Request
	if e = strictJSON(raw[:n], &request); e != nil {
		return e
	}
	o.mu.Lock()
	g := o.goTest
	if g == nil {
		o.mu.Unlock()
		return errors.New("no admitted caller")
	}
	expectedPID := g.cmd.Process.Pid
	e = o.ledger.Admit(o.manifest, request, int(cred.Pid), expectedPID)
	o.mu.Unlock()
	if e != nil {
		return e
	}
	// Kernel sender PID is not sufficient alone: actual birth/exe/argv/profile,
	// parent and right same-Start fd must still be this original Go actor.
	g.mu.Lock()
	_, e = observe(expectedPID, g.fd, g.artifact, g.cmd.Args, o.birth, o.namespaces, g.view)
	g.mu.Unlock()
	if e != nil {
		return e
	}
	_ = conn.SetReadDeadline(time.Time{})
	result, e := o.dispatch(request)
	response := Response{Sequence: request.Sequence, Result: result}
	if e != nil {
		response.Error = e.Error()
		o.fail(e)
	}
	payload, e := json.Marshal(response)
	if e != nil {
		return e
	}
	if len(payload) > MaxPacket {
		return errors.New("bounded response metadata required")
	}
	if e = conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); e != nil {
		return e
	}
	written, _, e := conn.WriteMsgUnix(payload, nil, nil)
	if e == nil && written != len(payload) {
		e = errors.New("short response")
	}
	return e
}
func (o *Owner) getFixture(r Request) (*fixture, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	f := o.fixtures[r.Fixture]
	if f == nil || f.name != r.Case {
		return nil, errors.New("exact own case/fixture required")
	}
	return f, nil
}
func (o *Owner) dispatch(r Request) (Result, error) {
	if _, ok := o.manifest.Cases[r.Case]; !ok {
		return Result{}, errors.New("unadmitted exact test case")
	}
	if r.Operation == "fixture" {
		return o.newFixture(r)
	}
	f, e := o.getFixture(r)
	if e != nil {
		return Result{}, e
	}
	switch r.Operation {
	case "temp":
		o.mu.Lock()
		if o.closed || f.closed || f.temporary >= 16 {
			o.mu.Unlock()
			return Result{}, errors.New("temporary allocation admission closed/bound")
		}
		f.temporary++
		p := filepath.Join(f.base, fmt.Sprintf("d-%02d", f.temporary))
		o.mu.Unlock()
		if e = privateDirectory(p, true); e != nil {
			return Result{}, e
		}
		return Result{Fixture: f.id, Base: p}, nil
	case "bind":
		if e = o.bind(f, r); e != nil {
			return Result{}, e
		}
		return Result{Fixture: f.id, Base: f.base}, nil
	case "spawn":
		return o.spawn(f, r)
	case "wait", "stop", "crash", "deadline":
		o.mu.Lock()
		a := o.actors[r.Actor]
		o.mu.Unlock()
		if a == nil || a.fixture != f.id {
			return Result{}, errors.New("actor id is not this own fixture")
		}
		if r.Operation == "deadline" {
			if r.Action == "barrier" && a.role != "adoption-fault" {
				return Result{}, errors.New("barrier deadline wrong role")
			}
			a.expireKind("caller existing action/barrier deadline", r.Action == "barrier")
			return a.snapshot(), nil
		}
		if r.Operation == "stop" {
			return a.ordinaryStopAndJoin(), nil
		}
		if r.Operation == "crash" {
			fault, ok := o.manifest.Cases[f.name].Faults[r.Action]
			if !ok || fault.Site != r.Action {
				return Result{}, errors.New("exact Root fault site required")
			}
			if e = a.signal(9, &fault, r.BarrierObserved); e != nil {
				return Result{}, e
			}
			return a.join(), nil
		}
		return a.join(), nil
	case "close":
		o.mu.Lock()
		f.closed = true
		o.mu.Unlock()
		o.closeProducts(f.id)
		return Result{Fixture: f.id, Base: f.base}, nil
	case "copy":
		return o.copy(f, r)
	}
	return Result{}, errors.New("fixed operation required")
}
func (o *Owner) newFixture(r Request) (Result, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.manifest.Cases[r.Case]
	if o.closed || time.Now().UnixMilli() >= o.manifest.ExpiresUnixMs || o.caseCounts[r.Case] >= c.MaxFixtures {
		return Result{}, errors.New("fresh fixture admission closed")
	}
	o.nextFixture++
	id := fmt.Sprintf("f-%04d", o.nextFixture)
	base := filepath.Join(o.manifest.RetainedRoot, id)
	if e := privateDirectory(base, true); e != nil {
		return Result{}, e
	}
	f := &fixture{id: id, name: r.Case, base: base}
	o.fixtures[id] = f
	o.caseCounts[r.Case]++
	if e := durableNew(base, "fixture-owner.json", map[string]any{"scope": o.manifest.Scope, "nonce": o.manifest.Nonce, "case": r.Case, "id": id, "base": base, "retention": "NO_AUTOMATIC_DELETION_EVEN_ON_FAIL"}); e != nil {
		return Result{}, e
	}
	return Result{Fixture: id, Base: base}, nil
}
func (o *Owner) bind(f *fixture, r Request) error {
	for _, p := range []string{r.Config, r.State} {
		if e := withinPrivate(f.base, p, false); e != nil {
			return e
		}
	}
	if r.Profile != "" {
		if e := withinPrivate(f.base, r.Profile, false); e != nil {
			return e
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || f.closed {
		return errors.New("bind admission closed")
	}
	if f.config != "" {
		if f.config != r.Config || f.state != r.State || f.ca != r.Profile {
			return errors.New("fixture paths cannot change")
		}
		return nil
	}
	f.config, f.state, f.ca = r.Config, r.State, r.Profile
	return nil
}
func (o *Owner) spawn(f *fixture, r Request) (Result, error) {
	if time.Now().UnixMilli() >= o.manifest.ExpiresUnixMs {
		return Result{}, errors.New("Root spawn admission expired")
	}
	role, key, action := r.Role, "current", r.Action
	if role == "daemon" {
		action = "daemon"
	} else if role == "adoption-fault" {
		action = "adopt"
	} else if role == "domain" {
		if !allowedAction(action) || action == "daemon" || action == "copy-indexed" {
			return Result{}, errors.New("domain action")
		}
	} else {
		switch role {
		case "batch-current", "remount-current":
			action = "copy-indexed"
		case "historical-r1e", "historical-r1f":
			action = "copy-indexed"
			key = role
		default:
			return Result{}, errors.New("fixed native role")
		}
	}
	a, ok := o.manifest.Artifacts[key]
	if !ok {
		return Result{}, errors.New("authentic admitted role artifact missing")
	}
	o.mu.Lock()
	config, state, ca := f.config, f.state, f.ca
	o.mu.Unlock()
	if config == "" || state == "" {
		return Result{}, errors.New("bound exact config/state required")
	}
	for _, p := range []string{config, state} {
		if e := withinPrivate(f.base, p, false); e != nil {
			return Result{}, e
		}
	}
	if r.Profile != "" {
		if e := withinPrivate(f.base, r.Profile, false); e != nil {
			return Result{}, e
		}
	}
	args, e := commandArgs(action, config, state, filepath.Join(f.base, "control.sock"), r.Profile, r.Digest)
	if e != nil {
		return Result{}, e
	}
	budgetKey := action
	if action == "copy-indexed" {
		budgetKey = role
	}
	maximum, ok := o.manifest.Cases[f.name].Actions[budgetKey]
	if !ok || maximum <= 0 {
		return Result{}, errors.New("existing enclosing action budget required")
	}
	due := time.Time{}
	if role != "daemon" {
		now := time.Now()
		if r.DeadlineUnixMs <= now.UnixMilli() || r.DeadlineUnixMs > now.Add(time.Duration(maximum)*time.Millisecond).UnixMilli() {
			return Result{}, errors.New("original finite deadline must not be widened/reset")
		}
		due = time.UnixMilli(r.DeadlineUnixMs)
	}
	env := append([]string(nil), o.manifest.Environment...)
	if ca != "" {
		env = append(env, "SSL_CERT_FILE="+ca)
	}
	x, e := o.startActor(f, role, action, a, args, env, due, role == "domain" || role == "daemon" || role == "adoption-fault")
	if x == nil {
		return Result{}, e
	}
	return x.snapshot(), e
}
func (o *Owner) productActors(fixtureID string) []*actor {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []*actor
	for _, a := range o.actors {
		if a.role != "go-test" && (fixtureID == "" || a.fixture == fixtureID) {
			out = append(out, a)
		}
	}
	return out
}
func (o *Owner) closeProducts(fixtureID string) {
	actors := o.productActors(fixtureID)
	// Request every authorized ordinary stop BEFORE blocking on any one join.
	for _, a := range actors {
		select {
		case <-a.done:
			continue
		default:
		}
		if e := a.signal(15, nil, false); e != nil {
			o.fail(e)
		}
		if a.role == "daemon" {
			a.joinWatchdog()
		}
	}
	for _, a := range actors {
		_ = a.join()
	}
}
func (o *Owner) closeAllProducts() { o.closeProducts("") }

func (o *Owner) copy(f *fixture, r Request) (Result, error) {
	// Separate collector lease; never reopens product admission after failure.
	o.mu.Lock()
	closed := f.closed
	o.mu.Unlock()
	if !closed {
		return Result{}, errors.New("copy only after fixture admission closed and actors joined")
	}
	for _, a := range o.productActors(f.id) {
		select {
		case <-a.done:
		default:
			return Result{}, errors.New("copy before actual actor closure")
		}
	}
	a, ok := o.manifest.Artifacts["copy"]
	if !ok {
		return Result{}, errors.New("reviewed copy utility descriptor missing")
	}
	if r.Action != "state" && r.Action != "source-sparse" {
		return Result{}, errors.New("fixed collector mode")
	}
	if e := withinPrivate(f.base, r.CopySource, false); e != nil {
		return Result{}, e
	}
	expectedDestination := o.manifest.Cases[f.name].CopyDestinations[r.Action]
	if !beneath(o.manifest.EvidenceRoot, r.CopyDestination) || r.CopyDestination != expectedDestination {
		return Result{}, errors.New("Root exact new-only collector destination")
	}
	if _, e := os.Lstat(r.CopyDestination); !os.IsNotExist(e) {
		return Result{}, errors.New("copy output exists/unknown")
	}
	ms := o.manifest.Cases[f.name].CopyMs
	if ms <= 0 {
		return Result{}, errors.New("separate Root collector budget missing")
	}
	maximum := o.manifest.Cases[f.name].CopyMaxBytes
	if maximum <= 0 {
		return Result{}, errors.New("Root collector byte bound missing")
	}
	before, e := copyInventory(r.CopySource, maximum)
	if e != nil {
		return Result{}, e
	}
	// Atomically reserve the destination directory. No copy is allowed to merge
	// into an earlier scope's output, even if the utility would silently skip it.
	if e = privateDirectory(r.CopyDestination, true); e != nil {
		return Result{}, e
	}
	// Implementation uses an independently registered collector owner. Product
	// admission never gets toggled back to open. See startCollector below.
	args := []string{"-a", "--no-clobber", "--", r.CopySource + "/.", r.CopyDestination}
	if r.Action == "source-sparse" {
		args = []string{"-a", "--sparse=always", "--no-clobber", "--", r.CopySource + "/.", r.CopyDestination}
	}
	x, e := o.startCollector(f, a, args, time.Now().Add(time.Duration(ms)*time.Millisecond))
	if e != nil {
		return Result{}, e
	}
	result := x.join()
	afterSource, e := copyInventory(r.CopySource, maximum)
	if e != nil {
		return result, e
	}
	afterDestination, e := copyInventory(r.CopyDestination, maximum)
	if e != nil {
		return result, e
	}
	b, _ := json.Marshal(before)
	s, _ := json.Marshal(afterSource)
	d, _ := json.Marshal(afterDestination)
	if string(b) != string(s) || string(b) != string(d) {
		return result, errors.New("collector source changed or copied tree bytes differ")
	}
	if e = durableNew(x.evidence, "copy-byte-proof.json", map[string]any{"source": r.CopySource, "destination": r.CopyDestination, "entries": before, "inode_identity_preserved": false}); e != nil {
		return result, e
	}
	return result, nil
}
