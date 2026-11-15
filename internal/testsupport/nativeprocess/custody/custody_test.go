package nativecustody

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func originalTuple() Tuple {
	return Tuple{Birth: Birth{PID: 4101, PPID: 4001, Ticks: 12345, State: 'S'}, Parent: Birth{PID: 4001, PPID: 1, Ticks: 10000, State: 'R'}, PIDFDTarget: 4101, Exe: "/exocortex-cnative-0123456789abcdef.cli", ExeSHA256: strings.Repeat("a", 64), Argv: []string{"/exocortex-cnative-0123456789abcdef.cli", "daemon", "--config", "/fixture/own/config.json"}, Profile: Profile{UID: [4]uint32{10001, 10001, 10001, 10001}, GID: [4]uint32{10001, 10001, 10001, 10001}, Groups: []uint32{}, NNP: 1, Seccomp: 2}}
}

func cloneTuple(value Tuple) Tuple {
	value.Argv = append([]string{}, value.Argv...)
	value.Profile.Groups = append([]uint32{}, value.Profile.Groups...)
	return value
}

func validFile() (Artifact, FileView, Namespace) {
	return Artifact{LogicalPath: "raw/pluto-production-trust-artifacts-minimal-a01/pluto-linux-amd64", Bytes: 4, SHA256: strings.Repeat("a", 64)}, FileView{Path: "/exocortex-cnative-0123456789abcdef.cli", Device: 88, Inode: 200, UID: 0, GID: 0, Mode: 0555, Regular: true, Bytes: 4, SHA256: strings.Repeat("a", 64)}, Namespace{Path: "/", Device: 88, Inode: 1, UID: 0, GID: 0, Mode: 0755, Directory: true}
}

// Exactly31 meaningful decision vectors; these never fork or signal a process.
func TestCustodyAdmission31(t *testing.T) {
	type vector struct {
		name string
		run  func(*testing.T)
	}
	cases := []vector{}
	deny := func(name string, change func(*Tuple, *Handle)) {
		cases = append(cases, vector{name, func(t *testing.T) {
			expected := originalTuple()
			actual := cloneTuple(expected)
			handle := Handle{OwnStartPID: 4101, AtomicPIDFD: true, FD: 17}
			change(&actual, &handle)
			if SignalAllowed(expected, actual, actual, handle, Policy{Signal: 15}) == nil {
				t.Fatal("custody mutation admitted signal")
			}
		}})
	}
	deny("zeroPID", func(a *Tuple, h *Handle) { a.Birth.PID = 0 })
	deny("otherPID", func(a *Tuple, h *Handle) { a.Birth.PID = 4102 })
	deny("newBirth", func(a *Tuple, h *Handle) { a.Birth.Ticks++ })
	deny("wrongParent", func(a *Tuple, h *Handle) { a.Birth.PPID = 2 })
	deny("newParentBirth", func(a *Tuple, h *Handle) { a.Parent.Ticks++ })
	deny("deletedExe", func(a *Tuple, h *Handle) { a.Exe += " (deleted)" })
	deny("otherExe", func(a *Tuple, h *Handle) { a.Exe = "/foreign/pluto" })
	deny("otherSHA", func(a *Tuple, h *Handle) { a.ExeSHA256 = strings.Repeat("b", 64) })
	deny("otherArgv", func(a *Tuple, h *Handle) { a.Argv[3] = "/foreign/config.json" })
	deny("rootUID", func(a *Tuple, h *Handle) { a.Profile.UID = [4]uint32{0, 0, 0, 0} })
	deny("rootGID", func(a *Tuple, h *Handle) { a.Profile.GID = [4]uint32{0, 0, 0, 0} })
	deny("rootGroup", func(a *Tuple, h *Handle) { a.Profile.Groups = []uint32{0} })
	deny("NNP0", func(a *Tuple, h *Handle) { a.Profile.NNP = 0 })
	deny("seccomp0", func(a *Tuple, h *Handle) { a.Profile.Seccomp = 0 })
	deny("zombie", func(a *Tuple, h *Handle) { a.Birth.State = 'Z' })
	deny("noAtomicSameStartPIDFD", func(a *Tuple, h *Handle) { h.AtomicPIDFD = false })
	for index, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		deny("nonzero"+name, func(a *Tuple, h *Handle) { a.Profile.Caps[index] = 1 << 21 })
	}
	cases = append(cases,
		vector{"unknownReadNoSignal", func(t *testing.T) {
			e := originalTuple()
			if SignalAllowed(e, Tuple{}, Tuple{}, Handle{4101, true, 17}, Policy{Signal: 15}) == nil {
				t.Fatal("unknown evidence admitted")
			}
		}},
		vector{"incoherentReadNoSignal", func(t *testing.T) {
			e := originalTuple()
			after := cloneTuple(e)
			after.Birth.Ticks++
			if SignalAllowed(e, e, after, Handle{4101, true, 17}, Policy{Signal: 15}) == nil {
				t.Fatal("changed during read")
			}
		}},
		vector{"candidateRefusalBeforeStart", func(t *testing.T) {
			e, a, n := validFile()
			a.Bytes++
			if CheckArtifact(e, a, a, n, n) == nil {
				t.Fatal("unadmitted candidate")
			}
		}},
		vector{"alreadyReapedExit0", func(t *testing.T) {
			s, e := JoinDisposition(WaitResult{Observed: true, Exited: true, ExitCode: 0}, true, false, false, true)
			if e != nil || s != "NATURAL_JOINED0" {
				t.Fatal(s, e)
			}
		}},
		vector{"early0NotCustodyPASS", func(t *testing.T) {
			s, e := JoinDisposition(WaitResult{Observed: true, Exited: true, ExitCode: 0}, true, false, false, false)
			if e != nil || s != "FAIL_CUSTODY_WITH_ACTUAL_OUTCOME" {
				t.Fatal(s, e)
			}
		}},
		vector{"normalTERM", func(t *testing.T) {
			e := originalTuple()
			if err := SignalAllowed(e, e, e, Handle{4101, true, 17}, Policy{Signal: 15}); err != nil {
				t.Fatal(err)
			}
		}},
		vector{"watchdogNeverKILL", func(t *testing.T) {
			e := originalTuple()
			if SignalAllowed(e, e, e, Handle{4101, true, 17}, Policy{Watchdog: true, Signal: 9}) == nil {
				t.Fatal("watchdog escalated")
			}
		}},
		vector{"late0StillFAILActualReceiptFirst", func(t *testing.T) {
			w := WaitResult{Observed: true, Exited: true, ExitCode: 0}
			if _, e := JoinDisposition(w, false, true, false, true); e == nil {
				t.Fatal("metadata before durable actualWait")
			}
			s, e := JoinDisposition(w, true, true, false, true)
			if e != nil || s != "FAIL_WATCHDOG_WITH_ACTUAL_OUTCOME" {
				t.Fatal(s, e)
			}
		}},
		vector{"explicitReviewedCrash", func(t *testing.T) {
			e := originalTuple()
			p := Policy{CrashRequested: true, Test: "TestCompletionNativeBulkReadbackPauseRestartNoCopies", Signal: 9}
			if err := SignalAllowed(e, e, e, Handle{4101, true, 17}, p); err != nil {
				t.Fatal(err)
			}
			s, err := JoinDisposition(WaitResult{Observed: true, Signaled: true, Signal: 9, RawStatus: 9}, true, false, true, true)
			if err != nil || s != "INTENTIONAL_CRASH_JOINED" {
				t.Fatal(s, err)
			}
		}},
		vector{"unreviewedCrashRefused", func(t *testing.T) {
			e := originalTuple()
			if SignalAllowed(e, e, e, Handle{4101, true, 17}, Policy{CrashRequested: true, Test: "Unreviewed", Signal: 9}) == nil {
				t.Fatal("unreviewed crash admitted")
			}
		}},
	)
	if len(cases) != 31 {
		t.Fatal("table must contain31 cases", len(cases))
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func statText() string {
	return "4101 (daemon ) odd comm) S 4001 " + strings.Repeat("0 ", 17) + "12345 0\n"
}
func statusText() string {
	return "Name:\tpluto\nUid:\t10001 10001 10001 10001\nGid:\t10001 10001 10001 10001\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"
}

func TestPureProcParsers(t *testing.T) {
	b, err := ParseStat([]byte(statText()))
	if err != nil || b.PID != 4101 || b.PPID != 4001 || b.Ticks != 12345 {
		t.Fatal(b, err)
	}
	for _, raw := range []string{"4101 (x) S 4001 0\n", strings.Replace(statText(), "4101", "+4101", 1), strings.Repeat("x", MaxStat+1)} {
		if _, err := ParseStat([]byte(raw)); err == nil {
			t.Fatal("bad stat accepted")
		}
	}
	args, err := ParseCmdline([]byte("/fixture/pluto\x00daemon\x00"))
	if err != nil || !reflect.DeepEqual(args, []string{"/fixture/pluto", "daemon"}) {
		t.Fatal(args, err)
	}
	for _, raw := range []string{"/fixture/pluto", "x\x00\x00", strings.Repeat("x", MaxCmdline) + "\x00"} {
		if _, err := ParseCmdline([]byte(raw)); err == nil {
			t.Fatal("bad cmdline accepted")
		}
	}
	p, err := ParseStatus([]byte(statusText()))
	if err != nil || p.NNP != 1 || p.Seccomp != 2 || len(p.Groups) != 0 || p.UID[3] != 10001 {
		t.Fatal(p, err)
	}
	for _, raw := range []string{strings.Replace(statusText(), "CapBnd:\t0000000000000000\n", "", 1), statusText() + "CapEff:\t0000000000000000\n", strings.Replace(statusText(), "Groups:\t\n", "Groups:\t10001 10001\n", 1), strings.Replace(statusText(), "CapInh:\t0000000000000000", "CapInh:\t+000000000000000", 1)} {
		if _, err := ParseStatus([]byte(raw)); err == nil {
			t.Fatal("bad status accepted")
		}
	}
	pid, err := ParsePIDFDTarget([]byte("pos:\t0\nPid:\t4101\nNSpid:\t4101\n"))
	if err != nil || pid != 4101 {
		t.Fatal(pid, err)
	}
	for _, raw := range []string{"Pid:\t-1\n", "Pid:\t4101\nPid:\t4101\n", "NSpid:\t4101\n"} {
		if _, err := ParsePIDFDTarget([]byte(raw)); err == nil {
			t.Fatal("dead/ambiguous pidfd accepted")
		}
	}
}

func TestRootManifestAndReadonlyInputs(t *testing.T) {
	raw := []byte(`{"schema_version":1,"status":"PASS_UNSIGNED_LOCAL_TRUST_COMPOSITION_ONLY","version":"0.1.5","compiler":"go1.26.10","runtime_binaries":[{"architecture":"linux-amd64","path":"raw/pluto-production-trust-artifacts-minimal-a01/pluto-linux-amd64","bytes":4,"sha256":"` + strings.Repeat("a", 64) + `"}]}`)
	digest := sha256.Sum256(raw)
	pin := hex.EncodeToString(digest[:])
	a, err := AdmitManifest(raw, pin)
	if err != nil || a.Bytes != 4 {
		t.Fatal(a, err)
	}
	if _, err := AdmitManifest(append(raw, ' '), pin); err == nil {
		t.Fatal("selfselected modified manifest")
	}
	if _, err := AdmitManifest(raw, strings.Repeat("b", 64)); err == nil {
		t.Fatal("wrong Root pin")
	}
	e, f, n := validFile()
	if err := CheckArtifact(e, f, f, n, n); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*FileView, *Namespace){func(f *FileView, n *Namespace) { f.Symlink = true }, func(f *FileView, n *Namespace) { f.Mode = 0755 }, func(f *FileView, n *Namespace) { f.UID = 10001 }, func(f *FileView, n *Namespace) { n.Mode = 0777 }, func(f *FileView, n *Namespace) { f.Path = "/tmp/foreign.cli" }} {
		badFile, badNS := f, n
		mutate(&badFile, &badNS)
		if CheckArtifact(e, badFile, badFile, badNS, badNS) == nil {
			t.Fatal("mutable/unowned executable admitted")
		}
	}
	changed := f
	changed.Inode++
	if CheckArtifact(e, f, changed, n, n) == nil {
		t.Fatal("inode TOCTOU")
	}
	changedNS := n
	changedNS.Inode++
	if CheckArtifact(e, f, f, n, changedNS) == nil {
		t.Fatal("namespace TOCTOU")
	}
}
