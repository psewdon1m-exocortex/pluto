package nativefixture

import (
	"strings"
	"testing"
)

func TestStrictRPCAndReplayScope(t *testing.T) {
	var r Request
	for _, raw := range []string{`{"Schema":"nativefixture.rpc.v2","Schema":"other"}`, `{"Scope":"x","unexpected":1}`, `{} {}`, `{"Sequence":"1"}`} {
		if strictJSON([]byte(raw), &r) == nil {
			t.Fatal("ambiguous/malformed request accepted", raw)
		}
	}
	m := Manifest{Scope: "fresh", Nonce: strings.Repeat("a", 32)}
	good := Request{Schema: "nativefixture.rpc.v2", Scope: m.Scope, Nonce: m.Nonce, Sequence: 2}
	var l ReplayLedger
	if e := l.Admit(m, good, 41, 41); e != nil {
		t.Fatal(e)
	}
	if e := l.Admit(m, good, 41, 41); e == nil {
		t.Fatal("replay accepted")
	}
	// Distinct concurrent arrivals may reorder, never sharing signal authority.
	good.Sequence = 1
	if e := l.Admit(m, good, 41, 41); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"nonce", "sender", "scope", "zero", "overflow"} {
		x := good
		x.Sequence = 3
		pid := 41
		switch bad {
		case "nonce":
			x.Nonce = "wrong"
		case "scope":
			x.Scope = "old"
		case "sender":
			pid = 42
		case "zero":
			x.Sequence = 0
		case "overflow":
			x.Sequence = MaxRPC + 1
		}
		if (&ReplayLedger{}).Admit(m, x, pid, 41) == nil {
			t.Fatal("bad request admitted", bad)
		}
	}
}
func TestCredentialPlanClosesAllInjectedRightsWithoutUsingThem(t *testing.T) {
	good := CredentialRecord{Kind: "credentials", PID: 41, UID: 10001, GID: 10001}
	if p := PlanCredentials([]CredentialRecord{good}); p.Error != nil || p.PID != 41 {
		t.Fatal(p)
	}
	for _, records := range [][]CredentialRecord{{}, {good, good}, {{Kind: "credentials", PID: 41, UID: 0, GID: 0}}, {{Kind: "invalid"}, good}, {good, {Kind: "rights", FDs: []int{17}}, {Kind: "rights", FDs: []int{18, 17}}}} {
		p := PlanCredentials(records)
		if p.Error == nil {
			t.Fatal("bad control accepted", p)
		}
		if len(records) == 3 && (len(p.CloseFDs) != 2 || p.CloseFDs[0] != 17 || p.CloseFDs[1] != 18) {
			t.Fatal("later injected right leaked", p)
		}
	}
	// Numbers above are virtual data; tests call no Close/syscall/process API.
}
func TestFixedCommandsCannotSelectForeignPrograms(t *testing.T) {
	for _, action := range []string{"sh", "systemctl", "update", "/bin/cp", "adopt;anything"} {
		if _, e := commandArgs(action, "/own/config", "/own/state", "/own/socket", "/own/profile", strings.Repeat("a", 64)); e == nil {
			t.Fatal(action)
		}
	}
	if _, e := commandArgs("adopt", "/own/config", "/own/state", "/own/socket", "/own/profile", "bad"); e == nil {
		t.Fatal("malformed digest")
	}
	a, e := commandArgs("copy-indexed", "/own/config", "/own/state", "/own/socket", "", "")
	if e != nil || len(a) != 5 || a[0] != "copy-indexed" {
		t.Fatal(a, e)
	}
	for _, p := range []string{"/own/../foreign", "/own//file", "/own\\foreign", "relative", "/own/file\n"} {
		if beneath("/own", p) {
			t.Fatal("path escape", p)
		}
	}
}
