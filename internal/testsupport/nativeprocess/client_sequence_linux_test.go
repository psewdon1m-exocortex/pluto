//go:build linux

package nativefixture

import (
	"strings"
	"testing"
)

// Different fixtures recreate ClientFromEnvironment in the same Go actor.
// Owner's replay ledger must accept both clients' fresh messages, then refuse replay.
func TestSeparateClientsShareActualCallerReplayNamespace(t *testing.T) {
	a, b := new(Client), new(Client)
	m := Manifest{Scope: "same-go-actor", Nonce: strings.Repeat("a", 32)}
	var ledger ReplayLedger
	for n := 0; n < 32; n++ {
		for _, client := range []*Client{a, b} {
			r := Request{Schema: "nativefixture.rpc.v2", Scope: m.Scope, Nonce: m.Nonce, Sequence: client.nextRequestSequence()}
			if e := ledger.Admit(m, r, 41, 41); e != nil {
				t.Fatal("new fixture client reused caller sequence", e)
			}
			if e := ledger.Admit(m, r, 41, 41); e == nil {
				t.Fatal("actual replay admitted")
			}
		}
	}
}
