package syncstate

import (
	"errors"
	"testing"
)

// Exact retained schema4 intent bytes; fixture insertion is explicitly not a
// product Plan/admission shortcut. Schema5 may recover these IDs but not Send.
func fixtureLegacyPending(t *testing.T, s *Store, intent Intent, stage, sha, snapshot string) {
	t.Helper()
	if intent.Dependencies == nil {
		intent.Dependencies = []string{}
	}
	sealed := ""
	if stage != "PLANNED" {
		sealed = fingerprint(struct{ IntentFingerprint, SHA256 string }{fingerprint(intent), sha})
	} else {
		sha = ""
		snapshot = ""
	}
	if _, err := s.db.Exec("INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage,sha256,snapshot_id,sealed_fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?)", intent.OperationID, intent.RootID, intent.EntryID, intent.LocalGeneration, intent.Kind, string(mustJSON(intent)), fingerprint(intent), stage, sha, snapshot, sealed); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteModuleFiveLegacyOperationAdmissionFailClosed(t *testing.T) {
	r, w, v, entry, _ := capturedRemoteFixture(t)
	intent := fixtureIntent(t, r.store, "new", entry)
	if err := r.store.Plan(testContext, intent); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal("legacy Plan bypassed qualified authority", err)
	}
	fixtureLegacyPending(t, r.store, intent, "SUBMITTED", v.Evidence().SHA256, v.Evidence().SnapshotID)
	if err := r.store.Plan(testContext, intent); err != nil {
		t.Fatal("immutable retry lost original ID", err)
	}
	if err := r.store.Submitted(testContext, intent.OperationID); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal("legacy Submitted bypassed server status/fence", err)
	}
	op, _ := r.store.Operation(testContext, intent.OperationID)
	receipt := Receipt{OperationID: op.OperationID, RootID: op.RootID, EntryID: op.EntryID, NodeID: "old-published-node", Epoch: "old-epoch", Version: "old-version", SHA256: op.SHA256, SealedFingerprint: op.SealedFingerprint, LocalGeneration: op.LocalGeneration, SizeBytes: op.SizeBytes, Seq: 1, Published: true, ContentVerified: true}
	if err := r.store.Ack(testContext, receipt); err != nil {
		t.Fatal("historical receipt lost", err)
	}
	state, err := r.store.Entry(testContext, "root", entry)
	if err != nil || state.Base == nil || state.Base.OperationID != intent.OperationID || state.Base.RemoteBinding != nil || state.Dirty == nil {
		t.Fatal("legacy ACK claimed fresh authority/cleared dirty", state, err)
	}
	if d, err := r.DecideCaptured(testContext, w, "root", entry, v, nil, remoteNow); err != nil || d.Kind != "RECONCILE" {
		t.Fatal(d, err)
	}
}
