package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func createCapturedOperationFixture(t *testing.T) (*RemoteImport, SourceWitness, *VerifiedSnapshot, string, RemoteCandidate, Operation) {
	t.Helper()
	r, w, v, entry, c := capturedRemoteFixture(t)
	l, _ := readJSON[Observation](testContext, r.store.db, "SELECT descriptor_json FROM local_entries WHERE root_id='root' AND entry_id=?", entry)
	chain, _, err := func() ([]Observation, string, error) {
		tx, e := r.store.db.BeginTx(testContext, nil)
		if e != nil {
			return nil, "", e
		}
		defer tx.Rollback()
		return localPath(testContext, tx, l)
	}()
	if err != nil {
		t.Fatal(err)
	}
	// Keep actual ancestors, remove only target from candidate to prove CREATE.
	_, err = r.store.db.Exec("DELETE FROM remote_entries WHERE root_id='root' AND generation=? AND json_extract(descriptor_json,'$.Kind')='file'", c.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) < 2 {
		t.Fatal("fixture requires parent mapping")
	}
	d, err := r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(c), remoteNow)
	if err != nil || d.Kind != "CREATE" {
		t.Fatal(d, err)
	}
	id, err := NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	op, err := r.PlanCaptured(testContext, w, v, fixtureRemoteAuthority(c), d, id, remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	return r, w, v, entry, c, op
}
func publicationFixture(op Operation) CapturedPublication {
	b := op.Captured.Witness.Remote.Binding
	parent := b.RootID
	if len(op.Captured.Parents) > 0 {
		parent = op.Captured.Parents[len(op.Captured.Parents)-1].Remote.NodeID
	}
	e := RemoteEntry{RootID: op.RootID, NodeID: "published-node", ParentID: parent, Name: op.Name, Kind: "file", Epoch: b.ServerEpoch, Version: remoteVersion(10), SHA256: op.SHA256, Presence: "PRESENT", SizeBytes: op.SizeBytes, LastSeq: 1, Availability: "AVAILABLE", ContentVersionID: remoteVersion(11), RemoteBinding: &b}
	return CapturedPublication{Receipt: Receipt{OperationID: op.OperationID, RootID: op.RootID, EntryID: op.EntryID, NodeID: e.NodeID, Epoch: e.Epoch, Version: e.Version, SHA256: op.SHA256, SealedFingerprint: op.SealedFingerprint, LocalGeneration: op.LocalGeneration, SizeBytes: op.SizeBytes, Seq: 1, Published: true, ContentVerified: true}, Binding: b, Description: e, FirstSeq: 1}
}
func TestCapturedOperationProjectionRecoveryIndependentGenerations(t *testing.T) {
	r, w, v, entry, c, op := createCapturedOperationFixture(t)
	if entry == op.Captured.Evidence.Destination || op.LocalGeneration == op.Captured.Evidence.EntryGeneration {
		t.Fatal("fixture must exercise independent identity/generation")
	}
	a := r.store.artifacts
	if err := a.BindOperation(testContext, op.SnapshotID, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := r.SubmittedCaptured(testContext, w, v, fixtureRemoteAuthority(c), op.OperationID, remoteNow); err != nil {
		t.Fatal(err)
	}
	if err := v.Retain(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.sources.RecordSourceGap(testContext, w, "fixture gap"); err != nil {
		t.Fatal(err)
	}
	recovered, err := a.RecoveryOperation(testContext, op.SnapshotID)
	if err != nil || recovered.OperationID != op.OperationID || recovered.IntentFingerprint != op.IntentFingerprint || recovered.Stage != "SUBMITTED" {
		t.Fatal(recovered, err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	if err = a.BindOperation(testContext, op.SnapshotID, op.OperationID); err != nil {
		t.Fatal("historical bind rejected after gap", err)
	}
	pub := publicationFixture(op)
	if err = r.store.Ack(testContext, pub.Receipt); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal("legacy receipt bypass", err)
	}
	if err = r.AckCaptured(testContext, pub); err != nil {
		t.Fatal(err)
	}
	state, err := r.store.Entry(testContext, "root", entry)
	if err != nil || state.Dirty == nil || state.Base == nil || state.Base.OperationID != op.OperationID || state.Base.CaptureProof == nil {
		t.Fatal(state, err)
	}
	if err = r.AckCaptured(testContext, pub); err != nil {
		t.Fatal("exact replay", err)
	}
	pub.Description.ContentVersionID = remoteVersion(99)
	if err = r.AckCaptured(testContext, pub); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("altered historical result", err)
	}
}
func TestCapturedOperationNoSendAfterLocalRemoteTrustOrExpiry(t *testing.T) {
	for _, kind := range []string{"local", "remote", "trust", "expired"} {
		t.Run(kind, func(t *testing.T) {
			r, w, v, entry, c, op := createCapturedOperationFixture(t)
			a := fixtureRemoteAuthority(c)
			now := remoteNow
			switch kind {
			case "local":
				_, _ = r.store.db.Exec("UPDATE local_entries SET generation=generation+1,descriptor_json=json_set(descriptor_json,'$.Generation',generation+1) WHERE root_id='root' AND entry_id=?", entry)
			case "remote":
				if err := r.InvalidateRemote(testContext, c.RemoteWitness); err != nil {
					t.Fatal(err)
				}
			case "trust":
				if err := r.store.InvalidateTrust(testContext, "root", c.TrustGeneration); err != nil {
					t.Fatal(err)
				}
			case "expired":
				now = now.Add(31 * time.Second)
			}
			if err := r.SubmittedCaptured(testContext, w, v, a, op.OperationID, now); !errors.Is(err, ErrStaleGeneration) {
				t.Fatal("stale Send allowed", err)
			}
			stored, _ := r.store.Operation(testContext, op.OperationID)
			if stored.Stage != "SEALED" {
				t.Fatal(stored)
			}
			v.Retain()
		})
	}
}
func TestCapturedOperationAtomicPlanRollbackAndProofTamper(t *testing.T) {
	r, w, v, entry, c := capturedRemoteFixture(t)
	_, _ = r.store.db.Exec("DELETE FROM remote_entries WHERE root_id='root' AND generation=? AND json_extract(descriptor_json,'$.Kind')='file'", c.Generation)
	d, err := r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(c), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := NewOperationID()
	r.testPoint = func(p string) error {
		if p == "capture.before_plan" {
			return context.Canceled
		}
		return nil
	}
	if _, err = r.PlanCaptured(testContext, w, v, fixtureRemoteAuthority(c), d, id, remoteNow); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = r.store.Operation(testContext, id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("operation prefix escaped", err)
	}
	r.testPoint = nil
	op, err := r.PlanCaptured(testContext, w, v, fixtureRemoteAuthority(c), d, id, remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	bad := op.Intent
	copyProof := *op.Captured
	copyProof.Evidence.EntryGeneration++
	bad.Captured = &copyProof
	if err = r.store.Plan(testContext, bad); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal("public proof mint", err)
	}
	if err = r.store.artifacts.BindOperation(testContext, op.SnapshotID, id); err != nil {
		t.Fatal(err)
	}
	if err = v.Close(); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal("pending snapshot removed", err)
	}
	v.Retain()
}
