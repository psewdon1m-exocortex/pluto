package syncstate

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"pluto/internal/syncproto"
)

func TestCapturedExecutorAdoptParentsAtomicFreshRepeat(t *testing.T) {
	r, w, v, entry, c := capturedRemoteFixture(t)
	evidence := v.Evidence()
	s := &fixtureCapturedSession{r: r, results: make(map[string]CapturedPublication), published: make(chan struct{})}
	first, err := r.ExecuteCaptured(testContext, w, "root", entry, v, s, remoteNow)
	if err != nil || first.Kind != "ADOPT_EQUAL" || s.writes.Load() != 0 {
		t.Fatal(first, err)
	}
	scanSource(t, r.sources, w, "fresh-adoption-cycle", nil)
	source, err := r.sources.SourceEntry(testContext, w.SetID, evidence.Destination)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := CaptureGuarded(testContext, w, source, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = r.sources.RecordVerifiedSnapshot(testContext, w, fresh); err != nil {
		t.Fatal(err)
	}
	if err = r.ProjectCapturedEntry(testContext, w, "root", entry, fresh); err != nil {
		t.Fatal(err)
	}
	d, err := r.DecideCaptured(testContext, w, "root", entry, fresh, fixtureRemoteAuthority(c), remoteNow)
	if err != nil || d.Kind != "NOOP_CAPTURED" {
		t.Fatal("qualified first adoption lost its parent agreement for repeat", d, err)
	}
}

func TestCapturedRegistryRefusesTamperedHistoricalDescription(t *testing.T) {
	r, w, v, _, c, op := createCapturedOperationFixture(t)
	if err := r.store.artifacts.BindOperation(testContext, op.SnapshotID, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := r.SubmittedCaptured(testContext, w, v, fixtureRemoteAuthority(c), op.OperationID, remoteNow); err != nil {
		t.Fatal(err)
	}
	if err := v.Retain(); err != nil {
		t.Fatal(err)
	}
	if err := r.AckCaptured(testContext, publicationFixture(op)); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := r.store.db.QueryRow("SELECT receipt_json FROM operations WHERE operation_id=?", op.OperationID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rc Receipt
	if err := json.Unmarshal([]byte(raw), &rc); err != nil {
		t.Fatal(err)
	}
	rc.CapturedResult.Description.ParentID = "replaced-parent"
	if _, err := r.store.db.Exec("UPDATE operations SET receipt_json=? WHERE operation_id=?", string(mustJSON(rc)), op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := r.store.artifacts.Dispose(testContext, op.SnapshotID); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("unverified historical result erased retained bytes", err)
	}
	if _, err := r.store.db.Exec("UPDATE operations SET receipt_json=? WHERE operation_id=?", raw, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := r.store.artifacts.Dispose(testContext, op.SnapshotID); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedAckRootTopologyChangeRetainsDirty(t *testing.T) {
	r, w, v, _, c, op := createCapturedOperationFixture(t)
	if err := r.store.artifacts.BindOperation(testContext, op.SnapshotID, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := r.SubmittedCaptured(testContext, w, v, fixtureRemoteAuthority(c), op.OperationID, remoteNow); err != nil {
		t.Fatal(err)
	}
	pub := publicationFixture(op)
	file := descriptorFromRemote(pub.Description)
	anchor := descriptorFromRemote(op.Captured.RemoteAnchor)
	anchor.Name = "root-renamed"
	anchor.Version = remoteVersion(88)
	if _, err := r.ImportFeed(testContext, c.RemoteWitness, wireFeed(c.RemoteWitness, []syncproto.FeedItem{{Descriptor: file, Seq: "1", Kind: "upsert", OperationID: op.OperationID}, {Descriptor: anchor, Seq: "2", Kind: "upsert", OperationID: "root-rename"}}, "root-renamed-cut")); err != nil {
		t.Fatal(err)
	}
	if err := r.AckCaptured(testContext, pub); err != nil {
		t.Fatal(err)
	}
	state, err := r.store.Entry(testContext, op.RootID, op.EntryID)
	if err != nil || state.Base == nil || state.Dirty == nil {
		t.Fatal("root namespace changed while historical ACK cleared dirty", state, err)
	}
	v.Close()
}

func TestCapturedOperationOrderedTopologyAndAggregateSibling(t *testing.T) {
	r, w, v, entry, c, op := createCapturedOperationFixture(t)
	topology, err := op.ParentTopology()
	if err != nil || len(topology) != len(op.Captured.Parents)+1 {
		t.Fatal(topology, err)
	}
	if topology[0].NodeID != op.Captured.Parents[len(op.Captured.Parents)-1].Remote.NodeID || topology[len(topology)-1].NodeID != c.Binding.RootID || topology[len(topology)-1].ParentID != "" {
		t.Fatal("not ordered exact parent→root", topology)
	}
	bad := op
	proof := *op.Captured
	proof.Parents = append([]CapturedParentBinding(nil), op.Captured.Parents...)
	proof.Parents[0].Remote.ParentID = "other-parent"
	bad.Captured = &proof
	if _, err = bad.ParentTopology(); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("broken chain accepted", err)
	}
	// Discard an unsent immutable fixture intent, without inventing cancellation.
	// This direct fixture-only SQL permits testing a new advisory decision; the
	// product never replaces/cancels an original operation this way.
	if _, err = r.store.db.Exec("DELETE FROM operations WHERE operation_id=?", op.OperationID); err != nil {
		t.Fatal(err)
	}
	seedCapturedParentBases(t, r, entry, c)
	parent := op.Captured.Parents[len(op.Captured.Parents)-1].Remote
	desc := descriptorFromRemote(parent)
	desc.Version = remoteVersion(77)
	desc.SizeBytes = "19"
	newCut, err := r.ImportFeed(testContext, c.RemoteWitness, wireFeed(c.RemoteWitness, []syncproto.FeedItem{{Descriptor: desc, Seq: "1", Kind: "upsert", OperationID: "sibling-aggregate"}}, "aggregate-cut"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(newCut), remoteNow)
	if err != nil || d.Kind != "CREATE" {
		t.Fatal("unrelated sibling aggregate blocked namespace", d, err)
	}
	// An actual rename no longer identifies the intended parent namespace.
	desc.Name = "renamed"
	desc.Version = remoteVersion(78)
	newCut, err = r.ImportFeed(testContext, newCut.RemoteWitness, wireFeed(newCut.RemoteWitness, []syncproto.FeedItem{{Descriptor: desc, Seq: "2", Kind: "upsert", OperationID: "parent-rename"}}, "rename-cut"))
	if err != nil {
		t.Fatal(err)
	}
	d, err = r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(newCut), remoteNow)
	if err != nil || d.Kind == "CREATE" || d.Kind == "OVERWRITE" || d.Kind == "ADOPT_EQUAL" || d.Kind == "NOOP_CAPTURED" {
		t.Fatal("ancestor rename granted effect", d, err)
	}
}

func TestCapturedOperationAckRollbackPreservesOriginal(t *testing.T) {
	r, w, v, _, c, op := createCapturedOperationFixture(t)
	if err := r.store.artifacts.BindOperation(testContext, op.SnapshotID, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := r.SubmittedCaptured(testContext, w, v, fixtureRemoteAuthority(c), op.OperationID, remoteNow); err != nil {
		t.Fatal(err)
	}
	r.testPoint = func(p string) error {
		if p == "capture.before_ack" {
			return ErrStaleGeneration
		}
		return nil
	}
	if err := r.AckCaptured(testContext, publicationFixture(op)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	current, err := r.store.Operation(testContext, op.OperationID)
	if err != nil || current.Stage != "SUBMITTED" || current.IntentFingerprint != op.IntentFingerprint {
		t.Fatal(current, err)
	}
	if _, err = readJSON[Baseline](testContext, r.store.db, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("failed ACK escaped", err)
	}
	r.testPoint = nil
	v.Retain()
}
