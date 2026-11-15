package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type registryFixtureLimiter struct {
	a      *Artifacts
	r      *ArtifactReservation
	reader *testCaptureLimiter
}

func (b *registryFixtureLimiter) ReserveCapture(ctx context.Context, dir string, size int64) (func(), error) {
	r, err := b.a.Reserve(ctx, size)
	if err != nil {
		return nil, err
	}
	b.r = r
	return func() { r.Dispose(context.Background()) }, nil
}
func (b *registryFixtureLimiter) RegisterCaptureArtifact(string, int64) error { return nil }
func (b *registryFixtureLimiter) AcquireCaptureReader(ctx context.Context) (func(), error) {
	return b.reader.AcquireCaptureReader(ctx)
}
func (b *registryFixtureLimiter) CreateCaptureArtifact(ctx context.Context, dir string) (*os.File, string, error) {
	f, err := b.r.Create(ctx)
	return f, b.r.ID(), err
}
func (b *registryFixtureLimiter) SealCaptureArtifact(ctx context.Context, v *VerifiedSnapshot) error {
	return b.r.SealSnapshot(ctx, v)
}
func (b *registryFixtureLimiter) DisposeCaptureArtifact(ctx context.Context, _ string) error {
	return b.r.Dispose(ctx)
}
func (b *registryFixtureLimiter) RetainCaptureArtifact(ctx context.Context, _ string) error {
	return b.r.Relinquish()
}

func boundArtifactFixture(t *testing.T) (*Store, *Artifacts, *registryFixtureLimiter, *VerifiedSnapshot, Operation) {
	t.Helper()
	path := t.TempDir()
	name := filepath.Join(path, "file")
	if err := os.WriteFile(name, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	s, w, _ := sourceFixture(t, path)
	scanSource(t, s, w, "scan", nil)
	entry, err := s.SourceEntry(testContext, w.SetID, sourceDestination(name))
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding
	binding.SourceIdentity = w.SetID
	if err = s.store.BindRoot(testContext, binding); err != nil {
		t.Fatal(err)
	}
	if err = s.AttachSourceSet(testContext, w.SetID, w.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	a, err := s.store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	limiter := &registryFixtureLimiter{a: a, reader: newTestCaptureLimiter()}
	v, err := CaptureGuarded(testContext, w, entry, a.Directory(), limiter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Retain() })
	observation := fileObservation(entry.Destination, "file")
	observation.FileIdentity = entry.FileIdentity
	observation.SHA256 = v.Evidence().SHA256
	observation.HashGeneration = 1
	capture(t, s.store, observation)
	intent := fixtureIntent(t, s.store, "immutable-original-operation", entry.Destination)
	if err = s.store.Plan(testContext, intent); err != nil {
		t.Fatal(err)
	}
	if err = s.store.Seal(testContext, intent.OperationID, v.Evidence().SHA256, v.Evidence().SnapshotID); err != nil {
		t.Fatal(err)
	}
	op, err := s.store.Operation(testContext, intent.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	return s.store, a, limiter, v, op
}
func TestArtifactExistingImmutableIntentUnknownRetainAndAck(t *testing.T) {
	s, a, limiter, v, op := boundArtifactFixture(t)
	if err := a.BindOperation(testContext, limiter.r.ID(), op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := s.Submitted(testContext, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal("unknown outcome disposed", err)
	}
	if err := v.Retain(); err != nil {
		t.Fatal(err)
	}
	recovered, err := a.RecoveryOperation(testContext, op.SnapshotID)
	if err != nil || recovered.OperationID != op.OperationID || recovered.Stage != "SUBMITTED" {
		t.Fatal(recovered, err)
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&count)
	if count != 1 {
		t.Fatal("new operation guessed", count)
	}
	if err := a.Dispose(testContext, op.SnapshotID); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal(err)
	}
	receipt := Receipt{OperationID: op.OperationID, RootID: op.RootID, EntryID: op.EntryID, LocalGeneration: op.LocalGeneration, NodeID: "node", Epoch: "epoch", Version: "version", SHA256: op.SHA256, SizeBytes: op.SizeBytes, SealedFingerprint: op.SealedFingerprint, Seq: 1, Published: true, ContentVerified: true}
	if err = s.Ack(testContext, receipt); err != nil {
		t.Fatal(err)
	}
	baseBefore, _ := s.Entry(testContext, op.RootID, op.EntryID)
	if err = a.Dispose(testContext, op.SnapshotID); err != nil {
		t.Fatal(err)
	}
	baseAfter, _ := s.Entry(testContext, op.RootID, op.EntryID)
	if baseBefore.Base == nil || baseAfter.Base == nil || *baseBefore.Base != *baseAfter.Base {
		t.Fatal("artifact cleanup rewrote B")
	}
	if n, err := a.CompactGone(testContext, 128); err != nil || n != 1 {
		t.Fatal("completed artifact capacity not reclaimed", n, err)
	}
	kept, err := s.Operation(testContext, op.OperationID)
	if err != nil || kept.OperationID != op.OperationID || kept.Stage != "CLIENT_ACKED" {
		t.Fatal("compaction removed immutable operation/receipt", kept, err)
	}
}
func TestArtifactBindingRejectsWrongEntryGenerationAndSourceGap(t *testing.T) {
	for _, change := range []string{"entry", "generation", "snapshot", "source-gap", "unattached"} {
		t.Run(change, func(t *testing.T) {
			s, a, limiter, v, op := boundArtifactFixture(t)
			defer v.Retain()
			switch change {
			case "entry":
				op.EntryID = "different"
				raw, _ := json.Marshal(op.Intent)
				s.db.Exec("UPDATE operations SET intent_json=? WHERE operation_id=?", string(raw), op.OperationID)
			case "generation":
				op.LocalGeneration++
				raw, _ := json.Marshal(op.Intent)
				s.db.Exec("UPDATE operations SET intent_json=? WHERE operation_id=?", string(raw), op.OperationID)
			case "snapshot":
				s.db.Exec("UPDATE operations SET snapshot_id='different' WHERE operation_id=?", op.OperationID)
			case "source-gap":
				if _, err := a.sources.RecordSourceGap(testContext, v.Evidence().Witness, "fixture observation gap"); err != nil {
					t.Fatal(err)
				}
			case "unattached":
				s.db.Exec("UPDATE source_sets SET attached_root_id=NULL")
			}
			if err := a.BindOperation(testContext, limiter.r.ID(), op.OperationID); err == nil {
				t.Fatal("bad association accepted", change)
			}
			var got sql.NullString
			s.db.QueryRow("SELECT operation_id FROM local_artifacts WHERE artifact_id=?", limiter.r.ID()).Scan(&got)
			if got.Valid {
				t.Fatal("failed bind changed row")
			}
		})
	}
}
func TestArtifactCrashBetweenSealAndBindRetainsExactOperation(t *testing.T) {
	s, a, limiter, v, op := boundArtifactFixture(t)
	// The durable operation references this exact UUID, but FK binding has not
	// committed. No checksum/path guess may treat it as an unused capture.
	if err := s.Submitted(testContext, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if record, err := a.Record(testContext, limiter.r.ID()); err != nil || record.OperationID != "" {
		t.Fatal(record, err)
	}
	if err := v.Close(); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal("unbound pending snapshot deleted", err)
	}
	if err := v.Retain(); err != nil {
		t.Fatal(err)
	}
	report, err := a.Reconcile(testContext, artifactTestReader)
	if err != nil || report.RecoveryOperations != 1 {
		t.Fatal(report, err)
	}
	got, err := a.RecoveryOperation(testContext, op.SnapshotID)
	if err != nil || got.OperationID != op.OperationID || got.Stage != "SUBMITTED" {
		t.Fatal(got, err)
	}
	if err = a.Dispose(testContext, op.SnapshotID); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal(err)
	}
}
func TestArtifactDuplicateSnapshotIntentReferencesRefuseGuess(t *testing.T) {
	s, a, _, v, op := boundArtifactFixture(t)
	defer v.Retain()
	other := fileObservation("other-entry", "other")
	other.FileIdentity = op.FileIdentity
	capture(t, s, other)
	intent := fixtureIntent(t, s, "other-operation", "other-entry")
	if err := s.Plan(testContext, intent); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(testContext, intent.OperationID, op.SHA256, op.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("duplicate refs chose one", err)
	}
	if _, err := a.RecoveryOperation(testContext, op.SnapshotID); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal(err)
	}
}
