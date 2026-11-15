package syncstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func compactedCapturedOriginal(t *testing.T) (*smallBatchDispatcher, Operation) {
	t.Helper()
	d, _, p, _ := dispatchFixture(t, 2)
	if err := d.dispatch(testContext, p); err != nil {
		t.Fatal(err)
	}
	if n, err := d.session.r.store.artifacts.CompactGone(testContext, 128); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	op, err := d.session.r.store.Operation(testContext, p.entries[0].original.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	return d, op
}
func TestCompactedOriginalProofIsReadOnlyAndRequiresExactIdentity(t *testing.T) {
	d, op := compactedCapturedOriginal(t)
	a := d.session.r.store.artifacts
	before, err := d.session.r.store.Operation(testContext, op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = a.ConfirmDisposedOriginal(testContext, op); err != nil {
			t.Fatal(err)
		}
	}
	after, err := d.session.r.store.Operation(testContext, op.OperationID)
	if err != nil || fingerprint(before) != fingerprint(after) {
		t.Fatal("immutable original changed", err)
	}
	if err = a.Dispose(testContext, op.SnapshotID); err == nil {
		t.Fatal("generic missing-owner Dispose became permissive")
	}
	for _, field := range []string{"root", "entry", "snapshot", "hash", "intent"} {
		t.Run(field, func(t *testing.T) {
			changed := op
			switch field {
			case "root":
				changed.RootID = "foreign"
			case "entry":
				changed.EntryID = "foreign"
			case "snapshot":
				changed.SnapshotID = "00000000-0000-4000-a000-000000000000"
			case "hash":
				changed.SHA256 = hashBytes([]byte("foreign"))
			case "intent":
				changed.Name = "foreign"
			}
			if err := a.ConfirmDisposedOriginal(testContext, changed); err == nil {
				t.Fatal("changed original accepted")
			}
		})
	}
}
func TestCompactedOriginalProofRejectsMissingOrInvalidAcknowledgement(t *testing.T) {
	for _, change := range []string{"pending", "receipt", "unknown"} {
		t.Run(change, func(t *testing.T) {
			d, op := compactedCapturedOriginal(t)
			switch change {
			case "pending":
				if _, err := d.session.r.store.db.Exec("UPDATE operations SET stage='SUBMITTED' WHERE operation_id=?", op.OperationID); err != nil {
					t.Fatal(err)
				}
			case "receipt":
				if _, err := d.session.r.store.db.Exec("UPDATE operations SET receipt_json='{}' WHERE operation_id=?", op.OperationID); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				op.OperationID = "unknown-original"
			}
			if err := d.session.r.store.artifacts.ConfirmDisposedOriginal(testContext, op); err == nil {
				t.Fatal("missing/invalid ACK accepted")
			}
		})
	}
}
func TestCompactedOriginalProofPreservesUnexpectedNativeFile(t *testing.T) {
	d, op := compactedCapturedOriginal(t)
	a := d.session.r.store.artifacts
	name := filepath.Join(a.Directory(), op.SnapshotID+".snapshot")
	payload := []byte("unexpected replacement must remain")
	if err := os.WriteFile(name, payload, 0400); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfirmDisposedOriginal(testContext, op); err == nil {
		t.Fatal("unexpected native file accepted")
	}
	raw, err := os.ReadFile(name)
	if err != nil || string(raw) != string(payload) {
		t.Fatal("unexpected bytes deleted", err)
	}
}
func TestCompactedOriginalProofRejectsUncompactedRecord(t *testing.T) {
	d, _, p, _ := dispatchFixture(t, 2)
	op := p.entries[0].original
	a := d.session.r.store.artifacts
	if err := a.ConfirmDisposedOriginal(testContext, op); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal("present pending artifact accepted", err)
	}
	if _, err := a.Record(testContext, op.SnapshotID); err != nil {
		t.Fatal("pending original removed", err)
	}
}
