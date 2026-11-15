package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func seedDisposedArtifacts(t *testing.T, a *Artifacts, count int) {
	t.Helper()
	if err := a.store.transaction(testContext, func(tx *sql.Tx) error {
		stmt, e := tx.Prepare("INSERT INTO local_artifacts(artifact_id,filename,phase,expected_bytes) VALUES(?,?,'GONE',0)")
		if e != nil {
			return e
		}
		defer stmt.Close()
		for i := 0; i < count; i++ {
			id := remoteVersion(i + 10000)
			if _, e = stmt.Exec(id, id+".snapshot"); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestCapturedRegistryPruneRollbackAndUnknownPreservation(t *testing.T) {
	_, a, _ := artifactFixture(t)
	seedDisposedArtifacts(t, a, 2)
	ctx, cancel := context.WithCancel(testContext)
	a.crashPoint = func(p string) {
		if p == "before-prune-commit" {
			cancel()
		}
	}
	if n, e := a.PruneDisposed(ctx, 2); !errors.Is(e, context.Canceled) || n != 0 {
		t.Fatal(n, e)
	}
	a.crashPoint = nil
	var count int
	if e := a.store.db.QueryRow("SELECT COUNT(*) FROM local_artifacts").Scan(&count); e != nil || count != 2 {
		t.Fatal("prune prefix escaped rollback", count, e)
	}
	id := remoteVersion(10000)
	filename := filepath.Join(a.Directory(), id+".snapshot")
	if e := os.WriteFile(filename, []byte("unknown"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := a.PruneDisposed(testContext, 2); e == nil {
		t.Fatal("unknown physical bytes evicted")
	}
	raw, e := os.ReadFile(filename)
	if e != nil || string(raw) != "unknown" {
		t.Fatal(raw, e)
	}
}
func TestCapturedRegistryPruneRefusesPendingAndLive(t *testing.T) {
	s, a, _, v, op := boundArtifactFixture(t)
	if e := a.BindOperation(testContext, op.SnapshotID, op.OperationID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("UPDATE local_artifacts SET phase='GONE' WHERE artifact_id=?", op.SnapshotID); e != nil {
		t.Fatal(e)
	}
	if _, e := a.PruneDisposed(testContext, 1); !errors.Is(e, ErrArtifactInUse) {
		t.Fatal("live row evicted", e)
	}
	if e := v.Retain(); e != nil {
		t.Fatal(e)
	}
	// Exact fixture corruption simulates an invalid disposed marker, not cleanup.
	if e := os.Remove(filepath.Join(a.Directory(), op.SnapshotID+".snapshot")); e != nil {
		t.Fatal(e)
	}
	info, _ := a.directory.Stat()
	a.directoryGeneration = statCTime(info)
	if _, e := a.PruneDisposed(testContext, 1); !errors.Is(e, ErrArtifactRetained) {
		t.Fatal("pending intent evicted", e)
	}
	recovered, e := a.RecoveryOperation(testContext, op.SnapshotID)
	if e != nil || recovered.OperationID != op.OperationID {
		t.Fatal(recovered, e)
	}
}
func TestCapturedRegistryPruneExactIndexAndBound(t *testing.T) {
	_, a, _ := artifactFixture(t)
	seedDisposedArtifacts(t, a, 500)
	if _, e := a.PruneDisposed(testContext, MaxSourcePage+1); !errors.Is(e, ErrSourceQuota) {
		t.Fatal(e)
	}
	rows, e := a.store.db.Query("EXPLAIN QUERY PLAN SELECT artifact_id FROM local_artifacts WHERE phase='GONE' ORDER BY artifact_id LIMIT 128")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	seen := false
	for rows.Next() {
		var i, j, k int
		var detail string
		if e = rows.Scan(&i, &j, &k, &detail); e != nil {
			t.Fatal(e)
		}
		if detail == "SCAN local_artifacts USING COVERING INDEX gone_artifacts" || detail == "SCAN local_artifacts USING INDEX gone_artifacts" {
			seen = true
		}
		t.Log(detail)
	}
	if !seen {
		t.Fatal("GONE partial index unused")
	}
	n, e := a.PruneDisposed(testContext, MaxSourcePage)
	if e != nil || n != 128 {
		t.Fatal(n, e)
	}
}
func TestCapturedRegistryDisposedHistoryCapRegression(t *testing.T) {
	_, a, _ := artifactFixture(t)
	seedDisposedArtifacts(t, a, DefaultArtifactLimits().Records)
	removed, err := a.PruneDisposed(testContext, MaxSourcePage)
	if err != nil || removed != MaxSourcePage {
		t.Fatal(removed, err)
	}
	reservation, err := a.Reserve(testContext, 0)
	if err != nil {
		t.Fatal("disposed history blocks subsequent admitted capture", err)
	}
	if err = reservation.Dispose(testContext); err != nil {
		t.Fatal(err)
	}
}
