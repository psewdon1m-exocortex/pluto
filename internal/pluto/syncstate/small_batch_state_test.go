package syncstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type pendingSmallBatchSession struct{ *IsolatedHTTPSession }

func (s pendingSmallBatchSession) Publish(context.Context, Operation, io.Reader) (CapturedPublication, error) {
	return CapturedPublication{}, ErrArtifactRetained
}
func smallBatchStateFixture(t *testing.T, count int) (*RemoteImport, []Operation) {
	t.Helper()
	r, _, w, session, _, _ := actualHTTPFixture(t, count)
	report, err := r.RunCapturedScan(testContext, CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: pendingSmallBatchSession{session}, Capture: func(ctx context.Context, w SourceWitness, e SourceEntry) (*VerifiedSnapshot, error) {
		return CaptureGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	}})
	if report.Failed != int64(count) || report.Uploaded != 0 {
		t.Fatal(report, err)
	}
	rows, err := r.store.db.Query("SELECT operation_id FROM operations WHERE kind='PUT' ORDER BY operation_id")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	var ops []Operation
	for _, id := range ids {
		op, err := r.store.Operation(testContext, id)
		if err != nil || op.Stage != "SUBMITTED" || op.HTTPBinding != nil {
			t.Fatal(op.Stage, err)
		}
		ops = append(ops, op)
	}
	if len(ops) != count {
		t.Fatal(len(ops), count)
	}
	return r, ops
}
func stateBatchPlan(t *testing.T, id string, ops []Operation) *smallBatchPlan {
	t.Helper()
	p, err := newSmallBatchPlan(id, "rules-v1", ops)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func batchOriginalState(t *testing.T, r *RemoteImport, ops []Operation) string {
	t.Helper()
	var state []any
	for _, given := range ops {
		op, err := r.store.Operation(testContext, given.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		var receipt sql.NullString
		if err = r.store.db.QueryRow("SELECT receipt_json FROM operations WHERE operation_id=?", op.OperationID).Scan(&receipt); err != nil {
			t.Fatal(err)
		}
		state = append(state, op, receipt)
	}
	for _, table := range []string{"baselines", "dirty_entries"} {
		rows, err := r.store.db.Query("SELECT * FROM " + table + " ORDER BY root_id,entry_id")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for n := range dest {
				dest[n] = &values[n]
			}
			if err = rows.Scan(dest...); err != nil {
				t.Fatal(err)
			}
			state = append(state, values)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	return fingerprint(state)
}
func TestSmallBatchStateOptionalWALMigrationReferencesAndRestart(t *testing.T) {
	r, ops := smallBatchStateFixture(t, 3)
	before := batchOriginalState(t, r, ops)
	var version int
	r.store.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 6 {
		t.Fatal("default activated v7", version)
	}
	batches, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	p := stateBatchPlan(t, "durable-batch", ops)
	record, err := batches.reserve(testContext, p)
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != "RESERVED" || record.ExpectedBytes != 9 || record.FileIdentity != "" || record.Revision != 1 {
		t.Fatal(record)
	}
	if again, err := batches.reserve(testContext, p); err != nil || again.Name != record.Name || !bytes.Equal(again.Plan.manifest, p.manifest) {
		t.Fatal(err)
	}
	if batchOriginalState(t, r, ops) != before {
		t.Fatal("transport references changed original receipt/B/dirty")
	}
	var raw string
	if err = r.store.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=7").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var migration struct {
		Backup       string
		BackupSHA256 string
	}
	if err = json.Unmarshal([]byte(raw), &migration); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(filepath.Dir(r.store.filename), "sync-state-backups", migration.Backup)
	digest, err := fileDigest(backupPath)
	if err != nil || digest != migration.BackupSHA256 {
		t.Fatal("backup hash", err)
	}
	backup, err := openDB(backupPath, true)
	if err != nil {
		t.Fatal(err)
	}
	backup.QueryRow("PRAGMA user_version").Scan(&version)
	var oldCount int
	backup.QueryRow("SELECT COUNT(*) FROM operations WHERE kind='PUT' AND stage='SUBMITTED'").Scan(&oldCount)
	backup.Close()
	if version != 6 || oldCount != 3 {
		t.Fatal("WAL-aware v6 original backup", version, oldCount)
	}
	directory := filepath.Dir(r.store.filename)
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = artifacts.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	next, err := store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.enableHTTPBindings(testContext); err != nil {
		t.Fatal(err)
	}
	batches, err = next.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := batches.read(testContext, p.id)
	if err != nil || reopened.Name != record.Name || reopened.Scope != record.Scope || !bytes.Equal(reopened.Plan.manifest, p.manifest) {
		t.Fatal("reopen", err)
	}
	if batchOriginalState(t, next, ops) != before {
		t.Fatal("restart changed original authority")
	}
}
func TestSmallBatchStateMigrationAndReserveCrashBoundaries(t *testing.T) {
	r, ops := smallBatchStateFixture(t, 2)
	before := batchOriginalState(t, r, ops)
	r.testPoint = func(p string) error {
		if p == "small_batch.migration.before_commit" {
			return context.Canceled
		}
		return nil
	}
	if _, err := r.enableSmallBatches(testContext); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var version int
	r.store.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 6 {
		t.Fatal(version)
	}
	r.testPoint = nil
	batches, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	p := stateBatchPlan(t, "crash-batch", ops)
	for _, point := range []string{"small_batch.reserve.before_commit", "small_batch.reserve.after_commit"} {
		r.testPoint = func(name string) error {
			if name == point {
				return context.Canceled
			}
			return nil
		}
		if _, err = batches.reserve(testContext, p); !errors.Is(err, context.Canceled) {
			t.Fatal(point, err)
		}
		_, err = batches.read(testContext, p.id)
		if point == "small_batch.reserve.before_commit" && !errors.Is(err, sql.ErrNoRows) || point == "small_batch.reserve.after_commit" && err != nil {
			t.Fatal(point, err)
		}
	}
	r.testPoint = nil
	if _, err = batches.reserve(testContext, p); err != nil {
		t.Fatal(err)
	}
	if batchOriginalState(t, r, ops) != before {
		t.Fatal("crash boundary changed originals")
	}
}
func TestSmallBatchStateSharedPlaintextQuotaAndActiveOriginalExclusion(t *testing.T) {
	r, ops := smallBatchStateFixture(t, 2)
	batches, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	p := stateBatchPlan(t, "quota-batch", ops)
	a := r.store.artifacts
	a.limits.PlaintextBytes = 11
	if _, err = batches.reserve(testContext, p); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("additional plaintext not charged", err)
	}
	a.limits.PlaintextBytes = 12
	if _, err = batches.reserve(testContext, p); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reserve(testContext, 1); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("ordinary capture bypassed packet charge", err)
	}
	a.limits.PlaintextBytes = MaxFileBytes
	if _, err = batches.reserve(testContext, stateBatchPlan(t, "overlapping", ops)); !errors.Is(err, ErrArtifactInUse) {
		t.Fatal("same original in two live groups", err)
	}
	changed := stateBatchPlan(t, p.id, ops[:1])
	if _, err = batches.reserve(testContext, changed); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("same batch ID rebound", err)
	}
	for _, op := range ops {
		artifact, err := a.Record(testContext, op.SnapshotID)
		if err != nil || artifact.Phase != ArtifactSealed {
			t.Fatal("fallback original lost", err)
		}
	}
}
func TestSmallBatchStateFourLiveGroupsAreHardBound(t *testing.T) {
	r, ops := smallBatchStateFixture(t, 5)
	batches, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	for n, op := range ops {
		p := stateBatchPlan(t, "group-"+remoteDecimal(int64(n)), []Operation{op})
		_, err = batches.reserve(testContext, p)
		if n < 4 && err != nil || n == 4 && !errors.Is(err, ErrSourceQuota) {
			t.Fatal(n, err)
		}
	}
}
func TestSmallBatchStateReadRejectsMembershipManifestAndSchemaDamage(t *testing.T) {
	r, ops := smallBatchStateFixture(t, 2)
	batches, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	p := stateBatchPlan(t, "tamper-batch", ops)
	if _, err = batches.reserve(testContext, p); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		sql      string
		args     []any
		undo     string
		undoArgs []any
	}{
		{"UPDATE small_batch_members SET offset_bytes=1 WHERE batch_id=? AND ordinal=0", []any{p.id}, "UPDATE small_batch_members SET offset_bytes=0 WHERE batch_id=? AND ordinal=0", []any{p.id}},
		{"UPDATE small_batch_members SET source_generation=source_generation+1 WHERE batch_id=? AND ordinal=0", []any{p.id}, "UPDATE small_batch_members SET source_generation=source_generation-1 WHERE batch_id=? AND ordinal=0", []any{p.id}},
		{"UPDATE small_batch_members SET source_identity=? WHERE batch_id=? AND ordinal=0", []any{strings.Repeat("0", 64), p.id}, "UPDATE small_batch_members SET source_identity=? WHERE batch_id=? AND ordinal=0", []any{p.entries[0].sourceIdentity, p.id}},
		{"UPDATE small_batch_groups SET manifest_sha256=? WHERE batch_id=?", []any{strings.Repeat("0", 64), p.id}, "UPDATE small_batch_groups SET manifest_sha256=? WHERE batch_id=?", []any{hashBytes(p.manifest), p.id}},
		{"UPDATE small_batch_members SET active=0 WHERE batch_id=? AND ordinal=0", []any{p.id}, "UPDATE small_batch_members SET active=1 WHERE batch_id=? AND ordinal=0", []any{p.id}},
	} {
		if _, err = r.store.db.Exec(change.sql, change.args...); err != nil {
			t.Fatal(err)
		}
		if _, err = batches.read(testContext, p.id); err == nil {
			t.Fatal("damaged reference accepted")
		}
		if _, err = r.store.db.Exec(change.undo, change.undoArgs...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = batches.read(testContext, p.id); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(r.store.filename)
	r.store.db.Exec("DROP INDEX active_small_batch_original")
	r.store.Close()
	before, _ := os.ReadFile(r.store.filename)
	if invalid, err := Open(testContext, directory); err == nil {
		invalid.Close()
		t.Fatal("damaged v7 DDL admitted")
	}
	after, _ := os.ReadFile(r.store.filename)
	if !bytes.Equal(before, after) {
		t.Fatal("preflight rewrote damaged v7")
	}
}
func TestSmallBatchStateActualV6ReaderPreservesDurableState(t *testing.T) {
	reader := os.Getenv("PLUTO_BATCH_V6_READER")
	if reader == "" {
		t.Skip("requires frozen actual v6 executable")
	}
	for _, keepWAL := range []bool{false, true} {
		t.Run(map[bool]string{false: "checkpointed", true: "committed-WAL"}[keepWAL], func(t *testing.T) {
			r, ops := smallBatchStateFixture(t, 2)
			batches, err := r.enableSmallBatches(testContext)
			if err != nil {
				t.Fatal(err)
			}
			plan := stateBatchPlan(t, "v7-batch", ops)
			if _, err = batches.reserve(testContext, plan); err != nil {
				t.Fatal(err)
			}
			originals := batchOriginalState(t, r, ops)
			if keepWAL {
				anchor, err := openDB(r.store.filename, true)
				if err != nil {
					t.Fatal(err)
				}
				defer anchor.Close()
				var version int
				if err = anchor.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 7 {
					t.Fatal(version, err)
				}
			}
			dir := filepath.Dir(r.store.filename)
			if err = r.store.Close(); err != nil {
				t.Fatal(err)
			}
			type file struct {
				Bytes  int
				SHA256 string
			}
			snapshot := func() map[string]file {
				result := map[string]file{}
				for _, suffix := range []string{"", "-wal", "-shm"} {
					raw, err := os.ReadFile(r.store.filename + suffix)
					if err == nil {
						result[suffix] = file{len(raw), hashBytes(raw)}
					} else if !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
				}
				return result
			}
			before := snapshot()
			if keepWAL && before["-wal"].Bytes <= 32 {
				t.Fatal("missing committed WAL fixture")
			}
			output, err := exec.Command(reader, dir).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "sync state schema is unsupported") {
				t.Fatal(string(output), err)
			}
			after := snapshot()
			if before[""] != after[""] {
				t.Fatal("old reader changed main database")
			}
			if before["-wal"].Bytes > 0 {
				if before["-wal"] != after["-wal"] {
					t.Fatal("old reader changed committed WAL")
				}
			} else if after["-wal"].Bytes != 0 {
				t.Fatal("old reader wrote new WAL bytes")
			}
			// SQLite's frozen v6 readonly preflight may create an empty WAL and
			// a transient SHM index. These are observed, not claimed byte-unchanged.
			if after["-shm"].Bytes > 32768 {
				t.Fatal("unexpected sidecar growth")
			}
			t.Logf("actual v6 refusal: before=%v after=%v; durable DB/WAL exact", before, after)
			current, err := Open(testContext, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer current.Close()
			next := &RemoteImport{store: current}
			saved, err := (&smallBatchStore{remote: next}).read(testContext, plan.id)
			if err != nil || !bytes.Equal(saved.Plan.manifest, plan.manifest) || batchOriginalState(t, next, ops) != originals {
				t.Fatal("new reader did not retain originals/packet", err)
			}
		})
	}
}
