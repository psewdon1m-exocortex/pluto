package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Test-only old-generation fixture. Production has no downgrade path.
func versionOneFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s, dir := stateFixture(t)
	l := fileObservation("file", "file")
	l.HashGeneration = 1
	l.SHA256 = hashBytes([]byte("one"))
	capture(t, s, l)
	op := planned(t, s, "initial", "file")
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	seedBaselineRemote(t, s, "file")
	l.ExpectedGeneration = 1
	l.HashGeneration = 2
	l.SHA256 = hashBytes([]byte("two"))
	capture(t, s, l)
	intent := fixtureIntent(t, s, "pending-outcome", "file")
	if err := s.Plan(testContext, intent); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(testContext, intent.OperationID, l.SHA256, "snapshot-two"); err != nil {
		t.Fatal(err)
	}
	if err := s.Submitted(testContext, intent.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := s.transaction(testContext, func(tx *sql.Tx) error {
		if _, err := tx.Exec("DROP INDEX pending_entry_operations; PRAGMA user_version=1"); err != nil {
			return err
		}
		_, err := tx.Exec("UPDATE schema_migrations SET version=1,manifest_json='{}'")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestPendingIndexMigrationPreservesDurableStateAndWalBackup(t *testing.T) {
	s, dir := versionOneFixture(t)
	before, err := s.Entry(testContext, "root", "file")
	if err != nil {
		t.Fatal(err)
	}
	beforeOp, _ := s.Operation(testContext, "pending-outcome")
	beforeRoot, _ := s.Root(testContext, "root")
	beforeLocal, _ := s.Cursor(testContext, "root", "local")
	beforeRemote, _ := s.Cursor(testContext, "root", "remote")
	// Keep WAL mode open while releasing the Store lock; committed state must be
	// included by the backup API even if absent from the main database file.
	keeper, err := openDB(filepath.Join(dir, "sync-state.sqlite"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	var version int
	if err = keeper.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal(version, err)
	}
	s.Close()
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := reopened.Entry(testContext, "root", "file")
	afterOp, _ := reopened.Operation(testContext, "pending-outcome")
	afterRoot, _ := reopened.Root(testContext, "root")
	afterLocal, _ := reopened.Cursor(testContext, "root", "local")
	afterRemote, _ := reopened.Cursor(testContext, "root", "remote")
	if fingerprint(before) != fingerprint(after) || fingerprint(beforeOp) != fingerprint(afterOp) || beforeRoot != afterRoot || beforeLocal != afterLocal || beforeRemote != afterRemote || afterRoot.EngineReady {
		t.Fatal("migration reinterpreted durable state", before, after)
	}
	var raw string
	if err = reopened.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=?", SchemaVersion).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Backup          string
		BackupSHA256    string
		EngineActivated bool
	}
	if err = json.Unmarshal([]byte(raw), &manifest); err != nil || manifest.EngineActivated || !validHash(manifest.BackupSHA256) {
		t.Fatal(raw, err)
	}
	backup := filepath.Join(dir, "sync-state-backups", manifest.Backup)
	digest, err := fileDigest(backup)
	if err != nil || digest != manifest.BackupSHA256 {
		t.Fatal("backup digest", digest, err)
	}
	if err = preflight(testContext, backup); err != nil {
		t.Fatal("old-generation backup", err)
	}
	bdb, err := openDB(backup, true)
	if err != nil {
		t.Fatal(err)
	}
	var opStage string
	if err = bdb.QueryRow("SELECT stage FROM operations WHERE operation_id='pending-outcome'").Scan(&opStage); err != nil || opStage != "SUBMITTED" {
		t.Fatal("WAL receipt/intent missing from backup", opStage, err)
	}
	if err = bdb.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal("backup was migrated", version, err)
	}
	bdb.Close()
	reopened.Close()
	again, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	var migrations int
	if err = again.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migrations); err != nil || migrations != 2 {
		t.Fatal("migration repeated", migrations, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "sync-state-backups", "schema-v1-*.sqlite"))
	if err != nil || len(files) != 1 {
		t.Fatal("backup repeated", files, err)
	}
}

func TestInterruptedPendingIndexMigrationKeepsVersionOne(t *testing.T) {
	s, dir := versionOneFixture(t)
	s.Close()
	backup := qualifyClosedFixtureBackup(t, dir, nil, func(restored *Store) {
		op, err := restored.Operation(testContext, "pending-outcome")
		if err != nil || op.Stage != "SUBMITTED" {
			t.Fatal("restored pending original", op, err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPendingMigrationCrashHelper$")
	cmd.Env = append(os.Environ(), "PLUTO_PENDING_MIGRATION_CRASH_DIR="+dir)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 34 {
		t.Fatal("crash fixture", err, string(out))
	}
	backup.recordActualExit(t, "TestPendingMigrationCrashHelper", cmd.Process.Pid, exit.ExitCode())
	if err = preflight(testContext, filepath.Join(dir, "sync-state.sqlite")); err != nil {
		t.Fatal("uncommitted DDL survived", err)
	}
	db, err := openDB(filepath.Join(dir, "sync-state.sqlite"), true)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal(version, err)
	}
	db.Close()
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	op, err := reopened.Operation(testContext, "pending-outcome")
	if err != nil || op.Stage != "SUBMITTED" {
		t.Fatal("pending intent lost after migration interruption", op, err)
	}
}

func TestPendingMigrationCrashHelper(t *testing.T) {
	dir := os.Getenv("PLUTO_PENDING_MIGRATION_CRASH_DIR")
	if dir == "" {
		return
	}
	db, err := openDB(filepath.Join(dir, "sync-state.sqlite"), false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(testContext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(pendingIndexDDL); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", SchemaVersion)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,'fixture','{}')", SchemaVersion); err != nil {
		t.Fatal(err)
	}
	os.Exit(34)
}

func TestCancelledMigrationDoesNotAdvanceSchema(t *testing.T) {
	s, dir := versionOneFixture(t)
	s.Close()
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if store, err := Open(ctx, dir); err == nil {
		store.Close()
		t.Fatal("cancelled migration continued")
	}
	if err := preflight(testContext, filepath.Join(dir, "sync-state.sqlite")); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(filepath.Join(dir, "sync-state.sqlite"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal(version, err)
	}
}
