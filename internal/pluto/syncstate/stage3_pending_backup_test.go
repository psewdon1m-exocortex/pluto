package syncstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	sqlite "modernc.org/sqlite"
)

func stage3ImmutableDB(t *testing.T, filename string) *sql.DB {
	t.Helper()
	u := url.URL{Scheme: "file", Path: filename}
	u.RawQuery = "mode=ro&immutable=1"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}
func stage3DatabaseLogicalDigest(t *testing.T, filename string) (string, int) {
	t.Helper()
	db := stage3ImmutableDB(t, filename)
	defer db.Close()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	objects, err := db.Query("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")
	if err != nil {
		t.Fatal(err)
	}
	var schema [][]any
	var tables []string
	for objects.Next() {
		var kind, name, table string
		var ddl any
		if err = objects.Scan(&kind, &name, &table, &ddl); err != nil {
			t.Fatal(err)
		}
		schema = append(schema, []any{kind, name, table, ddl})
		if kind == "table" {
			tables = append(tables, name)
		}
	}
	if err = objects.Err(); err != nil {
		t.Fatal(err)
	}
	if err = objects.Close(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(tables)
	payload := map[string]any{"version": version, "schema": schema}
	rowCount := 0
	for _, table := range tables {
		quoted := "\"" + strings.ReplaceAll(table, "\"", "\"\"") + "\""
		rows, err := db.Query("SELECT * FROM " + quoted)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var values []string
		for rows.Next() {
			cells := make([]any, len(columns))
			targets := make([]any, len(columns))
			for n := range cells {
				targets[n] = &cells[n]
			}
			if err = rows.Scan(targets...); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(cells)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, string(raw))
			rowCount++
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err = rows.Close(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(values)
		payload[table] = map[string]any{"columns": columns, "rows": values}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), rowCount
}
func stage3RestoreSQLiteAPI(t *testing.T, directory, source, expected string) {
	t.Helper()
	sourceSHA, err := fileDigest(source)
	if err != nil || sourceSHA != expected {
		t.Fatal("exact genuine restore source", err)
	}
	filename := filepath.Join(directory, "sync-state.sqlite")
	before, err := os.Lstat(filename)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := lockStateWriter(directory)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDB(filename, false)
	if err != nil {
		lock.Close()
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(testContext, 10*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		lock.Close()
		t.Fatal(err)
	}
	restoreErr := conn.Raw(func(driver any) error {
		// Restore is used only by this fixture checkpoint helper. The product
		// statement cache wraps the same native connection under its lock.
		if wrapped, ok := driver.(*stateSQLiteConn); ok {
			driver = wrapped.stateSQLiteNative
		}
		actual, ok := driver.(interface {
			NewRestore(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("qualified SQLite driver has no restore API")
		}
		u := url.URL{Scheme: "file", Path: source}
		u.RawQuery = "mode=ro&immutable=1"
		restore, err := actual.NewRestore(u.String())
		if err != nil {
			return err
		}
		for {
			if err = ctx.Err(); err != nil {
				return errors.Join(err, restore.Finish())
			}
			more, stepErr := restore.Step(128)
			if stepErr != nil {
				return errors.Join(stepErr, restore.Finish())
			}
			if !more {
				return restore.Finish()
			}
		}
	})
	connClose := conn.Close()
	var busy, log, done int
	checkpointErr := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done)
	closeErr := db.Close()
	lockErr := lock.Close()
	if restoreErr != nil || connClose != nil || checkpointErr != nil || busy != 0 || closeErr != nil || lockErr != nil {
		t.Fatal("SQLite API restore did not close coherently", restoreErr, connClose, checkpointErr, busy, closeErr, lockErr)
	}
	after, err := os.Lstat(filename)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		t.Fatal("same original DB inode required", err)
	}
	if digest, e := fileDigest(source); e != nil || digest != expected {
		t.Fatal("restore source mutated", e)
	}
	syncFixtureDirectory(t, directory)
}

type stage3PhysicalEntry struct {
	Root, Relative, Kind, SHA256 string
	Device, Inode                uint64
	Mode                         uint32
	Bytes, MTimeNS, CTimeNS      int64
}

func stage3PendingPhysical(t *testing.T, state, source string) []stage3PhysicalEntry {
	t.Helper()
	var entries []stage3PhysicalEntry
	for _, root := range []string{filepath.Join(state, ArtifactDirectoryName), filepath.Join(state, smallBatchDirectoryName), source} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != uint32(os.Getuid()) {
				return ErrIdentityConflict
			}
			rel, e := filepath.Rel(root, p)
			if e != nil {
				return e
			}
			row := stage3PhysicalEntry{Root: root, Relative: rel, Kind: "directory", Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, Bytes: info.Size(), MTimeNS: info.ModTime().UnixNano(), CTimeNS: statCTime(info)}
			if !info.IsDir() {
				if !info.Mode().IsRegular() || st.Nlink != 1 {
					return ErrIdentityConflict
				}
				row.Kind = "file"
				row.SHA256, e = fileDigest(p)
				if e != nil {
					return e
				}
			}
			entries = append(entries, row)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return entries
}
func stage3PendingProofWrite(t *testing.T, filename string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(append(raw, '\n'))
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	syncFixtureDirectory(t, filepath.Dir(filename))
}

func qualifyStage3PendingMigrationBackup(t *testing.T, state, source string, plan *smallBatchPlan) *fixtureBackup {
	t.Helper()
	originalFile := filepath.Join(state, "sync-state.sqlite")
	originalLogical, originalRows := stage3DatabaseLogicalDigest(t, originalFile)
	originalPhysical := stage3PendingPhysical(t, state, source)
	if len(plan.entries) != 2 {
		t.Fatal("original two-operation fixture required")
	}
	preliminary := qualifyClosedFixtureBackup(t, state, []string{source}, func(copy *Store) {
		filename := copy.filename
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		digest, count := stage3DatabaseLogicalDigest(t, filename)
		if digest != originalLogical || count != originalRows {
			t.Fatal("preliminary full logical backup differs")
		}
	})
	restoreSource := filepath.Join(preliminary.directory, "restored/state/sync-state.sqlite")
	sourceSHA, err := fileDigest(restoreSource)
	if err != nil {
		t.Fatal(err)
	}
	stage3RestoreSQLiteAPI(t, state, restoreSource, sourceSHA)
	if digest, count := stage3DatabaseLogicalDigest(t, originalFile); digest != originalLogical || count != originalRows {
		t.Fatal("SQLite restore API did not preserve complete logical database")
	}
	var restoredReads []map[string]any
	var restoredBytes int64
	product, err := Open(testContext, state)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if err := product.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err = product.EnableSources(testContext, DefaultSourceLimits()); err != nil {
			t.Fatal(err)
		}
		artifacts, e := product.EnableArtifacts(testContext, DefaultArtifactLimits())
		if e != nil {
			t.Fatal(e)
		}
		report, e := artifacts.Reconcile(testContext, artifactTestReader)
		if e != nil || !report.Admitted || report.Files != 2 || report.RecoveryOperations != 2 || report.ReservedBytes != 6 {
			t.Fatal("restored pending artifact admission", report, e)
		}
		remote, e := product.EnableRemoteImport(testContext)
		if e != nil {
			t.Fatal(e)
		}
		batches, e := remote.enableSmallBatches(testContext)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = batches.enableArtifacts(testContext); e != nil {
			t.Fatal(e)
		}

		for _, entry := range plan.entries {
			current, e := product.Operation(testContext, entry.original.OperationID)
			if e != nil || !reflect.DeepEqual(current, entry.original) {
				t.Fatal("restored immutable pending operation differs", e)
			}
			var artifactName string
			if e = product.db.QueryRow("SELECT filename FROM local_artifacts WHERE snapshot_id=? AND operation_id=?", current.SnapshotID, current.OperationID).Scan(&artifactName); e != nil {
				t.Fatal(e)
			}
			e = artifacts.WithRecoveryReader(testContext, current, artifactTestReader, func(reader io.Reader) error {
				raw, err := io.ReadAll(io.LimitReader(reader, current.SizeBytes+1))
				if err != nil {
					return err
				}
				if current.Captured == nil {
					return errors.New("original captured source evidence missing")
				}
				evidence := current.Captured.Evidence
				binding, err := product.sources.Binding(testContext, evidence.SetID, evidence.SourceID)
				if err != nil || binding.PhysicalPath != source {
					return errors.New("original physical source binding differs")
				}
				relative, err := filepath.Rel(filepath.FromSlash(binding.Destination), filepath.FromSlash(evidence.Destination))
				if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					return errors.New("original captured source outside binding")
				}
				sourceRaw, err := os.ReadFile(filepath.Join(source, relative))
				if err != nil {
					return err
				}
				if int64(len(raw)) != current.SizeBytes || !reflect.DeepEqual(raw, sourceRaw) || hashBytes(raw) != current.SHA256 {
					return errors.New("restored original captured plaintext differs")
				}
				restoredBytes += int64(len(raw))
				restoredReads = append(restoredReads, map[string]any{"operationID": current.OperationID, "snapshotID": current.SnapshotID, "artifactName": artifactName, "sourceName": filepath.ToSlash(relative), "operationName": current.Name, "bytes": len(raw), "sha256": hashBytes(raw)})
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		var version int
		if e = product.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 7 {
			t.Fatal("restore must retain original v7 before crash", version, e)
		}
	}()
	if len(restoredReads) != 2 || restoredBytes != 6 {
		t.Fatal("both actual retained plaintexts must be restored and read", len(restoredReads), restoredBytes)
	}
	if t.Failed() {
		t.Fatal("pending full-module restore precondition failed")
	}
	// A second complete SQLite restore returns the just-qualified fixture to its
	// genuine checkpoint before the first migration fault. No row/guard edit.
	stage3RestoreSQLiteAPI(t, state, restoreSource, sourceSHA)
	finalLogical, finalRows := stage3DatabaseLogicalDigest(t, originalFile)
	if finalLogical != originalLogical || finalRows != originalRows {
		t.Fatal("full checkpoint restore changed original IDs/rows")
	}
	if !reflect.DeepEqual(originalPhysical, stage3PendingPhysical(t, state, source)) {
		t.Fatal("restore probe changed original source/artifact inode graph")
	}
	final := qualifyClosedFixtureBackup(t, state, []string{source}, func(copy *Store) {
		filename := copy.filename
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		digest, count := stage3DatabaseLogicalDigest(t, filename)
		if digest != originalLogical || count != originalRows {
			t.Fatal("final before-fault checkpoint differs")
		}
	})
	stage3PendingProofWrite(t, filepath.Join(final.directory, "pending-restore.json"), map[string]any{"schema": "pluto.pending-same-inode-restore.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "preliminaryDirectory": filepath.Base(preliminary.directory), "preliminaryArchiveSHA256": preliminary.archiveSHA, "finalArchiveSHA256": final.archiveSHA, "SQLiteRestoreAPI": "modernc.org/sqlite@v1.60.1 NewRestore, Step128, Finish", "restoreCallsBeforeFault": 2, "restoredOnOriginalPhysicalInodes": true, "directoryRelocated": false, "manualAuthorityOrRowEdits": false, "logicalBeforeSHA256": originalLogical, "logicalFinalSHA256": finalLogical, "logicalRows": finalRows, "originalPhysical": originalPhysical, "pendingOperations": 2, "pendingBytes": 6, "allV7ModulesOpened": true, "actualRestoredReads": restoredReads, "actualRestoredBytes": restoredBytes, "historicalReader": false})
	t.Logf("STAGE3_PENDING_GRAPH_RESTORED_SAME_INODES logicalRows=%d retainedOperations=2 retainedBytes=6", finalRows)
	return final
}
func preserveStage3PendingDatabase(t *testing.T, store *Store, backup *fixtureBackup, phase string, version int, plan *smallBatchPlan) {
	t.Helper()
	if phase != "rolledback-v7" && phase != "forward-v8" {
		t.Fatal("exact pending migration evidence phase required")
	}
	var actualVersion int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&actualVersion); err != nil || actualVersion != version {
		t.Fatal("actual pending migration schema", actualVersion, err)
	}
	var originals []Operation
	for _, entry := range plan.entries {
		current, err := store.Operation(testContext, entry.original.OperationID)
		if err != nil || !reflect.DeepEqual(current, entry.original) {
			t.Fatal("original pending operation changed", err, current.OperationID)
		}
		originals = append(originals, current)
	}
	result, err := store.Backup(testContext)
	if err != nil || filepath.Base(result.Filename) != result.Filename {
		t.Fatal("real pending SQLite backup", err)
	}
	src := filepath.Join(filepath.Dir(store.filename), "sync-state-backups", result.Filename)
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	info, err := in.Stat()
	if err != nil || info.Size() < 1 || info.Size() > 64<<20 {
		in.Close()
		t.Fatal("bounded pending SQLite backup", err)
	}
	target := filepath.Join(backup.directory, phase+".sqlite")
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		in.Close()
		t.Fatal(err)
	}
	copied, copyErr := io.Copy(out, in)
	inputClose := in.Close()
	syncErr, outputClose := out.Sync(), out.Close()
	if copyErr != nil || inputClose != nil || syncErr != nil || outputClose != nil || copied != info.Size() {
		t.Fatal(copyErr, inputClose, syncErr, outputClose)
	}
	digest, err := fileDigest(target)
	if err != nil || digest != result.SHA256 {
		t.Fatal("pending backup SHA", err)
	}
	logical, rows := stage3DatabaseLogicalDigest(t, target)
	stage3PendingProofWrite(t, filepath.Join(backup.directory, phase+".json"), map[string]any{"schema": "pluto.pending-migration-database.v1", "case": t.Name(), "phase": phase, "at": time.Now().UTC().Format(time.RFC3339Nano), "schemaVersion": version, "sqliteSHA256": digest, "sqliteBytes": copied, "actualSQLiteBackup": result, "logicalSHA256": logical, "logicalRows": rows, "originals": originals, "historicalReader": false})
	t.Logf("STAGE3_PENDING_DATABASE_EXPORTED phase=%s version=%d sqliteSHA256=%s", phase, version, digest)
}
func stage3VerifyPendingPhysicalAfter(t *testing.T, backup *fixtureBackup, state, source string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(backup.directory, "pending-restore.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		OriginalPhysical []stage3PhysicalEntry `json:"originalPhysical"`
	}
	if err = json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	actual := stage3PendingPhysical(t, state, source)
	if !reflect.DeepEqual(expected.OriginalPhysical, actual) {
		t.Fatal("original physical graph changed across migration crash")
	}
	stage3PendingProofWrite(t, filepath.Join(backup.directory, "pending-physical-after.json"), map[string]any{"schema": "pluto.pending-physical-after.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "originalPhysical": actual, "unchanged": true, "historicalReader": false})
}
