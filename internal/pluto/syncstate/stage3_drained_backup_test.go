package syncstate

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stage3BackupScope struct {
	ScopeID, DirectoryIdentity, OwnerID string
	OwnerSequence                       int64
}

func qualifyStage3DrainedHintBackup(t *testing.T, state, source string, binding RootBinding) *fixtureBackup {
	t.Helper()
	return qualifyClosedFixtureBackup(t, state, []string{source}, func(copy *Store) {
		restoredState := filepath.Dir(copy.filename)
		var before stage3BackupScope
		if err := copy.db.QueryRow("SELECT scope_id,directory_identity,owner_id,owner_sequence FROM artifact_scope WHERE singleton=1").Scan(&before.ScopeID, &before.DirectoryIdentity, &before.OwnerID, &before.OwnerSequence); err != nil {
			t.Fatal(err)
		}
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		digest, err := fileDigest(filepath.Join(restoredState, "sync-state.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		transferred, err := RestoreArtifactDirectory(testContext, restoredState, digest, binding)
		if err != nil || !transferred.Changed || transferred.ScopeID != before.ScopeID || transferred.PreviousDirectoryIdentity != before.DirectoryIdentity {
			t.Fatal("official drained graph restore failed", transferred, err)
		}
		actual, err := Open(testContext, restoredState)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := actual.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err = actual.EnableSources(testContext, DefaultSourceLimits()); err != nil {
			t.Fatal(err)
		}
		artifacts, err := actual.EnableArtifacts(testContext, DefaultArtifactLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := artifacts.Reconcile(testContext, artifactTestReader)
		if err != nil || !report.Admitted || report.Files != 0 || report.ReservedBytes != 0 || report.RecoveryOperations != 0 {
			t.Fatal("restored artifact admission", report, err)
		}
		remote, err := actual.EnableRemoteImport(testContext)
		if err != nil {
			t.Fatal(err)
		}
		if err = remote.EnableDaemonState(testContext); err != nil {
			t.Fatal(err)
		}
		root, err := actual.Root(testContext, binding.RootID)
		if err != nil || root.RootBinding != binding {
			t.Fatal("restored binding changed", root, err)
		}
		var after stage3BackupScope
		if err = actual.db.QueryRow("SELECT scope_id,directory_identity,owner_id,owner_sequence FROM artifact_scope WHERE singleton=1").Scan(&after.ScopeID, &after.DirectoryIdentity, &after.OwnerID, &after.OwnerSequence); err != nil {
			t.Fatal(err)
		}
		if after.ScopeID != before.ScopeID || after.DirectoryIdentity != transferred.DirectoryIdentity || after.OwnerSequence != before.OwnerSequence+1 || after.OwnerID == "" || after.OwnerID == before.OwnerID {
			t.Fatal("restored custody handoff differs", before, after)
		}
		var version, operations, dirty int
		if err = actual.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err = actual.db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&operations); err != nil {
			t.Fatal(err)
		}
		if err = actual.db.QueryRow("SELECT COUNT(*) FROM source_dirty").Scan(&dirty); err != nil {
			t.Fatal(err)
		}
		if version != 8 || operations != 0 || dirty != 0 {
			t.Fatal("pre-hint restored state differs", version, operations, dirty)
		}
		for _, directory := range []string{source, filepath.Join(filepath.Dir(restoredState), "source-001")} {
			files, err := os.ReadDir(directory)
			if err != nil || len(files) != 0 {
				t.Fatal("exact empty original/restored source required", err)
			}
		}
		if err = actual.Close(); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(map[string]any{"schema": "pluto.drained-hint-restore.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "databaseBeforeRestoreSHA256": digest, "officialRestore": transferred, "beforeScope": before, "afterScope": after, "binding": binding, "schemaVersion": version, "operations": operations, "dirtyHints": dirty, "allModulesOpened": true, "artifactAdmission": report, "originalAndCopiedSourceEmpty": true, "historicalReader": false}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		proof := filepath.Join(filepath.Dir(filepath.Dir(restoredState)), "drained-restore.json")
		f, err := os.OpenFile(proof, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := f.Write(append(raw, '\n'))
		syncErr, closeErr := f.Sync(), f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal(writeErr, syncErr, closeErr)
		}
		syncFixtureDirectory(t, filepath.Dir(proof))
		t.Logf("STAGE3_DRAINED_GRAPH_RESTORED schema=%d scope=%s ownerSequence=%d", version, after.ScopeID, after.OwnerSequence)
	})
}

func preserveStage3HintOutcome(t *testing.T, store *Store, backup *fixtureBackup, setID, source string) {
	t.Helper()
	var hint struct {
		SetID, SourceID, Destination, PhysicalPath string
		Generation, FirstMS, LastMS, Mask, Cookie  int64
	}
	err := store.db.QueryRow("SELECT set_id,source_id,destination,physical_path,generation,first_ms,last_ms,mask,cookie FROM source_dirty WHERE set_id=? AND generation>0 AND destination LIKE '%/durable'", setID).Scan(&hint.SetID, &hint.SourceID, &hint.Destination, &hint.PhysicalPath, &hint.Generation, &hint.FirstMS, &hint.LastMS, &hint.Mask, &hint.Cookie)
	if err != nil || hint.SetID != setID || hint.SourceID != "source" || hint.Generation < 1 || hint.Mask != 1 || hint.PhysicalPath != filepath.Join(source, "durable") {
		t.Fatal("actual original durable hint differs", hint, err)
	}
	walBytes := int64(0)
	if info, e := os.Stat(store.filename + "-wal"); e == nil {
		walBytes = info.Size()
	} else if !os.IsNotExist(e) {
		t.Fatal(e)
	}
	sqlBackup, err := store.Backup(testContext)
	if err != nil || filepath.Base(sqlBackup.Filename) != sqlBackup.Filename {
		t.Fatal("actual postfault SQLite backup", err)
	}
	sourceFile := filepath.Join(filepath.Dir(store.filename), "sync-state-backups", sqlBackup.Filename)
	info, err := os.Lstat(sourceFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 {
		t.Fatal("bounded postfault backup", err)
	}
	in, err := os.Open(sourceFile)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(backup.directory, "postfault.sqlite")
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	digest, err := fileDigest(destination)
	if err != nil || digest != sqlBackup.SHA256 {
		t.Fatal("postfault backup SHA differs", err)
	}
	raw, err := json.MarshalIndent(map[string]any{"schema": "pluto.durable-hint-postfault.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "sqliteSHA256": digest, "sqliteBytes": copied, "actualSQLiteBackup": sqlBackup, "mainWalBytesBeforeBackup": walBytes, "originalHint": hint, "actualChildExit": 86, "historicalReader": false}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := os.OpenFile(filepath.Join(backup.directory, "postfault-hint.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := proof.Write(append(raw, '\n'))
	proofSync, proofClose := proof.Sync(), proof.Close()
	if writeErr != nil || proofSync != nil || proofClose != nil {
		t.Fatal(writeErr, proofSync, proofClose)
	}
	syncFixtureDirectory(t, backup.directory)
	t.Logf("STAGE3_DURABLE_HINT_EXPORTED sqliteSHA256=%s generation=%d walBytesBeforeBackup=%d", digest, hint.Generation, walBytes)
}
