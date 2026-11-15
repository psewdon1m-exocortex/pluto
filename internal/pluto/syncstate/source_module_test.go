package syncstate

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceModuleMigrationWalBackupAndLegacyPreservation(t *testing.T) {
	store, dir := stateFixture(t)
	capture(t, store, fileObservation("file", "file"))
	rootBefore, _ := store.Root(testContext, "root")
	entryBefore, _ := store.Entry(testContext, "root", "file")
	for name, raw := range map[string][]byte{"config.json": []byte(`{"paused":true,"token":"fixture-only","sources":["/fixture"]}`), "pause-state": []byte("paused\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keeper, err := openDB(filepath.Join(dir, "sync-state.sqlite"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	var version int
	keeper.QueryRow("PRAGMA user_version").Scan(&version)
	walCheckpoint := qualifySourceWalMigrationBackup(t, store, dir)
	sources, err := store.EnableSources(testContext, DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	rootAfter, _ := store.Root(testContext, "root")
	entryAfter, _ := store.Entry(testContext, "root", "file")
	if rootBefore != rootAfter || fingerprint(entryBefore) != fingerprint(entryAfter) || rootAfter.EngineReady {
		t.Fatal("migration reinterpreted durable evidence")
	}
	var raw string
	if err = store.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=3").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Backup, BackupSHA256 string
		EngineActivated      bool
	}
	json.Unmarshal([]byte(raw), &manifest)
	if !validHash(manifest.BackupSHA256) || manifest.EngineActivated {
		t.Fatal(raw)
	}
	backup := filepath.Join(dir, "sync-state-backups", manifest.Backup)
	digest, _ := fileDigest(backup)
	if digest != manifest.BackupSHA256 {
		t.Fatal(digest)
	}
	bdb, _ := openDB(backup, true)
	bdb.QueryRow("PRAGMA user_version").Scan(&version)
	var n int
	bdb.QueryRow("SELECT COUNT(*) FROM local_entries").Scan(&n)
	bdb.Close()
	if version != 2 || n != 1 {
		t.Fatal("WAL omitted", version, n)
	}
	u, err := sources.DiskUsage(testContext)
	if err != nil || u.PageSize != 4096 || u.Backup == 0 {
		t.Fatal("physical accounting", u, err)
	}
	store.Close()
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	reopened.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=3").Scan(&n)
	if n != 1 {
		t.Fatal("migration repeated", n)
	}
	for name, want := range map[string]string{"config.json": `{"paused":true,"token":"fixture-only","sources":["/fixture"]}`, "pause-state": "paused\n"} {
		bytes, _ := os.ReadFile(filepath.Join(dir, name))
		if string(bytes) != want {
			t.Fatal("legacy file changed", name)
		}
	}
	preserveSourceWalMigrationOutcome(t, reopened, dir, walCheckpoint)
	if old := os.Getenv("PLUTO_OLD_STATE_READER"); old != "" {
		reopened.Close()
		before, _ := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
		out, err := exec.Command(old, dir).CombinedOutput()
		if err != nil || string(out) != "unsupported-preserved\n" {
			t.Fatal("actual old reader did not refuse", string(out), err)
		}
		after, _ := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
		if before != after {
			t.Fatal("old reader mutated module")
		}
	}
}
func TestSourceModuleCorruptUnknownAndInterruptedMigration(t *testing.T) {
	for _, mutation := range []string{"DROP TABLE source_evidence", "PRAGMA user_version=999", "CREATE TABLE unrelated(value TEXT)"} {
		t.Run(mutation, func(t *testing.T) {
			physical := t.TempDir()
			s, _, _ := sourceFixture(t, physical)
			dir := filepath.Dir(s.store.filename)
			s.store.Close()
			qualifyClosedFixtureBackup(t, dir, []string{physical}, func(restored *Store) {
				if _, err := restored.EnableSources(testContext, DefaultSourceLimits()); err != nil {
					t.Fatal("restored source module", err)
				}
			})
			mutator, err := openDB(filepath.Join(dir, "sync-state.sqlite"), false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = mutator.Exec(mutation); err != nil {
				mutator.Close()
				t.Fatal(err)
			}
			if err = mutator.Close(); err != nil {
				t.Fatal(err)
			}
			before, _ := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
			if opened, err := Open(testContext, dir); err == nil {
				opened.Close()
				t.Fatal("unknown/broken schema writable")
			}
			after, _ := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
			if before != after {
				t.Fatal("preflight changed bytes")
			}
		})
	}
	store, dir := stateFixture(t)
	store.Close()
	backup := qualifyClosedFixtureBackup(t, dir, nil, func(restored *Store) {
		if _, err := restored.Root(testContext, "root"); err != nil {
			t.Fatal("restored source migration baseline", err)
		}
	})
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^TestSourceMigrationCrashHelper$")
	cmd.Env = append(os.Environ(), "PLUTO_SOURCE_MIGRATION_CRASH="+dir)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 85 {
		t.Fatal(string(out), err)
	}
	backup.recordActualExit(t, "TestSourceMigrationCrashHelper", cmd.Process.Pid, exit.ExitCode())
	if err = preflight(testContext, filepath.Join(dir, "sync-state.sqlite")); err != nil {
		t.Fatal(err)
	}
	db, _ := openDB(filepath.Join(dir, "sync-state.sqlite"), true)
	var version int
	db.QueryRow("PRAGMA user_version").Scan(&version)
	db.Close()
	if version != 2 {
		t.Fatal(version)
	}
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
}
func TestSourceMigrationCrashHelper(t *testing.T) {
	dir := os.Getenv("PLUTO_SOURCE_MIGRATION_CRASH")
	if dir == "" {
		return
	}
	db, err := openDB(filepath.Join(dir, "sync-state.sqlite"), false)
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := db.BeginTx(testContext, nil)
	if _, err = tx.Exec(sourceSchema); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", SourceSchemaVersion)); err != nil {
		t.Fatal(err)
	}
	os.Exit(85)
}
func TestSourceQuotaPinnedWalAndBackupAdmission(t *testing.T) {
	s, w, _ := sourceFixture(t, "/synthetic")
	limits := s.limits
	limits.WALBytes = 8 << 20
	s.limits = limits
	reader, err := openDB(s.store.filename, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.BeginTx(testContext, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow("SELECT COUNT(*) FROM source_sets").Scan(&count); err != nil {
		t.Fatal(err)
	}
	// Pin a real read snapshot; repeated changed pages cannot be truncated away.
	for i := range 300 {
		if _, err = s.store.db.Exec("UPDATE source_sets SET config_digest=? WHERE set_id=?", hashBytes([]byte(fmt.Sprint(i))), w.SetID); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := s.DiskUsage(testContext)
	if err != nil || usage.WAL == 0 {
		t.Fatal(usage, err)
	}
	s.limits.WALBytes = usage.WAL + (1 << 19)
	if _, err = s.RecordSourceGap(testContext, w, "bounded refusal"); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("pinned WAL admitted growth", usage, err)
	}
	usageAfter, _ := s.DiskUsage(testContext)
	if usageAfter.WAL != usage.WAL {
		t.Fatal("refusal wrote WAL", usage, usageAfter)
	}
	tx.Rollback()
	s.limits = limits
	set, _ := s.Set(testContext, w.SetID)
	w = witness(set)
	if _, err = s.RecordSourceGap(testContext, w, "after reader closes"); err != nil {
		t.Fatal(err)
	}
}
