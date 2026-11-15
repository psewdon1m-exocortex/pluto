package syncstate

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestArtifactModuleWalMigrationAndLegacyBytes(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	binding := testBinding
	binding.SourceIdentity = "local-set"
	if err = s.BindRoot(testContext, binding); err != nil {
		t.Fatal(err)
	}
	sources, err := s.EnableSources(testContext, DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	set, err := sources.BindSourceSet(testContext, "local-set", hashBytes([]byte("config")), 0, []SourceSpec{{ID: "selected", SelectedPath: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if err = sources.AttachSourceSet(testContext, set.ID, set.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"config.json": []byte(`{"paused":true,"token":"fixture-only","sources":["/selected"]}`), "pause-state": []byte("paused\n")} {
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	rootBefore, _ := s.Root(testContext, "root")
	setBefore, _ := sources.Set(testContext, set.ID)
	u, err := sources.DiskUsage(testContext)
	if err != nil || u.WAL <= 0 {
		t.Fatal("fixture lacks committed WAL", u, err)
	}
	if _, err = s.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	rootAfter, _ := s.Root(testContext, "root")
	setAfter, _ := sources.Set(testContext, set.ID)
	if rootBefore != rootAfter || setBefore != setAfter || rootAfter.EngineReady {
		t.Fatal("migration activated/changed state")
	}
	var raw string
	if err = s.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=4").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err = json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "sync-state-backups", manifest["backup"].(string))
	if digest, err := fileDigest(backup); err != nil || digest != manifest["backupSHA256"] {
		t.Fatal(digest, err)
	}
	old, err := openDB(backup, true)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	var version int
	old.QueryRow("PRAGMA user_version").Scan(&version)
	var saved int
	old.QueryRow("SELECT COUNT(*) FROM source_sets WHERE set_id='local-set'").Scan(&saved)
	if version != 3 || saved != 1 {
		t.Fatal("WAL data absent in backup", version, saved)
	}
	for name, expected := range map[string]string{"config.json": `{"paused":true,"token":"fixture-only","sources":["/selected"]}`, "pause-state": "paused\n"} {
		bytes, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(bytes) != expected {
			t.Fatal("legacy bytes changed", name, err)
		}
	}
}
func TestArtifactModuleUnknownOrBrokenReadonlyPreservation(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "missing-table"}[broken], func(t *testing.T) {
			s, _, dir := artifactFixture(t)
			if broken {
				if _, err := s.db.Exec("DROP TABLE local_artifacts"); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.db.Exec("PRAGMA user_version=999"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(testContext, dir); err == nil {
				opened.Close()
				t.Fatal("unsupported state writable opened")
			}
			after, err := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
			if err != nil || before != after {
				t.Fatal("readonly refusal changed bytes", before, after, err)
			}
		})
	}
}
func TestArtifactActualV3ReaderRefusesBeforeWrite(t *testing.T) {
	reader := os.Getenv("PLUTO_ARTIFACT_V3_READER")
	if reader == "" {
		t.Skip("qualified separately with actual frozen schema 3 source binary")
	}
	s, _, dir := artifactFixture(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, "sync-state.sqlite")
	before, err := fileDigest(filename)
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(reader, dir).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 || string(output) != "sync state schema is unsupported\n" {
		t.Fatal(string(output), err)
	}
	after, err := fileDigest(filename)
	if err != nil || before != after {
		t.Fatal("old reader changed schema 4", before, after, err)
	}
}
func TestArtifactPhysicalQuotaPinnedWalRefusesPreservingBytes(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	limits := SourceLimits{64 << 20, 8 << 20, 64 << 20, 0}
	sources, err := s.EnableSources(testContext, limits)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	keeper, err := openDB(s.filename, true)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	tx, err := keeper.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow("SELECT COUNT(*) FROM artifact_scope").Scan(&n); err != nil {
		t.Fatal(err)
	}
	// Independent unqualified writer simulates the still-open aggregate quota
	// gate. Artifact admission must measure actual physical WAL, not PRAGMA 0.
	if _, err = s.db.Exec("UPDATE artifact_scope SET scope_id=scope_id"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("INSERT INTO local_artifacts(artifact_id,filename,phase,expected_bytes,capture_json) VALUES('fixture','fixture','GONE',0,zeroblob(6291456))"); err != nil {
		t.Fatal(err)
	}
	u, err := sources.DiskUsage(testContext)
	if err != nil || u.WAL < 6<<20 || u.PageSize < 512 {
		t.Fatal("pinned WAL not measured", u, err)
	}
	before, err := fileDigest(s.filename + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reserve(testContext, 1); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("pinned WAL admitted", u, err)
	}
	after, err := fileDigest(s.filename + "-wal")
	if err != nil || before != after {
		t.Fatal("quota refusal changed WAL", before, after, err)
	}
}
