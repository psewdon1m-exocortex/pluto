package syncstate

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRemoteModuleFiveWalBackupKeepsImmutableOperation(t *testing.T) {
	s, w, _ := sourceFixture(t, t.TempDir())
	binding := testBinding
	binding.SourceIdentity = w.SetID
	if err := s.store.BindRoot(testContext, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	capture(t, s.store, fileObservation("file", "file"))
	original := planned(t, s.store, "immutable", "file")
	usage, err := s.DiskUsage(testContext)
	if err != nil || usage.WAL == 0 {
		t.Fatal("fixture lacks committed WAL", usage, err)
	}
	if _, err = s.store.EnableRemoteImport(testContext); err != nil {
		t.Fatal(err)
	}
	retained, err := s.store.Operation(testContext, "immutable")
	if err != nil || !reflect.DeepEqual(original, retained) {
		t.Fatal("migration rewrote immutable operation", retained, err)
	}
	var raw string
	if err = s.store.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=5").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if json.Unmarshal([]byte(raw), &manifest) != nil {
		t.Fatal(raw)
	}
	db, err := openDB(filepath.Join(filepath.Dir(s.store.filename), "sync-state-backups", manifest["backup"].(string)), true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	backupOp, err := readOperation(testContext, db, "immutable")
	if err != nil || !reflect.DeepEqual(original, backupOp) {
		t.Fatal("WAL-backed operation missing from backup", backupOp, err)
	}
}

func TestRemoteActualOldReaderRefusesModuleFivePreservingBytes(t *testing.T) {
	reader := os.Getenv("PLUTO_REMOTE_V4_READER")
	if reader == "" {
		t.Skip("dedicated actual frozen module4 reader gate")
	}
	r, _, _ := remoteFixture(t)
	dir := filepath.Dir(r.store.filename)
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(reader, dir).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 || !strings.Contains(string(out), "unsupported") {
		t.Fatal("actual old reader did not refuse module5", string(out), err)
	}
	after, _ := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
	if after != before {
		t.Fatal("old refusal rewrote new schema")
	}
}
