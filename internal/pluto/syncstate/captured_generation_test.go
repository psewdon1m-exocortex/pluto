package syncstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Model an observer/filesystem that cannot distinguish both content generations
// by metadata. Real source and private sealed bytes are used; only the recorded
// observation generation is held constant by the coarse-observation fixture.
// This does not claim that Linux lets an unprivileged caller restore ctime.
func TestCapturedGenerationPromotionFromCoarseObservationFixture(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	if err := os.WriteFile(name, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	sources, w, _ := sourceFixture(t, dir)
	scanSource(t, sources, w, "first", nil)
	a, err := sources.store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	key := sourceDestination(name)
	entry, err := sources.SourceEntry(testContext, w.SetID, key)
	if err != nil {
		t.Fatal(err)
	}
	firstLimiter := &registryFixtureLimiter{a: a, reader: newTestCaptureLimiter()}
	first, err := CaptureGuarded(testContext, w, entry, a.Directory(), firstLimiter)
	if err != nil {
		t.Fatal(err)
	}
	if err = sources.RecordVerifiedSnapshot(testContext, w, first); err != nil {
		t.Fatal(err)
	}
	old := first.Evidence()
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(name, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	scanSource(t, sources, w, "second", nil)
	entry, err = sources.SourceEntry(testContext, w.SetID, key)
	if err != nil {
		t.Fatal(err)
	}
	// Current source guard remains the exact real current stat/link identity. The
	// fixture holds the historical generation stable as a coarse observer would.
	entry.Generation = old.EntryGeneration
	raw, _ := json.Marshal(entry)
	if _, err = sources.store.db.Exec("UPDATE source_entries SET generation=?,descriptor_json=? WHERE set_id=? AND destination=?", entry.Generation, string(raw), w.SetID, key); err != nil {
		t.Fatal(err)
	}
	limiter := &registryFixtureLimiter{a: a, reader: newTestCaptureLimiter()}
	v, err := CaptureGuarded(testContext, w, entry, a.Directory(), limiter)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.Evidence().SHA256 == old.SHA256 {
		t.Fatal("real changed bytes not captured")
	}
	if err = sources.RecordVerifiedSnapshot(testContext, w, v); err != nil {
		t.Fatal(err)
	}
	current, err := sources.SourceEntry(testContext, w.SetID, key)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := sources.Evidence(testContext, w.SetID, key)
	if err != nil {
		t.Fatal(err)
	}
	if current.Generation != old.EntryGeneration+1 || v.Evidence() != persisted || persisted.EntryGeneration != current.Generation {
		t.Fatal("private capture generation was not atomically promoted with source evidence", current.Generation, v.Evidence(), persisted)
	}
	var captureJSON string
	if err = sources.store.db.QueryRow("SELECT capture_json FROM local_artifacts WHERE artifact_id=?", v.Evidence().SnapshotID).Scan(&captureJSON); err != nil {
		t.Fatal(err)
	}
	var captured artifactCapture
	if err = json.Unmarshal([]byte(captureJSON), &captured); err != nil {
		t.Fatal(err)
	}
	if captured.SnapshotEvidence != persisted {
		t.Fatal("retained sealed registry proof generation differs", captured.SnapshotEvidence, persisted)
	}
}
