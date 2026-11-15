package syncstate

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestCapturedCoarsePromotionRefusesPendingNonDestinationEntry(t *testing.T) {
	for _, stage := range []string{"PLANNED", "SEALED", "SUBMITTED"} {
		t.Run(stage, func(t *testing.T) {
			r, w, first, entryID, _ := capturedRemoteFixture(t)
			old := first.Evidence()
			intent := fixtureIntent(t, r.store, "retained-original", entryID)
			// Retained historical schema4 intent is not bound to this new module5
			// projection's capture. Recovery keeps that old snapshot ID unchanged.
			fixtureLegacyPending(t, r.store, intent, stage, old.SHA256, "historical-snapshot")
			original, err := r.store.Operation(testContext, intent.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(first.physicalPath)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(first.physicalPath, []byte("two"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.Chtimes(first.physicalPath, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			scanSource(t, r.sources, w, "coarse-second", nil)
			source, err := r.sources.SourceEntry(testContext, w.SetID, old.Destination)
			if err != nil {
				t.Fatal(err)
			}
			source.Generation = old.EntryGeneration
			if _, err = r.store.db.Exec("UPDATE source_entries SET generation=?,descriptor_json=? WHERE set_id=? AND destination=?", source.Generation, string(mustJSON(source)), w.SetID, old.Destination); err != nil {
				t.Fatal(err)
			}
			capture, err := CaptureGuarded(testContext, w, source, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			before := capture.Evidence()
			if err = r.sources.RecordVerifiedSnapshot(testContext, w, capture); !errors.Is(err, ErrArtifactRetained) {
				t.Fatal("pending intent did not block proof rewrite", err)
			}
			current, _ := r.sources.SourceEntry(testContext, w.SetID, old.Destination)
			prior, _ := r.sources.Evidence(testContext, w.SetID, old.Destination)
			after, _ := r.store.Operation(testContext, intent.OperationID)
			if current.Generation != source.Generation || capture.Evidence() != before || prior != old || !reflect.DeepEqual(original, after) {
				t.Fatal("failed promotion partially committed", current, capture.Evidence(), prior, after)
			}
			var raw string
			if err = r.store.db.QueryRow("SELECT capture_json FROM local_artifacts WHERE artifact_id=?", before.SnapshotID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var stored artifactCapture
			if err = json.Unmarshal([]byte(raw), &stored); err != nil || stored.SnapshotEvidence != before {
				t.Fatal("sealed proof rewritten on refusal", stored, err)
			}
		})
	}
}
