package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStreamV2P02SourceProofHashesBytesAndRejectsChanges(t *testing.T) {
	_, op, _, data := p02V2TransportFixture(t)
	source := op.Stream.Source
	source.Kind = "file"
	source.Presence = "PRESENT"
	before := CaptureMetricSnapshot()
	proof, err := hashStableStreamSource(testContext, source, p02V2Acquire)
	if err != nil || proof.sha256 != hashBytes(data) || !proof.current(source) {
		t.Fatal("guarded full hash failed", err)
	}
	if CaptureMetricSnapshot().SourceHashBytes-before.SourceHashBytes != int64(len(data)) {
		t.Fatal("full hash was not counted")
	}
	link := proof.link
	proof.link = "different-link-guard"
	if proof.current(source) {
		t.Fatal("changed path link guard accepted")
	}
	proof.link = link
	changed := source
	changed.Generation++
	if proof.current(changed) {
		t.Fatal("proof rebound to new source generation")
	}
	old := source.PhysicalPath + ".old"
	if err = os.Rename(source.PhysicalPath, old); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(source.PhysicalPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if proof.current(source) {
		t.Fatal("same bytes at replacement inode accepted")
	}
	if _, err = hashStableStreamSource(testContext, source, p02V2Acquire); !errors.Is(err, ErrCaptureChanged) {
		t.Fatal(err)
	}
	if err = os.Remove(source.PhysicalPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(old), source.PhysicalPath); err != nil {
		t.Fatal(err)
	}
	if proof.current(source) {
		t.Fatal("replacement symlink accepted")
	}
}

func TestStreamV2P02LargeNoopRechecksBytesAndRetainsNewerWork(t *testing.T) {
	r, w, s, fixture, dir := stage3Wire(t, 1)
	if report, err := stage3HTTPScan(t, r, w, s); err != nil || report.Uploaded != 1 {
		t.Fatal(report, err)
	}
	filename := filepath.Join(dir, "file-000")
	if err := os.Truncate(filename, MaxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	scanSource(t, r.sources, w, "p02-large-noop", nil)
	source, err := r.sources.SourceEntry(testContext, w.SetID, "tree/nested/file-000")
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.ProjectSourcePath(testContext, w, "root", source)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := hashStableStreamSource(testContext, source, p02V2Acquire)
	if err != nil {
		t.Fatal(err)
	}
	// Seed the historical published large-file agreement; the exercised no-op
	// must independently hash the actual sparse source and consume exact work.
	err = r.sources.change(testContext, MaxSourcePageBytes, func(tx *sql.Tx) error {
		base, e := readJSON[Baseline](testContext, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", "root", id)
		if e != nil {
			return e
		}
		base.SizeBytes = source.SizeBytes
		base.SHA256 = proof.sha256
		base.CaptureProof = nil
		if _, e = tx.Exec("UPDATE baselines SET descriptor_json=? WHERE root_id=? AND entry_id=?", string(mustJSON(base)), "root", id); e != nil {
			return e
		}
		candidate, e := readCandidate(testContext, tx, "root")
		if e != nil {
			return e
		}
		remote, e := readJSON[RemoteEntry](testContext, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", "root", candidate.Generation, base.NodeID)
		if e != nil {
			return e
		}
		remote.SizeBytes = source.SizeBytes
		remote.SHA256 = proof.sha256
		if _, e = tx.Exec("UPDATE remote_entries SET descriptor_json=? WHERE root_id=? AND generation=? AND node_id=?", string(mustJSON(remote)), "root", candidate.Generation, base.NodeID); e != nil {
			return e
		}
		fixture.base.mu.Lock()
		d := fixture.base.nodes[base.NodeID]
		d.SizeBytes = remoteDecimal(source.SizeBytes)
		d.ContentSHA256 = &proof.sha256
		fixture.base.nodes[base.NodeID] = d
		fixture.base.mu.Unlock()
		local, e := readJSON[Observation](testContext, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", "root", id)
		if e != nil {
			return e
		}
		local.SizeBytes = source.SizeBytes
		local.MTimeNS = source.MTimeNS
		local.SHA256 = proof.sha256
		local.HashGeneration = local.Generation
		if _, e = tx.Exec("UPDATE local_entries SET descriptor_json=? WHERE root_id=? AND entry_id=?", string(mustJSON(local)), "root", id); e != nil {
			return e
		}
		_, e = tx.Exec("INSERT INTO dirty_entries(root_id,entry_id,reasons,observed_generation,remote_seq,first_dirty_ms) VALUES(?,?,?,?,?,1) ON CONFLICT(root_id,entry_id) DO UPDATE SET observed_generation=excluded.observed_generation", "root", id, "newer-work", local.Generation+1, candidate.Position)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	s.features["stream-upload-v1"] = true
	s.features["scale-transfer-v2"] = true
	s.streamFileBytes = streamV2MaximumFileBytes
	before := CaptureMetricSnapshot()
	network := s.Metrics()
	handled, uploaded, err := s.tryStream(testContext, w, source, id, p02V2Acquire)
	if err != nil || !handled || uploaded {
		t.Fatal("large no-op reported upload/failure", handled, uploaded, err)
	}
	if CaptureMetricSnapshot().SourceHashBytes-before.SourceHashBytes != source.SizeBytes {
		t.Fatal("no-op skipped full source hash")
	}
	if network != s.Metrics() {
		t.Fatal("no-op issued HTTP")
	}
	var work, streams, newer int
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM source_verification WHERE set_id=? AND destination=?", w.SetID, source.Destination).Scan(&work); err != nil {
		t.Fatal(err)
	}
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM operations WHERE kind='STREAM_PUT'").Scan(&streams); err != nil {
		t.Fatal(err)
	}
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM dirty_entries WHERE root_id=? AND entry_id=?", "root", id).Scan(&newer); err != nil {
		t.Fatal(err)
	}
	if work != 0 || streams != 0 || newer != 1 {
		t.Fatal("no-op lost current/newer work boundary", work, streams, newer)
	}
	scanSource(t, r.sources, w, "p02-large-unavailable", nil)
	source, err = r.sources.SourceEntry(testContext, w.SetID, source.Destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.store.db.Exec("UPDATE remote_entries SET descriptor_json=json_set(descriptor_json,'$.Availability','UNAVAILABLE') WHERE root_id=? AND json_extract(descriptor_json,'$.Kind')='file'", "root"); err != nil {
		t.Fatal(err)
	}
	before = CaptureMetricSnapshot()
	if handled, _, err = s.tryStream(testContext, w, source, id, p02V2Acquire); handled || !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal("unavailable remote accepted as no-op", handled, err)
	}
	if CaptureMetricSnapshot().SourceHashBytes != before.SourceHashBytes {
		t.Fatal("unqualified remote started source read")
	}
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM source_verification WHERE set_id=? AND destination=?", w.SetID, source.Destination).Scan(&work); err != nil || work != 1 {
		t.Fatal("unavailable remote lost work", work, err)
	}
}

func TestStreamV2P02SourceProofCancellationReleasesAdmission(t *testing.T) {
	_, op, _, _ := p02V2TransportFixture(t)
	source := op.Stream.Source
	source.Kind = "file"
	source.Presence = "PRESENT"
	ctx, cancel := context.WithCancel(testContext)
	released := false
	_, err := hashStableStreamSource(ctx, source, func(context.Context) (func(), error) { cancel(); return func() { released = true }, nil })
	if !errors.Is(err, context.Canceled) || !released {
		t.Fatal("source cancellation leaked admission", err, released)
	}
}
