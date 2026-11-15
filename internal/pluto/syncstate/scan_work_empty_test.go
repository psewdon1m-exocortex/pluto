package syncstate

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerificationEmptyQueuePreservesScanAndFrontier(t *testing.T) {
	s, w, _ := sourceFixture(t, t.TempDir())
	scan, err := s.BeginScan(testContext, w, "source", "empty-queue-scan")
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.VerificationPageForScan(testContext, w, scan.ID, "", MaxSourcePage)
	if err != nil || len(page) != 0 {
		t.Fatal("empty verification queue", page, err)
	}
	after, err := s.Scan(testContext, scan.ID)
	if err != nil || after != scan {
		t.Fatal("read-only empty page changed scan", after, err)
	}
	var frontier int
	var token string
	if err = s.store.db.QueryRow("SELECT count(*),min(claim_token) FROM source_frontier WHERE scan_id=?", scan.ID).Scan(&frontier, &token); err != nil || frontier != 1 || token != "" {
		t.Fatal("empty page consumed frontier ownership", frontier, token, err)
	}
	var queued int
	if err = s.store.db.QueryRow("SELECT count(*) FROM source_verification WHERE set_id=?", w.SetID).Scan(&queued); err != nil || queued != 0 {
		t.Fatal("empty page changed verification work", queued, err)
	}
}

func TestVerificationEmptyQueueSeesLaterScanAndPreservesReceipt(t *testing.T) {
	dir := t.TempDir()
	s, w, _ := sourceFixture(t, dir)
	scanSource(t, s, w, "empty-scan", nil)
	if page, err := s.VerificationPageForScan(testContext, w, "empty-scan", "", MaxSourcePage); err != nil || len(page) != 0 {
		t.Fatal("initial empty scan", page, err)
	}
	name := filepath.Join(dir, "file")
	if err := os.WriteFile(name, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	scanSource(t, s, w, "later-scan", nil)
	page, err := s.VerificationPageForScan(testContext, w, "later-scan", "", MaxSourcePage)
	if err != nil || len(page) != 1 || page[0].Entry.Destination != sourceDestination(name) {
		t.Fatal("work added after empty page was lost", page, err)
	}
	if old, err := s.VerificationPageForScan(testContext, w, "empty-scan", "", MaxSourcePage); err != nil || len(old) != 0 {
		t.Fatal("new work escaped its current scan", old, err)
	}
	v, err := CaptureGuarded(testContext, w, page[0].Entry, t.TempDir(), newTestCaptureLimiter())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err = s.RecordVerifiedSnapshot(testContext, w, v); err != nil {
		t.Fatal(err)
	}
	before, err := s.Evidence(testContext, w.SetID, page[0].Entry.Destination)
	if err != nil {
		t.Fatal(err)
	}
	if page, err = s.VerificationPageForScan(testContext, w, "later-scan", "", MaxSourcePage); err != nil || len(page) != 0 {
		t.Fatal("verified work did not drain", page, err)
	}
	after, err := s.Evidence(testContext, w.SetID, before.Destination)
	if err != nil || before != after {
		t.Fatal("empty page changed valid snapshot receipt", before, after, err)
	}
}

func TestVerificationEmptyQueueDoesNotWaiveWitnessOrScanValidation(t *testing.T) {
	s, w, _ := sourceFixture(t, t.TempDir())
	if _, err := s.BeginScan(testContext, w, "source", "empty-queue-scan"); err != nil {
		t.Fatal(err)
	}
	stale := w
	stale.OwnerSequence++
	if _, err := s.VerificationPageForScan(testContext, stale, "empty-queue-scan", "", MaxSourcePage); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("empty queue accepted stale owner", err)
	}
	if _, err := s.VerificationPageForScan(testContext, w, "missing-scan", "", MaxSourcePage); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("empty queue accepted a missing scan", err)
	}
	if _, err := s.VerificationPageForScan(testContext, w, "empty-queue-scan", "", MaxSourcePage+1); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("empty queue waived page capacity", err)
	}
}
