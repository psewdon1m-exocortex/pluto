package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type testCaptureLimiter struct {
	mu     sync.Mutex
	bytes  int64
	reader chan struct{}
}

func newTestCaptureLimiter() *testCaptureLimiter {
	return &testCaptureLimiter{reader: make(chan struct{}, 1)}
}
func (l *testCaptureLimiter) RegisterCaptureArtifact(string, int64) error { return nil }
func (l *testCaptureLimiter) ReserveCapture(ctx context.Context, dir string, size int64) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if size < 0 || size > MaxFileBytes || l.bytes+size > MaxFileBytes {
		return nil, ErrSourceQuota
	}
	l.bytes += size
	return func() { l.mu.Lock(); l.bytes -= size; l.mu.Unlock() }, nil
}
func (l *testCaptureLimiter) AcquireCaptureReader(ctx context.Context) (func(), error) {
	select {
	case l.reader <- struct{}{}:
		return func() { <-l.reader }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestSourceGuardedSnapshotSameSizeRestoredMtimeAndStaleEvidence(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	os.WriteFile(name, []byte("one"), 0600)
	s, w, _ := sourceFixture(t, dir)
	scanSource(t, s, w, "first", nil)
	key := sourceDestination(name)
	e, _ := s.SourceEntry(testContext, w.SetID, key)
	limiter := newTestCaptureLimiter()
	v, err := CaptureGuarded(testContext, w, e, t.TempDir(), limiter)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err = s.RecordVerifiedSnapshot(testContext, w, v); err != nil {
		t.Fatal(err)
	}
	old, _ := s.Evidence(testContext, w.SetID, key)
	info, _ := os.Stat(name)
	os.WriteFile(name, []byte("two"), 0600)
	os.Chtimes(name, info.ModTime(), info.ModTime())
	scanSource(t, s, w, "second", nil)
	e, _ = s.SourceEntry(testContext, w.SetID, key)
	v2, err := CaptureGuarded(testContext, w, e, t.TempDir(), limiter)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if err = s.RecordVerifiedSnapshot(testContext, w, v2); err != nil {
		t.Fatal(err)
	}
	newEvidence, _ := s.Evidence(testContext, w.SetID, key)
	if old.SHA256 == newEvidence.SHA256 || newEvidence.SHA256 != hashBytes([]byte("two")) {
		t.Fatal("size/mtime suppressed hash", old, newEvidence)
	}
	if err = s.RecordVerifiedSnapshot(testContext, w, v); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("old capture reused", err)
	}
	if err = s.RecordVerifiedSnapshot(testContext, w, &VerifiedSnapshot{}); err == nil {
		t.Fatal("fabricated proof accepted")
	}
	next, err := s.RecordSourceGap(testContext, w, "fixture overflow")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordVerifiedSnapshot(testContext, next, v2); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("gap restored proof", err)
	}
	work, err := s.VerificationPage(testContext, next, "", 128)
	if err != nil || len(work) != 0 {
		t.Fatal("completed historical capture fabricated work", len(work), err)
	}
	// A new conservative scan, not a gap boolean, queues fresh verification.
	scanSource(t, s, next, "after-gap", nil)
	work, err = s.VerificationPage(testContext, next, "", 128)
	if err != nil || len(work) != 1 {
		t.Fatal(work, err)
	}
}
func TestSourceCaptureMutationLinksLimitsAndCancelCleanup(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	os.WriteFile(name, []byte("one"), 0600)
	s, w, _ := sourceFixture(t, dir)
	scanSource(t, s, w, "scan", nil)
	e, _ := s.SourceEntry(testContext, w.SetID, sourceDestination(name))
	limiter := newTestCaptureLimiter()
	spool := t.TempDir()
	_, err := captureGuarded(testContext, w, e, spool, limiter, func() { os.WriteFile(name, []byte("two"), 0600) })
	if !errors.Is(err, ErrCaptureChanged) {
		t.Fatal("raced capture accepted", err)
	}
	files, _ := os.ReadDir(spool)
	if len(files) != 0 || limiter.bytes != 0 {
		t.Fatal("capture leak", len(files), limiter.bytes)
	}
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("link"), 0600)
	link := filepath.Join(dir, "link")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	scanSource(t, s, w, "links", nil)
	entry, _ := s.SourceEntry(testContext, w.SetID, sourceDestination(link))
	v, err := CaptureGuarded(testContext, w, entry, spool, limiter)
	if err != nil {
		t.Fatal(err)
	}
	if v.Evidence().SHA256 != hashBytes([]byte("link")) {
		t.Fatal(v.Evidence())
	}
	v.Close()
	if err = os.Symlink(dir, filepath.Join(dir, "directory-link")); err != nil {
		t.Fatal(err)
	}
	if _, err = DescribeSource(filepath.Join(dir, "directory-link"), "bad", 0); err == nil {
		t.Fatal("directory symlink followed")
	}
	fifo := filepath.Join(dir, "fifo")
	syscall.Mkfifo(fifo, 0600)
	if _, err = DescribeSource(fifo, "fifo", 0); err == nil {
		t.Fatal("special file accepted")
	}
	large := filepath.Join(dir, "large")
	f, _ := os.Create(large)
	f.Truncate(MaxFileBytes + 1)
	f.Close()
	d, _ := DescribeSource(large, "large", 0)
	observation, _ := ObserveSourceIncarnation(dir)
	oversize := SourceEntry{SourceDescriptor: d, SetID: w.SetID, SourceID: "source", SourceRootPath: dir, SourceObject: observation.Object(), SourceIncarnation: 1, Generation: 1, VerificationRequest: 1}
	if _, err = CaptureGuarded(testContext, w, oversize, spool, limiter); err == nil {
		t.Fatal("oversize capture")
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err = CaptureGuarded(ctx, w, entry, spool, limiter); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	files, _ = os.ReadDir(spool)
	if len(files) != 0 || limiter.bytes != 0 {
		t.Fatal("cancel leaked capture")
	}
}
func TestSourceHardlinkDestinationsKeepIndependentContentEvidence(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	if err := os.WriteFile(first, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, second); err != nil {
		t.Fatal(err)
	}
	s, w, _ := sourceFixture(t, dir)
	scanSource(t, s, w, "first", nil)
	var identity string
	for _, name := range []string{first, second} {
		entry, err := s.SourceEntry(testContext, w.SetID, sourceDestination(name))
		if err != nil || entry.Ambiguous {
			t.Fatal(entry, err)
		}
		if identity == "" {
			identity = entry.FileIdentity
		} else if identity != entry.FileIdentity {
			t.Fatal("fixture not a hardlink")
		}
		v, err := CaptureGuarded(testContext, w, entry, t.TempDir(), newTestCaptureLimiter())
		if err != nil {
			t.Fatal(err)
		}
		if err = s.RecordVerifiedSnapshot(testContext, w, v); err != nil {
			t.Fatal(err)
		}
		if err = v.Close(); err != nil {
			t.Fatal(err)
		}
	}
	stat, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(second, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(second, stat.ModTime(), stat.ModTime()); err != nil {
		t.Fatal(err)
	}
	scanSource(t, s, w, "next", nil)
	work, err := s.VerificationPage(testContext, w, "", 128)
	if err != nil || len(work) != 2 {
		t.Fatal("hardlink destination work collapsed", len(work), err)
	}
	for _, item := range work {
		v, err := CaptureGuarded(testContext, w, item.Entry, t.TempDir(), newTestCaptureLimiter())
		if err != nil {
			t.Fatal(err)
		}
		if v.Evidence().SHA256 != hashBytes([]byte("two")) {
			t.Fatal("hardlink stale content evidence")
		}
		v.Close()
	}
}
func TestSourceStreamingBeforeScanEOFAndTamperedSnapshot(t *testing.T) {
	dir := t.TempDir()
	for i := range 300 {
		os.WriteFile(filepath.Join(dir, time.Unix(int64(i), 0).Format("150405")), []byte("one"), 0600)
	}
	s, w, _ := sourceFixture(t, dir)
	verifiedBeforeEOF := false
	limiter := newTestCaptureLimiter()
	scanSource(t, s, w, "stream", func(c FrontierClaim) error {
		if verifiedBeforeEOF {
			return nil
		}
		work, err := s.VerificationPage(testContext, w, "", 1)
		if err != nil {
			return err
		}
		if len(work) == 0 {
			return nil
		}
		scan, _ := s.Scan(testContext, "stream")
		if scan.Status != "DISCOVERING" || c.Token == "" {
			return errors.New("verification started after iterator ended")
		}
		v, err := CaptureGuarded(testContext, w, work[0].Entry, t.TempDir(), limiter)
		if err != nil {
			return err
		}
		defer v.Close()
		if err = s.RecordVerifiedSnapshot(testContext, w, v); err != nil {
			return err
		}
		verifiedBeforeEOF = true
		return nil
	})
	if !verifiedBeforeEOF {
		t.Fatal("no early verified file")
	}
	work, _ := s.VerificationPage(testContext, w, "", 1)
	v, err := CaptureGuarded(testContext, w, work[0].Entry, t.TempDir(), limiter)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	os.Chmod(v.filename, 0600)
	os.WriteFile(v.filename, []byte("bad"), 0600)
	if err = s.RecordVerifiedSnapshot(testContext, w, v); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("tampered sealed bytes acknowledged", err)
	}
	var n int
	s.store.db.QueryRow("SELECT COUNT(*) FROM source_verification").Scan(&n)
	if n != 299 {
		t.Fatal("tamper lost pending work", n)
	}
}
func TestSourceCapturePermissionFixture(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("qualified separately as UID65534")
	}
	dir := t.TempDir()
	name := filepath.Join(dir, "denied")
	os.WriteFile(name, []byte("one"), 0000)
	defer os.Chmod(name, 0600)
	d, err := DescribeSource(name, "denied", 0)
	if err != nil {
		t.Fatal(err)
	}
	observation, _ := ObserveSourceIncarnation(dir)
	entry := SourceEntry{SourceDescriptor: d, SetID: "set", SourceID: "source", SourceRootPath: dir, SourceObject: observation.Object(), SourceIncarnation: 1, Generation: 1, VerificationRequest: 1}
	w := SourceWitness{SetID: "set", OwnerID: "owner", Revision: 1}
	if _, err = CaptureGuarded(testContext, w, entry, t.TempDir(), newTestCaptureLimiter()); !errors.Is(err, os.ErrPermission) {
		t.Fatal("unreadable file captured")
	}
}
func TestSourceScanPermissionIsIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("qualified separately as UID65534")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "unreadable")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	s, w, _ := sourceFixture(t, source)
	if err := os.Chmod(source, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(source, 0700)
	if _, err := s.BeginScan(testContext, w, "source", "denied"); err != nil {
		t.Fatal(err)
	}
	c, err := s.ClaimScanFrontier(testContext, w, "denied")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ScanClaim(testContext, c, nil); !errors.Is(err, os.ErrPermission) {
		t.Fatal("permission failure hidden", err)
	}
	scan, _ := s.Scan(testContext, "denied")
	if scan.Status != "INCOMPLETE" {
		t.Fatal(scan)
	}
	if err = s.CompleteScanScope(testContext, w, "denied"); !errors.Is(err, ErrSourceIncomplete) {
		t.Fatal(err)
	}
}
func TestSourceCaptureLateGenerationKeepsWork(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	os.WriteFile(name, []byte("one"), 0600)
	s, w, _ := sourceFixture(t, dir)
	scanSource(t, s, w, "one", nil)
	entry, _ := s.SourceEntry(testContext, w.SetID, sourceDestination(name))
	v, err := CaptureGuarded(testContext, w, entry, t.TempDir(), newTestCaptureLimiter())
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	scanSource(t, s, w, "two", nil)
	if err = s.RecordVerifiedSnapshot(testContext, w, v); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	if _, err = s.Evidence(testContext, w.SetID, entry.Destination); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("late capture stored", err)
	}
}
