package syncstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func scopeScanOptions(t *testing.T, r *RemoteImport, w SourceWitness, s *fixtureCapturedSession) CapturedScanOptions {
	t.Helper()
	o := scanOptions(t, r, w, s)
	o.Capture = nil
	o.CaptureAndUse = func(ctx context.Context, w SourceWitness, e SourceEntry, use func(*VerifiedSnapshot) error) error {
		if _, err := r.store.artifacts.PruneDisposed(ctx, MaxSourcePage); err != nil {
			return err
		}
		return CaptureAndUseGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()}, func(v *VerifiedSnapshot) error {
			record, err := r.store.artifacts.Record(ctx, v.Evidence().SnapshotID)
			if err != nil || record.Phase != ArtifactSealed || record.SHA256 != v.Evidence().SHA256 {
				t.Fatalf("consumer ran before durable seal: %+v %v", record, err)
			}
			return use(v)
		})
	}
	return o
}

func TestCaptureScopePipelineInitialRepeatAndChangedBytes(t *testing.T) {
	r, w, s, dir := scanExecutorFixture(t, 3)
	for round, uploaded := range []int64{3, 0, 1} {
		if round == 2 {
			file := filepath.Join(dir, "file-0000")
			info, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(file, []byte("two"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.Chtimes(file, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}
		before := CaptureMetricSnapshot()
		report, err := r.RunCapturedScan(testContext, scopeScanOptions(t, r, w, s))
		m := CaptureMetricSnapshot().Since(before)
		if err != nil || !report.Complete || report.Verified != 3 || report.Uploaded != uploaded || report.Adopted != 3-uploaded || report.Failed != 0 {
			t.Fatal(round, report, err)
		}
		if m.SourceReads != 3 || m.SourceHashBytes != 9 || m.PrivateVerificationReads != 3 || m.PrivateVerificationBytes != 9 || m.TransportHashBytes != uploaded*3 {
			t.Fatal("source, private verification and transport must each retain their guarantees", round, m)
		}
		charge, err := r.store.artifacts.Charge(testContext)
		if err != nil || charge != 0 {
			t.Fatal("joined scope leaked reservation", charge, err)
		}
	}
}

func TestCaptureScopePipelineLostAckRetainsExactOperation(t *testing.T) {
	r, w, s, _ := scanExecutorFixture(t, 1)
	s.lostAck.Store(true)
	first, err := r.RunCapturedScan(testContext, scopeScanOptions(t, r, w, s))
	if err == nil || first.Failed != 1 || s.writes.Load() != 1 {
		t.Fatal(first, err)
	}
	page, err := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if err != nil || len(page) != 1 {
		t.Fatal(page, err)
	}
	original := page[0]
	before := CaptureMetricSnapshot()
	second, err := r.RunCapturedScan(testContext, scopeScanOptions(t, r, w, s))
	if err != nil || second.Recovered != 1 || second.Uploaded != 0 || s.writes.Load() != 1 || CaptureMetricSnapshot().Since(before).SourceReads != 0 {
		t.Fatal(second, err)
	}
	stored, err := r.store.Operation(testContext, original.OperationID)
	if err != nil || stored.Stage != "CLIENT_ACKED" || stored.IntentFingerprint != original.IntentFingerprint || stored.SnapshotID != original.SnapshotID {
		t.Fatal(stored, err)
	}
	charge, err := r.store.artifacts.Charge(testContext)
	if err != nil || charge != 0 {
		t.Fatal(charge, err)
	}
}

func TestCaptureScopePipelineTamperGapAndCancellation(t *testing.T) {
	for _, mode := range []string{"bytes-restored-mtime", "replace", "permissions", "gap", "cancel", "unused"} {
		t.Run(mode, func(t *testing.T) {
			r, w, old, _, _ := capturedRemoteFixture(t)
			key := old.Evidence().Destination
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			scanSource(t, r.sources, w, "new-scope", nil)
			entry, err := r.sources.SourceEntry(testContext, w.SetID, key)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(testContext)
			defer cancel()
			var seen *VerifiedSnapshot
			err = CaptureAndUseGuarded(ctx, w, entry, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()}, func(v *VerifiedSnapshot) error {
				seen = v
				if err := WithValidatedCapture(ctx, v, func() error { return nil }); !errors.Is(err, ErrIdentityConflict) {
					t.Fatal("nested scope admitted", err)
				}
				switch mode {
				case "bytes-restored-mtime":
					if err := os.Chmod(v.filename, 0600); err != nil {
						return err
					}
					if err := os.WriteFile(v.filename, []byte("two"), 0400); err != nil {
						return err
					}
					if err := os.Chmod(v.filename, 0400); err != nil {
						return err
					}
					if err := os.Chtimes(v.filename, v.sealed.ModTime(), v.sealed.ModTime()); err != nil {
						return err
					}
				case "replace":
					if err := os.Rename(v.filename, v.filename+".old"); err != nil {
						return err
					}
					if err := os.WriteFile(v.filename, []byte("one"), 0400); err != nil {
						return err
					}
				case "permissions":
					if err := os.Chmod(v.filename, 0600); err != nil {
						return err
					}
				case "gap":
					if _, err := r.sources.RecordSourceGap(ctx, w, "gap inside sealed scope"); err != nil {
						return err
					}
				case "cancel":
					cancel()
				case "unused":
					return nil // Lexical owner must dispose even without explicit Close.
				}
				return r.sources.RecordVerifiedSnapshot(ctx, w, v)
			})
			if mode == "unused" {
				if err != nil || seen == nil || !seen.closed {
					t.Fatal("unused scope leaked", err)
				}
			} else if mode == "gap" {
				if !errors.Is(err, ErrStaleGeneration) {
					t.Fatal(mode, err)
				}
			} else if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(mode, err)
				}
			} else if !errors.Is(err, ErrInvalidReceipt) {
				t.Fatal(mode, err)
			}
			if seen != nil && seen.validation != nil {
				t.Fatal("private descriptor escaped lexical scope")
			}
		})
	}
}

func TestCaptureScopePipelineCancelJoinsTransport(t *testing.T) {
	r, w, base, _ := scanExecutorFixture(t, 2)
	s := &cancelledCapturedSession{base: base, started: make(chan struct{}, 2)}
	o := scopeScanOptions(t, r, w, base)
	o.Session = s
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan struct{})
	var err error
	go func() { _, err = r.RunCapturedScan(ctx, o); close(done) }()
	for range 2 {
		<-s.started
	}
	cancel()
	<-done
	if err == nil || s.active.Load() != 0 {
		t.Fatal("unjoined transport", err)
	}
	page, e := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if e != nil || len(page) != 2 {
		t.Fatal("uncertain original operations lost", page, e)
	}
	for _, op := range page {
		if op.Stage != "SUBMITTED" {
			t.Fatal("uncertain operation changed", op.Stage)
		}
		if _, e := r.store.artifacts.RecoveryOperation(testContext, op.SnapshotID); e != nil {
			t.Fatal("retained recovery bytes lost", e)
		}
	}
}
