package syncstate

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
)

func TestCapturedStreamRejectsPartialReadAndJoinsUser(t *testing.T) {
	_, _, v, _, _ := capturedRemoteFixture(t)
	if err := streamCaptured(testContext, v, func(reader io.Reader) error { var one [1]byte; _, err := reader.Read(one[:]); return err }); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("partial transport acknowledged", err)
	}
	if err := streamCaptured(testContext, v, func(reader io.Reader) error { _, err := io.Copy(io.Discard, reader); return err }); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedExecutorAtomicSubmitRollbackBeforeTransport(t *testing.T) {
	r, w, v, entry, _, op := createCapturedOperationFixture(t)
	if _, err := r.store.db.Exec("DELETE FROM operations WHERE operation_id=?", op.OperationID); err != nil {
		t.Fatal(err)
	}
	s := &fixtureCapturedSession{r: r, results: make(map[string]CapturedPublication), published: make(chan struct{})}
	r.testPoint = func(p string) error {
		if p == "capture.before_submit" {
			return context.Canceled
		}
		return nil
	}
	out, err := r.ExecuteCaptured(testContext, w, "root", entry, v, s, remoteNow)
	if !errors.Is(err, context.Canceled) || out.Uploaded || s.writes.Load() != 0 {
		t.Fatal(out, err)
	}
	pending, err := r.store.PendingPage(testContext, "root", "", 128)
	if err != nil || len(pending) != 0 {
		t.Fatal("partially staged identity escaped", pending, err)
	}
	charge, err := r.store.artifacts.Charge(testContext)
	if err != nil || charge != 0 {
		t.Fatal("rollback artifact charge", charge, err)
	}
	r.testPoint = nil
}

type cancelledCapturedSession struct {
	base    *fixtureCapturedSession
	started chan struct{}
	active  atomic.Int64
}

func (s *cancelledCapturedSession) Authority(ctx context.Context) (*RemoteAuthority, error) {
	return s.base.Authority(ctx)
}
func (s *cancelledCapturedSession) Publish(ctx context.Context, op Operation, reader io.Reader) (CapturedPublication, error) {
	s.active.Add(1)
	defer s.active.Add(-1)
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return CapturedPublication{}, err
	}
	s.started <- struct{}{}
	<-ctx.Done()
	return CapturedPublication{}, ctx.Err()
}
func (s *cancelledCapturedSession) Recover(context.Context, Operation) (*CapturedPublication, error) {
	return nil, nil
}
func TestCapturedScanCancelDuringTransportRetainsOriginalNoReplacement(t *testing.T) {
	r, w, base, _ := scanExecutorFixture(t, 2)
	s := &cancelledCapturedSession{base: base, started: make(chan struct{}, 2)}
	o := scanOptions(t, r, w, base)
	o.Session = s
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan struct{})
	var report CapturedScanReport
	var err error
	go func() { report, err = r.RunCapturedScan(ctx, o); close(done) }()
	for range 2 {
		<-s.started
	}
	cancel()
	<-done
	// Two retained file cancellations plus the interrupted source-completion
	// scope are three separate diagnostics; scope cancellation is not a lost file.
	if err == nil || report.Failed != 3 || len(report.Problems) != 3 || report.Problems[2].Destination != "source" || s.active.Load() != 0 {
		t.Fatal("unjoined cancellation", report, err, s.active.Load())
	}
	original, err := r.store.PendingPage(testContext, "root", "", 128)
	if err != nil || len(original) != 2 {
		t.Fatal(original, err)
	}
	for _, op := range original {
		if op.Stage != "SUBMITTED" {
			t.Fatal("unknown outcome became unsent", op)
		}
	}
	second := scanOptions(t, r, w, base)
	// A cancelled DISCOVERING scan is intentionally retained as incomplete.
	// A fresh observation owner records the read gap before a new scan; it never
	// rotates remote trust or invents a cancellation fence for retained uploads.
	next, err := r.sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "after-cancel-owner")
	if err != nil {
		t.Fatal(err)
	}
	second.Witness = next
	second.Session = s
	repeat, err := r.RunCapturedScan(testContext, second)
	if err == nil || repeat.Failed != 2 || repeat.Uploaded != 0 {
		t.Fatal(repeat, err)
	}
	after, err := r.store.PendingPage(testContext, "root", "", 128)
	if err != nil || len(after) != 2 {
		t.Fatal(after, err)
	}
	for i := range original {
		if original[i].OperationID != after[i].OperationID || original[i].SealedFingerprint != after[i].SealedFingerprint {
			t.Fatal("unknown cancellation replaced original", original, after)
		}
	}
	charge, err := r.store.artifacts.Charge(testContext)
	if err != nil || charge != 6 {
		t.Fatal("unknown retained charge lost", charge, err)
	}
}
