package syncstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type engineCaptureLimiter struct {
	*registryFixtureLimiter
	jobs chan struct{}
	done sync.Once
}

func (l *engineCaptureLimiter) release() { l.done.Do(func() { <-l.jobs }) }
func (l *engineCaptureLimiter) ReserveCapture(ctx context.Context, dir string, size int64) (func(), error) {
	select {
	case l.jobs <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release, err := l.registryFixtureLimiter.ReserveCapture(ctx, dir, size)
	if err != nil {
		l.release()
		return nil, err
	}
	return func() { release(); l.release() }, nil
}
func (l *engineCaptureLimiter) DisposeCaptureArtifact(ctx context.Context, id string) error {
	err := l.registryFixtureLimiter.DisposeCaptureArtifact(ctx, id)
	if err == nil {
		l.release()
	}
	return err
}
func (l *engineCaptureLimiter) RetainCaptureArtifact(ctx context.Context, id string) error {
	err := l.registryFixtureLimiter.RetainCaptureArtifact(ctx, id)
	if err == nil {
		l.release()
	}
	return err
}

func engineFixture(t *testing.T, sizes []int, capability bool, itemLimit ...int) (*RemoteImport, SourceWitness, *dispatchHTTPFixture, string) {
	t.Helper()
	r, _, w, old, base, dir := actualHTTPFixture(t, len(sizes))
	old.Close()
	for n, size := range sizes {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%03d", n)), bytes.Repeat([]byte{byte(n + 1)}, size), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(r.store.filename), 0700); err != nil {
		t.Fatal(err)
	}
	f := &dispatchHTTPFixture{base: base, groups: map[string]*smallBatchPlan{}, calls: map[string]int{}, sent: map[string]int{}}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		if capability && len(itemLimit) == 1 && req.URL.Path == "/sync/v1/roots/"+base.binding.RootID+"/small-batches/capabilities" {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.calls["capabilities"]++
			base.json(writer, map[string]any{"schema": "saturn.small-file-batch-capabilities.v1", "transport": smallBatchSchema, "binding": bindingHTTP(base.binding), "device_id": f.session.identity.DeviceID, "backend_identity": f.session.identity.BackendIdentity, "qualification_receipt_sha256": f.session.identity.ContractReceiptSHA256, "limits": map[string]any{"items": itemLimit[0], "file_bytes": "262144", "data_bytes": "33554432", "manifest_bytes": "4194304"}})
			return
		}
		if !capability && req.URL.Path == "/sync/v1/roots/"+base.binding.RootID+"/small-batches/capabilities" {
			writer.WriteHeader(404)
			return
		}
		if req.URL.Path == "/sync/v1/roots/"+base.binding.RootID+"/small-batches/prepare" {
			raw, err := io.ReadAll(io.LimitReader(req.Body, smallBatchMaximumMetadataBytes+1))
			if err != nil {
				t.Error(err)
				return
			}
			req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(raw))
			value := jsonRawValue(raw).(map[string]any)
			id := value["manifest"].(map[string]any)["batch_id"].(string)
			record, err := r.store.batches.state.read(req.Context(), id)
			if err != nil {
				t.Error(err)
				return
			}
			descriptors, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Error(err)
				return
			}
			for _, e := range record.Plan.entries {
				for _, fd := range descriptors {
					name, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
					if name == filepath.Join(dir, e.original.Name) {
						t.Error("batch prepare retained member source descriptor", e.original.Name)
					}
				}
			}
		}
		f.ServeHTTP(writer, req)
	}))
	t.Cleanup(server.Close)
	s, err := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: server.URL, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(base.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.SetRecoveryReader(artifactTestReader)
	f.session = s
	if err = s.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	return r, w, f, dir
}
func runEngineFixture(t *testing.T, ctx context.Context, r *RemoteImport, w SourceWitness, f *dispatchHTTPFixture, mode string) (CapturedScanReport, error) {
	t.Helper()
	jobs := make(chan struct{}, 2)
	readers := newTestCaptureLimiter()
	budget := &fixtureSmallBatchBudget{}
	acquire := func(ctx context.Context) (func(), error) {
		select {
		case jobs <- struct{}{}:
			return func() { <-jobs }, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	report, err := r.RunCapturedScan(ctx, CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: f.session, SmallBatchMode: mode, SmallBatchBudget: budget, AcquireRecovery: acquire, DisposeRecovered: func(ctx context.Context, op Operation) error { return r.store.artifacts.Dispose(ctx, op.SnapshotID) }, CaptureAndUse: func(ctx context.Context, w SourceWitness, e SourceEntry, use func(*VerifiedSnapshot) error) error {
		return CaptureAndUseGuarded(ctx, w, e, r.store.artifacts.Directory(), &engineCaptureLimiter{registryFixtureLimiter: &registryFixtureLimiter{a: r.store.artifacts, reader: readers}, jobs: jobs}, use)
	}})
	if len(jobs) != 0 {
		t.Fatal("data admission did not join", len(jobs))
	}
	if err == nil && budget.charge() != 0 {
		t.Fatal("successful scan retained aggregate quota", budget.charge())
	}
	return report, err
}
func TestSmallBatchEngineMixedCaptureOnceClosedSourcesAndRepeat(t *testing.T) {
	r, w, f, _ := engineFixture(t, []int{0, 1, 1024, 262144, 262145}, true)
	before := CaptureMetricSnapshot()
	report, err := runEngineFixture(t, testContext, r, w, f, "bulk")
	metrics := CaptureMetricSnapshot().Since(before)
	if err != nil || !report.Complete || report.Uploaded != 5 || report.Failed != 0 || metrics.SourceReads != 5 || metrics.SourceHashBytes != 525314 {
		t.Fatal(report, metrics, err)
	}
	f.mu.Lock()
	packets := f.calls["data"]
	f.mu.Unlock()
	if packets < 1 {
		t.Fatal("no actual packet used")
	}
	before = CaptureMetricSnapshot()
	report, err = runEngineFixture(t, testContext, r, w, f, "changes")
	metrics = CaptureMetricSnapshot().Since(before)
	if err != nil || !report.Complete || report.Uploaded != 0 || report.Adopted != 5 || metrics.SourceReads != 5 {
		t.Fatal(report, metrics, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls["data"] != packets {
		t.Fatal("unchanged packet replay")
	}
}
func TestSmallBatchEngineUnavailableAndDefaultPreserveV6(t *testing.T) {
	for _, mode := range []string{"", "bulk"} {
		t.Run("mode-"+mode, func(t *testing.T) {
			r, w, f, _ := engineFixture(t, []int{0, 7, 1024}, mode == "")
			report, err := runEngineFixture(t, testContext, r, w, f, mode)
			var version int
			readErr := r.store.db.QueryRow("PRAGMA user_version").Scan(&version)
			if err != nil || readErr != nil || version != HTTPBindingSchemaVersion || report.Uploaded != 3 || !report.Complete {
				t.Fatal(report, version, err, readErr)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.calls["data"] != 0 || f.calls["prepare"] != 0 || mode == "" && f.calls["capabilities"] != 0 {
				t.Fatal(f.calls)
			}
		})
	}
}
func TestSmallBatchEngineLostDataNewOwnerRecoversOriginalsWithoutCapture(t *testing.T) {
	r, w, f, _ := engineFixture(t, []int{0, 1, 7, 1024}, true)
	f.loseData = true
	report, err := runEngineFixture(t, testContext, r, w, f, "bulk")
	if err == nil || report.Failed != 4 {
		t.Fatal(report, err)
	}
	pending, err := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if err != nil || len(pending) != 4 {
		t.Fatal(pending, err)
	}
	next, err := r.sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "engine-recovery")
	if err != nil {
		t.Fatal(err)
	}
	before := CaptureMetricSnapshot()
	report, err = runEngineFixture(t, testContext, r, next, f, "bulk")
	if err != nil || !report.Complete || report.Recovered != 4 || report.Uploaded != 0 || CaptureMetricSnapshot().Since(before).SourceReads != 0 {
		t.Fatal(report, err)
	}
	for _, op := range pending {
		current, e := r.store.Operation(testContext, op.OperationID)
		if e != nil || current.Stage != "CLIENT_ACKED" || current.IntentFingerprint != op.IntentFingerprint || current.LocalGeneration != op.LocalGeneration {
			t.Fatal(current.Stage, e)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls["status"] != 1 || f.calls["data"] != 1 {
		t.Fatal(f.calls)
	}
	if errors.Is(err, ErrArtifactRetained) {
		t.Fatal(err)
	}
}

func TestSmallBatchEngineDisabledModeRetiresAggregateAndRecoversIndividually(t *testing.T) {
	r, w, f, _ := engineFixture(t, []int{0, 1, 7, 1024}, true)
	f.loseData = true
	first, err := runEngineFixture(t, testContext, r, w, f, "bulk")
	if err == nil || first.Failed != 4 {
		t.Fatal(first, err)
	}
	f.mu.Lock()
	capabilities := f.calls["capabilities"]
	f.mu.Unlock()
	before := CaptureMetricSnapshot()
	pending, err := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if err != nil || len(pending) != 4 {
		t.Fatal(pending, err)
	}
	// Original recovery uses sealed artifacts, regardless of the current batch
	// preference. The following ordinary scan must still verify current bytes.
	n, err := r.RecoverOriginals(testContext, CapturedScanOptions{Witness: w, RootID: "root", Session: f.session, DisposeRecovered: func(ctx context.Context, op Operation) error { return r.store.artifacts.Dispose(ctx, op.SnapshotID) }})
	if err != nil || n != 4 || CaptureMetricSnapshot().Since(before).SourceReads != 0 {
		t.Fatal("individual original recovery read the source", n, err)
	}
	for _, original := range pending {
		current, err := r.store.Operation(testContext, original.OperationID)
		if err != nil || current.Stage != "CLIENT_ACKED" || current.IntentFingerprint != original.IntentFingerprint || current.LocalGeneration != original.LocalGeneration {
			t.Fatal("original identity changed", current, err)
		}
	}
	recovered, err := runEngineFixture(t, testContext, r, w, f, "")
	if err != nil || !recovered.Complete || recovered.Recovered != 0 || recovered.Uploaded != 0 || recovered.Adopted != 4 || CaptureMetricSnapshot().Since(before).SourceReads != 4 {
		t.Fatal(recovered, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls["capabilities"] != capabilities || f.calls["status"] != 0 || f.calls["data"] != 1 {
		t.Fatal(f.calls)
	}
	var active int
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM small_batch_groups WHERE phase<>'GONE'").Scan(&active); err != nil || active != 0 {
		t.Fatal(active, err)
	}
}

func TestSmallBatchEngineCancellationJoinsCaptureQueueAndAggregate(t *testing.T) {
	r, w, f, _ := engineFixture(t, []int{0, 1, 7, 1024}, true)
	f.hold = make(chan struct{})
	f.entered = make(chan struct{})
	f.completed = make(chan struct{})
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := runEngineFixture(t, ctx, r, w, f, "bulk"); done <- err }()
	select {
	case <-f.entered:
	case <-time.After(10 * time.Second):
		cancel()
		close(f.hold)
		t.Fatal("no data request")
	}
	cancel()
	close(f.hold)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not join")
	}
	select {
	case <-f.completed:
	case <-time.After(time.Second):
		t.Fatal("receiver did not join")
	}
	if r.store.batches.inUse() {
		t.Fatal("native aggregate handle still active")
	}
}
