package pluto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type pipelineFixture struct {
	mu                sync.Mutex
	files             map[string][]byte
	folders           map[string]bool
	gets, posts       map[string]int
	active, maxActive int
	started           chan string
	release           chan struct{}
	fail              map[string]int
	badReceipt        map[string]bool
	delay             time.Duration
	server            *httptest.Server
}

func newPipelineFixture(t testing.TB) *pipelineFixture {
	t.Helper()
	f := &pipelineFixture{files: map[string][]byte{}, folders: map[string]bool{"": true}, gets: map[string]int{}, posts: map[string]int{}, started: make(chan string, 100), fail: map[string]int{}, badReceipt: map[string]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		key := r.URL.Query().Get("path")
		if r.URL.Path == "/api/v1/pluto/folders" {
			var input struct{ Path string }
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				w.WriteHeader(400)
				return
			}
			f.mu.Lock()
			f.posts[input.Path]++
			f.folders[input.Path] = true
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		if r.Method == "GET" {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.gets[key]++
			if f.folders[key] {
				_ = json.NewEncoder(w).Encode(Metadata{Type: "folder"})
				return
			}
			data, ok := f.files[key]
			if !ok {
				w.WriteHeader(404)
				return
			}
			h := sha256.Sum256(data)
			_ = json.NewEncoder(w).Encode(Metadata{Type: "file", SHA256: hex.EncodeToString(h[:]), ETag: `"` + hex.EncodeToString(h[:]) + `"`, SizeBytes: int64(len(data))})
			return
		}
		if r.Method != "PUT" {
			w.WriteHeader(405)
			return
		}
		f.mu.Lock()
		f.active++
		f.maxActive = max(f.maxActive, f.active)
		gate := f.release
		failure := f.fail[key]
		badReceipt := f.badReceipt[key]
		delay := f.delay
		f.mu.Unlock()
		defer func() { f.mu.Lock(); f.active--; f.mu.Unlock() }()
		select {
		case f.started <- key:
		default:
		}
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		if failure != 0 {
			w.WriteHeader(failure)
			return
		}
		if delay != 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		h := sha256.Sum256(data)
		if r.ContentLength != int64(len(data)) || r.Header.Get("X-Content-Sha256") != hex.EncodeToString(h[:]) {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if old, exists := f.files[key]; exists {
			oldHash := sha256.Sum256(old)
			if r.Header.Get("If-Match") != `"`+hex.EncodeToString(oldHash[:])+`"` {
				w.WriteHeader(412)
				return
			}
		} else if r.Header.Get("If-None-Match") != "*" {
			w.WriteHeader(428)
			return
		}
		f.files[key] = data
		if badReceipt {
			_ = json.NewEncoder(w).Encode(Metadata{Type: "file", SHA256: "wrong", SizeBytes: int64(len(data))})
			return
		}
		_ = json.NewEncoder(w).Encode(Metadata{Type: "file", SHA256: hex.EncodeToString(h[:]), SizeBytes: int64(len(data))})
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *pipelineFixture) remote() Remote {
	return Remote{f.server.Client(), f.server.URL, "fixture-token"}
}

func writePipelineFiles(t testing.TB, names []string, data []byte) (string, []string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sources")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	files := make([]string, len(names))
	for i, name := range names {
		files[i] = filepath.Join(root, name)
		if err := os.WriteFile(files[i], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, files
}

func waitPipelineStart(t *testing.T, f *pipelineFixture) string {
	t.Helper()
	select {
	case name := <-f.started:
		return name
	case <-time.After(3 * time.Second):
		t.Fatal("transfer did not start")
		return ""
	}
}

func assertPipelineClean(t *testing.T, spool string, budget *copyBudget) {
	t.Helper()
	entries, err := os.ReadDir(spool)
	if err != nil || len(entries) != 0 {
		t.Fatalf("snapshot leaked: %v %v", entries, err)
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.spoolBytes != 0 || len(budget.workers) != 0 || len(budget.readers) != 0 {
		t.Fatalf("resource reservation leaked: spool=%d workers=%d readers=%d", budget.spoolBytes, len(budget.workers), len(budget.readers))
	}
}

func TestCopyPipelineOverlapsTwoTransfersAndDeduplicatesParentsAndSources(t *testing.T) {
	f := newPipelineFixture(t)
	f.release = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(f.release) }) }
	t.Cleanup(release)
	root, files := writePipelineFiles(t, []string{"a", "b", "c"}, []byte("verified fixture"))
	if err := os.Mkdir(filepath.Join(root, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	budget := newCopyBudget(2, 1, MaxFileBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := copyPipeline(ctx, f.remote(), append([]string{root}, files...), spool, budget)
		result <- struct {
			n   int
			err error
		}{n, err}
	}()
	first, second := waitPipelineStart(t, f), waitPipelineStart(t, f)
	if first == second {
		t.Fatal("same path concurrently uploaded")
	}
	select {
	case third := <-f.started:
		t.Fatalf("exceeded two workers: %s", third)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	out := <-result
	if out.n != 3 || out.err != nil {
		t.Fatalf("copy: %d %v", out.n, out.err)
	}
	f.mu.Lock()
	if f.maxActive != 2 || len(f.files) != 3 || !f.folders[RelativePath(filepath.Join(root, "empty"))] {
		t.Fatal("bounded overlap lost files/empty directory", f.maxActive, len(f.files))
	}
	for name, count := range f.posts {
		if count != 1 || f.gets[name] != 1 {
			t.Fatalf("duplicate parent operation %s: get=%d post=%d", name, f.gets[name], count)
		}
	}
	f.mu.Unlock()
	assertPipelineClean(t, spool, budget)
}

func TestCopyPipelineByteBudgetBackpressureAndCancellationCleanup(t *testing.T) {
	f := newPipelineFixture(t)
	f.release = make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(f.release) }) })
	root, _ := writePipelineFiles(t, []string{"a", "b", "c"}, bytes.Repeat([]byte("x"), 24))
	spool := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	budget := newCopyBudget(2, 1, 32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := copyPipeline(ctx, f.remote(), []string{root}, spool, budget); result <- err }()
	waitPipelineStart(t, f)
	select {
	case <-f.started:
		t.Fatal("two snapshots exceeded byte budget")
	case <-time.After(50 * time.Millisecond):
	}
	entries, err := os.ReadDir(spool)
	if err != nil || len(entries) != 1 {
		t.Fatal("budget should admit one snapshot", entries, err)
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > 32 {
		t.Fatalf("spool bytes exceeded: %d", total)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation left a worker blocked")
	}
	assertPipelineClean(t, spool, budget)
}

func TestCopyPipelinePublishesBeforeRemainingDirectoryScanCompletes(t *testing.T) {
	f := newPipelineFixture(t)
	root, _ := writePipelineFiles(t, []string{"a-first"}, []byte("first"))
	later := filepath.Join(root, "z-later")
	if err := os.Mkdir(later, 0700); err != nil {
		t.Fatal(err)
	}
	transport := f.server.Client().Transport
	client := &http.Client{Transport: pipelineRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && r.URL.Query().Get("path") == RelativePath(later) {
			// The remaining scan cannot advance until a ready file's transfer has
			// begun. A whole-tree preparation barrier would deadlock this case.
			select {
			case <-f.started:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return transport.RoundTrip(r)
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	spool := filepath.Join(t.TempDir(), "spool")
	n, err := Copy(ctx, Remote{client, f.server.URL, "fixture"}, []string{root}, spool)
	if n != 1 || err != nil {
		t.Fatalf("initial copy waited for the whole directory tree: %d %v", n, err)
	}
	assertPipelineClean(t, spool, copyResources)
}

func TestCopyPipelineSourceGrowthCannotExceedSpoolReservationOrPublish(t *testing.T) {
	f := newPipelineFixture(t)
	_, files := writePipelineFiles(t, []string{"changing"}, []byte("small"))
	spool := t.TempDir()
	budget := newCopyBudget(2, 1, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := budget.acquireReader(ctx); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := copyPipeline(ctx, f.remote(), files, spool, budget); result <- err }()
	for {
		budget.mu.Lock()
		reserved := budget.spoolBytes
		budget.mu.Unlock()
		if reserved > 0 {
			break
		}
		select {
		case <-ctx.Done():
			budget.releaseReader()
			t.Fatal("source was not reserved")
		case <-time.After(time.Millisecond):
		}
	}
	if err := os.WriteFile(files[0], []byte("grew beyond reservation"), 0600); err != nil {
		budget.releaseReader()
		t.Fatal(err)
	}
	budget.releaseReader()
	if err := <-result; err == nil || !strings.Contains(err.Error(), "source changed") {
		t.Fatal("changed source accepted", err)
	}
	if len(f.files) != 0 {
		t.Fatal("unverified changed source published")
	}
	assertPipelineClean(t, spool, budget)
}

func TestCopyPipelinePartialFailuresPreserveHealthyCopiesAndOrder(t *testing.T) {
	f := newPipelineFixture(t)
	root, files := writePipelineFiles(t, []string{"a-conflict", "b-bad-receipt", "c-healthy"}, []byte("new"))
	f.files[RelativePath(files[0])] = []byte("old")
	f.fail[RelativePath(files[0])] = 412
	f.badReceipt[RelativePath(files[1])] = true
	spool := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	budget := newCopyBudget(2, 1, MaxFileBytes)
	n, err := copyPipeline(context.Background(), f.remote(), []string{root}, spool, budget)
	if n != 1 || err == nil || !strings.Contains(err.Error(), "2 source entries failed") {
		t.Fatalf("partial result: %d %v", n, err)
	}
	if strings.Index(err.Error(), files[0]) > strings.Index(err.Error(), files[1]) {
		t.Fatal("failures not reported in scan order", err)
	}
	f.mu.Lock()
	if string(f.files[RelativePath(files[0])]) != "old" || string(f.files[RelativePath(files[2])]) != "new" {
		t.Fatal("CAS conflict damaged stored/healthy bytes")
	}
	f.mu.Unlock()
	assertPipelineClean(t, spool, budget)
}

func TestCopyPipelineAuthorizationStopsWorkersWithoutLosingConfirmedSuccesses(t *testing.T) {
	f := newPipelineFixture(t)
	_, files := writePipelineFiles(t, []string{"a-healthy", "b-denied", "c-later"}, []byte("safe"))
	f.fail[RelativePath(files[1])] = 403
	spool := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	budget := newCopyBudget(2, 1, MaxFileBytes)
	// An explicit healthy source followed by its duplicate waits for the receipt
	// before denial is scheduled, proving that aggregate cancellation retains it.
	n, err := copyPipeline(context.Background(), f.remote(), []string{files[0], files[0], files[1], files[2]}, spool, budget)
	var denied *HTTPError
	if n < 1 || !errors.As(err, &denied) || denied.Status != 403 {
		t.Fatalf("authorization result: %d %v", n, err)
	}
	f.mu.Lock()
	if string(f.files[RelativePath(files[0])]) != "safe" {
		t.Fatal("lost acknowledged success")
	}
	f.mu.Unlock()
	assertPipelineClean(t, spool, budget)
}

func TestCopyBudgetSharedAcrossConcurrentRunsAndReaderCancellation(t *testing.T) {
	budget := newCopyBudget(2, 1, 64)
	ctx, cancel := context.WithCancel(context.Background())
	if err := budget.acquireReader(ctx); err != nil {
		t.Fatal(err)
	}
	readerResult := make(chan error, 1)
	go func() { readerResult <- budget.acquireReader(ctx) }()
	cancel()
	if err := <-readerResult; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	budget.releaseReader()
	f := newPipelineFixture(t)
	f.release = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(f.release) }) }
	t.Cleanup(release)
	_, files := writePipelineFiles(t, []string{"a", "b", "c", "d"}, []byte("snapshot"))
	var runs sync.WaitGroup
	errs := make(chan error, 2)
	for _, source := range [][]string{files[:2], files[2:]} {
		spool := t.TempDir()
		runs.Go(func() {
			n, err := copyPipeline(context.Background(), f.remote(), source, spool, budget)
			if n != 2 || err != nil {
				errs <- fmt.Errorf("copy %d: %v", n, err)
			}
		})
	}
	waitPipelineStart(t, f)
	waitPipelineStart(t, f)
	select {
	case <-f.started:
		t.Fatal("concurrent runs multiplied worker budget")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	runs.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	f.mu.Lock()
	if f.maxActive != 2 || len(f.files) != 4 {
		t.Fatal("shared budget lost work", f.maxActive, len(f.files))
	}
	f.mu.Unlock()
	if budget.spoolBytes != 0 || len(budget.workers) != 0 || len(budget.readers) != 0 {
		t.Fatal("shared budget leaked")
	}
}

func TestSnapshotWriterNeverExceedsReservationAndContextReaderStops(t *testing.T) {
	var content bytes.Buffer
	w := &snapshotWriter{writer: &content, remaining: 3}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("d")); err == nil || content.String() != "abc" {
		t.Fatal("snapshot grew beyond byte reservation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&copyContextReader{ctx: ctx, reader: strings.NewReader("secret")}).Read(make([]byte, 64))
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type pipelineRoundTripper func(*http.Request) (*http.Response, error)

func (f pipelineRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParentEnsurerSingleflightBoundedCacheAndInvalidation(t *testing.T) {
	var mu sync.Mutex
	gets := map[string]int{}
	start, release := make(chan struct{}), make(chan struct{})
	var started sync.Once
	client := &http.Client{Transport: pipelineRoundTripper(func(r *http.Request) (*http.Response, error) {
		key := r.URL.Query().Get("path")
		mu.Lock()
		gets[key]++
		mu.Unlock()
		if key == "root/shared" {
			started.Do(func() { close(start) })
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"Type":"folder"}`)), Header: make(http.Header)}, nil
	})}
	parents := newParentEnsurer(Remote{client, "https://fixture.test", ""})
	var waits sync.WaitGroup
	errs := make(chan error, 2)
	waits.Go(func() { errs <- parents.ensure(context.Background(), "root/shared") })
	<-start
	waits.Go(func() { errs <- parents.ensure(context.Background(), "root/shared") })
	close(release)
	waits.Wait()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if gets["root/shared"] != 1 || gets["root"] != 1 {
		t.Fatal("duplicate parent resolution", gets)
	}
	for i := range parentCacheSize + 1 {
		if err := parents.ensure(context.Background(), fmt.Sprintf("root/p-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(parents.ready) > parentCacheSize {
		t.Fatal("unbounded parent cache", len(parents.ready))
	}
	parents.invalidate()
	if err := parents.ensure(context.Background(), "root/shared"); err != nil {
		t.Fatal(err)
	}
	if gets["root/shared"] != 2 {
		t.Fatal("stale positive cache retained")
	}
}

func TestParentEnsurerRejectsConflictsAndDoesNotCacheFailures(t *testing.T) {
	for _, status := range []int{409, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: pipelineRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				code := status
				if calls == 1 {
					code = 404
				}
				if calls >= 3 {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"Type":"folder"}`)), Header: make(http.Header)}, nil
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			})}
			parents := newParentEnsurer(Remote{client, "https://fixture.test", ""})
			if err := parents.ensure(context.Background(), "root"); err == nil {
				t.Fatal("accepted failed folder creation")
			}
			if err := parents.ensure(context.Background(), "root"); err != nil || calls != 3 {
				t.Fatal("failure cached", calls, err)
			}
		})
	}
}

func TestCopyBudgetCleanupFailureStopsFurtherAdmission(t *testing.T) {
	budget := newCopyBudget(2, 1, 32)
	dir := t.TempDir()
	if err := budget.reserveSpool(context.Background(), dir, 32); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- budget.reserveSpool(context.Background(), dir, 1) }()
	budget.blockSpool(errSnapshotCleanup)
	budget.releaseSpool(32)
	select {
	case err := <-result:
		if !errors.Is(err, errSnapshotCleanup) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup failure left waiter blocked")
	}
	if err := budget.reserveSpool(context.Background(), dir, 1); !errors.Is(err, errSnapshotCleanup) {
		t.Fatal("admitted more snapshots after cleanup failure", err)
	}
}

// This isolates transfer latency, keeping capture, hashing, CAS and receipt
// verification identical. It is not a production SFTP or delta-engine benchmark.
func BenchmarkCopyPipelineBoundedLatency(b *testing.B) {
	for _, workers := range []int{1, 2} {
		b.Run(fmt.Sprintf("workers-%d", workers), func(b *testing.B) {
			f := newPipelineFixture(b)
			f.delay = 40 * time.Millisecond
			names := make([]string, 24)
			for i := range names {
				names[i] = fmt.Sprintf("fixture-%02d", i)
			}
			root, _ := writePipelineFiles(b, names, bytes.Repeat([]byte("x"), 32*1024))
			spool := b.TempDir()
			budget := newCopyBudget(workers, 1, MaxFileBytes)
			b.SetBytes(24 * 32 * 1024)
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				f.mu.Lock()
				clear(f.files)
				f.mu.Unlock()
				b.StartTimer()
				n, err := copyPipeline(context.Background(), f.remote(), []string{root}, spool, budget)
				if n != 24 || err != nil {
					b.Fatalf("copy %d: %v", n, err)
				}
			}
			b.ReportMetric(24, "files/op")
			b.ReportMetric(float64(f.maxActive), "max-transfers")
		})
	}
}
