package pluto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type enumerationInfo struct {
	name      string
	directory bool
}

func (i enumerationInfo) Name() string { return i.name }
func (i enumerationInfo) Size() int64  { return 0 }
func (i enumerationInfo) Mode() fs.FileMode {
	if i.directory {
		return fs.ModeDir | 0700
	}
	return 0600
}
func (i enumerationInfo) ModTime() time.Time { return time.Time{} }
func (i enumerationInfo) IsDir() bool        { return i.directory }
func (i enumerationInfo) Sys() any           { return nil }

// Descriptors are generated only in response to bounded ReadDir(n), rather
// than constructing a fixture array that could hide enumeration allocations.
type syntheticEnumerationFS struct {
	count, depth                               int
	wideDirectories                            bool
	mu                                         sync.Mutex
	open, peakOpen, returned, peakBatch, calls int
	gate                                       func(int) error
}

func (f *syntheticEnumerationFS) Lstat(name string) (fs.FileInfo, error) {
	return enumerationInfo{name, true}, nil
}
func (f *syntheticEnumerationFS) OpenDirectory(name string) (copyDirectoryReader, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open++
	f.peakOpen = max(f.peakOpen, f.open)
	return &syntheticEnumerationDirectory{f: f, depth: strings.Count(name, "/")}, nil
}

type syntheticEnumerationDirectory struct {
	f             *syntheticEnumerationFS
	offset, depth int
	closed        bool
}

func (d *syntheticEnumerationDirectory) ReadDir(n int) ([]fs.DirEntry, error) {
	if n != copyDirectoryBatch {
		return nil, errors.New("unbounded ReadDir request")
	}
	f := d.f
	if f.gate != nil {
		if err := f.gate(d.offset); err != nil {
			return nil, err
		}
	}
	count := f.count
	if f.wideDirectories && d.depth > 0 {
		count = 0
	}
	if d.depth < f.depth {
		count = 1
	}
	if d.offset >= count {
		return nil, io.EOF
	}
	end := min(d.offset+n, count)
	batch := make([]fs.DirEntry, 0, end-d.offset)
	for d.offset < end {
		name := fmt.Sprintf("file-%09d", d.offset)
		isDir := d.depth < f.depth || f.wideDirectories
		if isDir && !f.wideDirectories {
			name = "d"
		}
		batch = append(batch, fs.FileInfoToDirEntry(enumerationInfo{name, isDir}))
		d.offset++
	}
	f.mu.Lock()
	f.returned += len(batch)
	f.calls++
	f.peakBatch = max(f.peakBatch, len(batch))
	f.mu.Unlock()
	return batch, nil
}
func (d *syntheticEnumerationDirectory) Close() error {
	if !d.closed {
		d.f.mu.Lock()
		d.f.open--
		d.f.mu.Unlock()
		d.closed = true
	}
	return nil
}

func TestCopyEnumerationWideDirectoryFrontierIsDiskBounded(t *testing.T) {
	s := enumerationStateForTest(t, copyMetadataDatabaseBytes)
	ctx := context.Background()
	filesystem := &syntheticEnumerationFS{count: 100000, wideDirectories: true}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	peak := before.HeapInuse
	visited := 0
	started := time.Now()
	err := streamCopySource(ctx, "root", filesystem, s, func(_ string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() {
			t.Fatal("not a directory")
		}
		visited++
		if visited%4096 == 0 {
			runtime.ReadMemStats(&after)
			peak = max(peak, after.HeapInuse)
		}
		return nil
	})
	runtime.ReadMemStats(&after)
	peak = max(peak, after.HeapInuse)
	if err != nil || filesystem.returned != 100000 || visited != 100002 || filesystem.peakOpen != 1 || filesystem.open != 0 || peak > before.HeapInuse+32*1024*1024 {
		t.Fatal("unbounded/lost directory frontier", err, filesystem.returned, visited, filesystem.peakOpen, peak, before.HeapInuse)
	}
	var pending int
	if err := s.db.QueryRow("SELECT count(*) FROM frontier").Scan(&pending); err != nil || pending != 0 {
		t.Fatal("frontier retained unfinished paths", pending, err)
	}
	data := map[string]any{"directories": 100000, "visitedIncludingRootQualification": visited, "returnedDescriptors": filesystem.returned, "maxBatch": filesystem.peakBatch, "maxOpenDirectories": filesystem.peakOpen, "heapBeforeBytes": before.HeapInuse, "peakHeapBytes": peak, "cumulativeAllocatedBytes": after.TotalAlloc - before.TotalAlloc, "durationMs": time.Since(started).Milliseconds()}
	encoded, _ := json.Marshal(data)
	t.Log(string(encoded))
	if dir := os.Getenv("PLUTO_ENUMERATION_EVIDENCE"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "wide-directory-frontier-100000.json"), append(encoded, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func enumerationStateForTest(t testing.TB, maxBytes int64) *copyEnumerationState {
	t.Helper()
	spool := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := newCopyEnumerationState(context.Background(), spool, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestCopyEnumerationExactInvocationSetAndIndexedFrontier(t *testing.T) {
	ctx := context.Background()
	s := enumerationStateForTest(t, copyMetadataDatabaseBytes)
	for i := range 257 {
		p := fmt.Sprintf("unmodified/source/%d", i)
		if exists, err := s.hasCompleted(ctx, p); exists || err != nil {
			t.Fatal(exists, err)
		}
		if err := s.markCompleted(ctx, p); err != nil {
			t.Fatal(err)
		}
		if len(s.completed) >= copyCompletionBatch {
			t.Fatal("unbounded completion buffer")
		}
	}
	for i := range 257 {
		if exists, err := s.hasCompleted(ctx, fmt.Sprintf("unmodified/source/%d", i)); !exists || err != nil {
			t.Fatal(i, exists, err)
		}
	}
	// Identity is intentionally not normalized: these are different legacy
	// remoteRelativePath strings even if local resolution reaches one inode.
	if exists, err := s.hasCompleted(ctx, "unmodified/source/./0"); exists || err != nil {
		t.Fatal("changed path identity", exists, err)
	}
	for _, p := range []string{"one", "two", "one"} {
		if err := s.pushDirectory(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"one", "two", "one"} {
		actual, ok, err := s.popDirectory(ctx)
		if actual != p || !ok || err != nil {
			t.Fatal(actual, ok, err)
		}
	}
	if _, ok, err := s.popDirectory(ctx); ok || err != nil {
		t.Fatal(ok, err)
	}
	for _, q := range []string{"SELECT 1 FROM completed WHERE path='unmodified/source/1'", "SELECT id,path FROM frontier WHERE id>0 ORDER BY id LIMIT 1", "DELETE FROM frontier WHERE id=1"} {
		rows, err := s.db.Query("EXPLAIN QUERY PLAN " + q)
		if err != nil {
			t.Fatal(err)
		}
		var details []string
		for rows.Next() {
			var a, b, c int
			var detail string
			if err := rows.Scan(&a, &b, &c, &detail); err != nil {
				t.Fatal(err)
			}
			details = append(details, detail)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(details, ";")
		if strings.Contains(joined, "TEMP B-TREE") || (strings.Contains(q, "WHERE") && !strings.Contains(joined, "SEARCH")) {
			t.Fatal("not indexed", q, joined)
		}
		t.Log(q, joined)
	}
	var mode string
	var pages, limit int64
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRow("PRAGMA page_count").Scan(&pages)
	_ = s.db.QueryRow("PRAGMA max_page_count").Scan(&limit)
	if mode != "delete" || limit*4096 > copyMetadataDatabaseBytes || pages > limit {
		t.Fatal(mode, pages, limit)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(filepath.Join(s.directory, "state.sqlite") + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unexpected WAL", err)
		}
	}
	oldDir := s.directory
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("metadata leaked", err)
	}
	// A new invocation cannot accept the old set as a baseline/resume proof.
	fresh := enumerationStateForTest(t, copyMetadataDatabaseBytes)
	if ok, err := fresh.hasCompleted(ctx, "unmodified/source/0"); ok || err != nil {
		t.Fatal("state reused across Copy", ok, err)
	}
}

func TestCopyEnumerationWideAndDeepBoundedDescriptors(t *testing.T) {
	for _, n := range []int{100000, 500000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			ctx := context.Background()
			s := enumerationStateForTest(t, copyMetadataDatabaseBytes)
			depth := 128
			filesystem := &syntheticEnumerationFS{count: n, depth: depth}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			peakHeap := before.HeapInuse
			peakCompleted := 0
			files := 0
			firstAt := 0
			started := time.Now()
			err := streamCopySource(ctx, "root", filesystem, s, func(name string, e fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if e.IsDir() {
					return nil
				}
				files++
				if files == 1 {
					firstAt = filesystem.returned
				}
				if err := s.markCompleted(ctx, RelativePath(name)); err != nil {
					return err
				}
				peakCompleted = max(peakCompleted, len(s.completed))
				if files%4096 == 0 {
					runtime.ReadMemStats(&after)
					peakHeap = max(peakHeap, after.HeapInuse)
				}
				return nil
			})
			runtime.ReadMemStats(&after)
			peakHeap = max(peakHeap, after.HeapInuse)
			if err != nil || files != n || filesystem.returned != n+depth || filesystem.peakBatch > 128 || filesystem.peakOpen != 1 || filesystem.open != 0 || peakCompleted >= 128 || firstAt >= n {
				t.Fatalf("stream lost/buffered descriptors: files=%d returned=%d batch=%d FDs=%d remaining=%d completion=%d first=%d error=%v", files, filesystem.returned, filesystem.peakBatch, filesystem.peakOpen, filesystem.open, peakCompleted, firstAt, err)
			}
			if peakHeap > before.HeapInuse+32*1024*1024 {
				t.Fatalf("wide tree live heap grew: before=%d peak=%d", before.HeapInuse, peakHeap)
			}
			for _, i := range []int{0, n / 2, n - 1} {
				name := "root/" + strings.Repeat("d/", depth) + fmt.Sprintf("file-%09d", i)
				if ok, err := s.hasCompleted(ctx, name); !ok || err != nil {
					t.Fatal("lost successful identity", i, ok, err)
				}
			}
			var pages int64
			if err := s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
				t.Fatal(err)
			}
			data := map[string]any{"descriptors": filesystem.returned, "files": files, "depth": depth, "ReadDirCalls": filesystem.calls, "maxBatch": filesystem.peakBatch, "maxOpenDirectories": filesystem.peakOpen, "firstVisitAtReturned": firstAt, "maxCompletionBuffer": peakCompleted, "heapBeforeBytes": before.HeapInuse, "peakHeapBytes": peakHeap, "cumulativeAllocatedBytes": after.TotalAlloc - before.TotalAlloc, "databaseBytes": pages * 4096, "databaseLimitBytes": copyMetadataDatabaseBytes, "journalMode": "DELETE", "WALBytes": 0, "durationMs": time.Since(started).Milliseconds()}
			encoded, _ := json.Marshal(data)
			t.Log(string(encoded))
			if dir := os.Getenv("PLUTO_ENUMERATION_EVIDENCE"); dir != "" {
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("descriptors-%d.json", n)), append(encoded, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCopyEnumerationRepresentativeDiskProjection(t *testing.T) {
	for _, bytes := range []int{128, 256, 512} {
		t.Run(fmt.Sprint(bytes), func(t *testing.T) {
			s := enumerationStateForTest(t, copyMetadataDatabaseBytes)
			ctx := context.Background()
			started := time.Now()
			const count = 100000
			prefix := strings.Repeat("p", bytes-10) + "/"
			for i := range count {
				name := prefix + fmt.Sprintf("%09d", i)
				if len(name) != bytes {
					t.Fatal(len(name))
				}
				if err := s.markCompleted(ctx, name); err != nil {
					t.Fatal(err)
				}
			}
			var pages int64
			if err := s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
				t.Fatal(err)
			}
			// Quantified projection from actual 100k exact PK rows, with the actual
			// deep500k case recorded separately; this is capacity planning, not a
			// guarantee for all path distributions/frontier peaks.
			data := map[string]any{"actualRows": count, "pathBytes": bytes, "actualDatabaseBytes": pages * 4096, "projected500kBytes": pages * 4096 * 5, "defaultDatabaseCapBytes": copyMetadataDatabaseBytes, "maximumConfiguredCapBytes": maxCopyMetadataDatabaseBytes, "cacheKiB": 2048, "journalMode": "DELETE", "WALBytes": 0, "durationMs": time.Since(started).Milliseconds()}
			encoded, _ := json.Marshal(data)
			t.Log(string(encoded))
			if dir := os.Getenv("PLUTO_ENUMERATION_EVIDENCE"); dir != "" {
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("disk-projection-%d.json", bytes)), append(encoded, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if pages*4096*5 > copyMetadataDatabaseBytes {
				t.Fatal("default capacity insufficient for representative fixture")
			}
		})
	}
}

func TestCopyEnumerationOptionsCapAndCancelledAdmission(t *testing.T) {
	for _, bad := range []int64{-1, 4096, maxCopyMetadataDatabaseBytes + 1} {
		if _, err := (CopyOptions{bad}).metadataLimit(); err == nil {
			t.Fatal("invalid capacity accepted", bad)
		}
	}
	for _, capacity := range []int64{0, 16384, copyMetadataDatabaseBytes, maxCopyMetadataDatabaseBytes} {
		if _, err := (CopyOptions{capacity}).metadataLimit(); err != nil {
			t.Fatal(capacity, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	budget := newCopyBudget(2, 1, MaxFileBytes)
	if err := budget.acquireEnumeration(ctx, t.TempDir(), copyMetadataDatabaseBytes); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(budget.enumerators) != 0 || budget.metadataBytes != 0 {
		t.Fatal("cancelled admission leaked reservation")
	}
	if err := validCopyStatePath(strings.Repeat("x", copyPathBytes+1)); err == nil {
		t.Fatal("unbounded path accepted")
	}
}

func TestCopyEnumerationPrivateDatabasePathCannotBecomeDSNOptions(t *testing.T) {
	for _, component := range []string{"parent ? literal # percent% ü", "parent ?_pragma=journal_mode(WAL) # ü"} {
		t.Run(component, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), component)
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			spool := filepath.Join(parent, "spool")
			if err := os.Mkdir(spool, 0700); err != nil {
				t.Fatal(err)
			}
			s, err := newCopyEnumerationState(context.Background(), spool, copyMetadataDatabaseBytes)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			var seq int
			var name, filename string
			if err := s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &filename); err != nil {
				t.Fatal(err)
			}
			expected := filepath.Join(s.directory, "state.sqlite")
			if filename != expected {
				t.Fatalf("database escaped private directory or interpreted path as DSN: actual=%q expected=%q", filename, expected)
			}
			info, err := os.Stat(filename)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private DB permissions", info, err)
			}
			if err := s.markCompleted(context.Background(), "verified-only"); err != nil {
				t.Fatal(err)
			}
			if err := s.close(); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || entries[0].Name() != "spool" {
				t.Fatal("metadata escaped cleanup", entries, err)
			}
		})
	}
}

func TestCopyEnumerationMetadataCapStopsWithoutFalseSuccess(t *testing.T) {
	s := enumerationStateForTest(t, 8*4096)
	ctx := context.Background()
	var failure error
	for i := range 128 {
		failure = s.markCompleted(ctx, fmt.Sprintf("%d/%s", i, strings.Repeat("x", 4000)))
		if failure != nil {
			break
		}
	}
	if failure == nil {
		t.Fatal("metadata cap ignored")
	}
	var pages, limit int64
	_ = s.db.QueryRow("PRAGMA page_count").Scan(&pages)
	_ = s.db.QueryRow("PRAGMA max_page_count").Scan(&limit)
	if pages > limit || limit != 8 {
		t.Fatal("database bytes escaped cap", pages, limit)
	}
	// The caller cancels this invocation on the error. The successful buffer is
	// not persisted as a baseline and cannot authorize another invocation.
	t.Log("bounded resource failure", failure)
}

type hookedEnumerationFS struct {
	beforeOpen func(string) error
	beforeRead func(string, int) error
}

func (f hookedEnumerationFS) Lstat(p string) (fs.FileInfo, error) { return os.Lstat(p) }
func (f hookedEnumerationFS) OpenDirectory(p string) (copyDirectoryReader, error) {
	if f.beforeOpen != nil {
		if err := f.beforeOpen(p); err != nil {
			return nil, err
		}
	}
	r, err := osCopyEnumerationFS{}.OpenDirectory(p)
	if err != nil {
		return nil, err
	}
	return &hookedEnumerationDirectory{r: r, path: p, hook: f.beforeRead}, nil
}

type hookedEnumerationDirectory struct {
	r     copyDirectoryReader
	path  string
	reads int
	hook  func(string, int) error
}

func (d *hookedEnumerationDirectory) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.hook != nil {
		if err := d.hook(d.path, d.reads); err != nil {
			return nil, err
		}
	}
	d.reads++
	return d.r.ReadDir(n)
}
func (d *hookedEnumerationDirectory) Close() error { return d.r.Close() }

func TestCopyEnumerationFirstPublishBeforeWideReadCompletesAndCancelCleanup(t *testing.T) {
	f := newPipelineFixture(t)
	names := make([]string, 257)
	for i := range names {
		names[i] = fmt.Sprintf("f-%04d", i)
	}
	root, _ := writePipelineFiles(t, names, []byte("verified"))
	spool := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	budget := newCopyBudget(2, 1, MaxFileBytes)
	blocked := make(chan struct{})
	var once sync.Once
	filesystem := hookedEnumerationFS{beforeRead: func(p string, reads int) error {
		if p == root && reads == 1 {
			// Exactly one 128-descriptor batch has been returned. A file must
			// already have published before the second batch is requested.
			select {
			case <-f.started:
			case <-ctx.Done():
				return ctx.Err()
			}
			for {
				f.mu.Lock()
				published := len(f.files) > 0
				f.mu.Unlock()
				if published {
					break
				}
				select {
				case <-time.After(time.Millisecond):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			once.Do(func() { close(blocked) })
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}
	result := make(chan error, 1)
	go func() {
		_, err := copyPipelineWithFS(ctx, f.remote(), []string{root}, spool, budget, filesystem)
		result <- err
	}()
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("enumeration did not publish before remaining batch")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel leaked enumeration/worker")
	}
	assertPipelineClean(t, spool, budget)
	entries, err := os.ReadDir(filepath.Dir(spool))
	if err != nil || len(entries) != 1 || entries[0].Name() != "spool" {
		t.Fatal("temporary metadata leaked", entries, err)
	}
	if len(budget.enumerators) != 0 || budget.metadataBytes != 0 {
		t.Fatal("enumeration reservation leaked")
	}
}

func TestCopyEnumerationOverlappingFailureCanRetryAndUnreadableParentDoesNotHideDirectSource(t *testing.T) {
	f := newPipelineFixture(t)
	root, files := writePipelineFiles(t, []string{"healthy", "retry"}, []byte("verified"))
	transport := f.server.Client().Transport
	var mu sync.Mutex
	failed := false
	client := &http.Client{Transport: pipelineRoundTripper(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		reject := r.Method == "PUT" && r.URL.Query().Get("path") == RelativePath(files[1]) && !failed
		if reject {
			failed = true
		}
		mu.Unlock()
		if reject {
			// An explicit pre-effect rejection is local to this source entry.
			// A 5xx is transport uncertainty and correctly stops the whole cycle.
			return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader("fixture rejected before write")), Header: make(http.Header)}, nil
		}
		return transport.RoundTrip(r)
	})}
	spool := filepath.Join(t.TempDir(), "spool")
	_ = os.Mkdir(spool, 0700)
	n, err := copyPipeline(context.Background(), Remote{client, f.server.URL, "fixture"}, []string{root, root, files[0], files[1]}, spool, newCopyBudget(2, 1, MaxFileBytes))
	if n != 2 || err == nil || !strings.Contains(err.Error(), "1 source entries failed") || len(f.files) != 2 {
		t.Fatal("failed overlap was hidden or confirmed success recopied", n, err, len(f.files))
	}
	f2 := newPipelineFixture(t)
	filesystem := hookedEnumerationFS{beforeOpen: func(p string) error {
		if p == root {
			return fs.ErrPermission
		}
		return nil
	}}
	n, err = copyPipelineWithFS(context.Background(), f2.remote(), []string{root, files[0]}, spool, newCopyBudget(2, 1, MaxFileBytes), filesystem)
	if n != 1 || err == nil || !strings.Contains(err.Error(), "service account") || len(f2.files) != 1 {
		t.Fatal("unreadable parent hid explicit source", n, err)
	}
}

func TestCopyEnumerationSourceIdentityRelativeAbsoluteDotAndDuplicate(t *testing.T) {
	// Chdir is test-local and cannot be used with parallel tests.
	f := newPipelineFixture(t)
	root, files := writePipelineFiles(t, []string{"file"}, []byte("same inode, legacy identities"))
	t.Chdir(root)
	spool := filepath.Join(t.TempDir(), "spool")
	n, err := Copy(context.Background(), f.remote(), []string{"file", "file", "./file", files[0], root}, spool)
	if n != 3 || err != nil {
		t.Fatal(n, err)
	}
	for _, p := range []string{"file", "./file", RelativePath(files[0])} {
		if _, ok := f.files[p]; !ok {
			t.Fatal("changed remote path identity", p)
		}
	}
}

func TestCopyEnumerationDirectoryReplacementBySymlinkIsNotTraversed(t *testing.T) {
	f := newPipelineFixture(t)
	root, _ := writePipelineFiles(t, []string{"healthy"}, []byte("safe"))
	child := filepath.Join(root, "directory")
	outside := t.TempDir()
	_ = os.Mkdir(child, 0700)
	_ = os.WriteFile(filepath.Join(outside, "secret"), []byte("do not traverse"), 0600)
	filesystem := hookedEnumerationFS{beforeOpen: func(p string) error {
		if p == child {
			if err := os.Remove(child); err != nil {
				return err
			}
			return os.Symlink(outside, child)
		}
		return nil
	}}
	spool := filepath.Join(t.TempDir(), "spool")
	_ = os.Mkdir(spool, 0700)
	n, err := copyPipelineWithFS(context.Background(), f.remote(), []string{root}, spool, newCopyBudget(2, 1, MaxFileBytes), filesystem)
	if n != 1 || err == nil || len(f.files) != 1 {
		t.Fatal("traversed replacement directory link", n, err, len(f.files))
	}
}

func TestCopyEnumerationReadErrorProcessesReturnedDescriptorsAndReportsOnce(t *testing.T) {
	s := enumerationStateForTest(t, copyMetadataDatabaseBytes)
	filesystem := &syntheticEnumerationFS{count: 257}
	filesystem.gate = func(offset int) error {
		if offset >= 128 {
			return fs.ErrPermission
		}
		return nil
	}
	files, failures := 0, 0
	err := streamCopySource(context.Background(), "root", filesystem, s, func(_ string, e fs.DirEntry, err error) error {
		if err != nil {
			failures++
			return nil
		}
		if !e.IsDir() {
			files++
		}
		return nil
	})
	if err != nil || files != 128 || failures != 1 || filesystem.open != 0 {
		t.Fatal(files, failures, filesystem.open, err)
	}
}
