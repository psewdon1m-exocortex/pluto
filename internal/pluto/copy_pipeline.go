package pluto

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sync"

	"pluto/internal/pluto/syncstate"
)

const (
	copyWorkers     = 2
	copyQueueSize   = 2
	copyBufferBytes = 64 * 1024
	parentCacheSize = 4096
)

// The daemon permits one Copy at a time. Keep these limits process-wide too:
// callers cannot multiply active transfers, source readers or plaintext spool.
var copyResources = newCopyBudget(copyWorkers, 1, MaxFileBytes)

type copyBudget struct {
	workers, readers    chan struct{}
	enumerators         chan struct{}
	mu                  sync.Mutex
	spoolBytes          int64
	retainedBytes       int64
	liveArtifactBytes   int64 // included in retainedBytes, still owned by active captures
	artifactOwner       string
	artifactScope       string
	artifactBootstrap   bool
	artifactDetached    bool
	artifactDirectories []string
	artifactProfile     os.FileInfo
	metadataBytes       int64
	spoolLimit          int64
	changed             chan struct{}
	spoolFailure        error
}

func newCopyBudget(workers, readers int, spoolLimit int64) *copyBudget {
	return &copyBudget{workers: make(chan struct{}, workers), readers: make(chan struct{}, readers), enumerators: make(chan struct{}, 1), spoolLimit: spoolLimit, changed: make(chan struct{})}
}

func (b *copyBudget) acquireEnumeration(ctx context.Context, directory string, maxMetadataBytes int64) error {
	if err := acquireCopySlot(ctx, b.enumerators); err != nil {
		return err
	}
	b.mu.Lock()
	// Reserve the capped DB, at most another DB's pages in DELETE rollback
	// journal, plus page/journal headers. This is separate from plaintext spool.
	metadataReservation := 2*maxMetadataBytes + 16*1024*1024
	err := b.spoolFailure
	if err == nil {
		err = b.artifactDirectory(directory)
	}
	if err == nil && b.artifactBootstrap {
		err = syncstate.ErrArtifactUnreconciled
	}
	if err == nil {
		err = checkSpoolSpace(directory, b.spoolBytes+b.retainedBytes+metadataReservation)
	}
	if err == nil {
		err = checkSpoolSpace(filepath.Dir(directory), metadataReservation)
	}
	if err == nil {
		b.metadataBytes = metadataReservation
	}
	b.mu.Unlock()
	if err != nil {
		<-b.enumerators
	}
	return err
}

func (b *copyBudget) releaseEnumeration() {
	b.mu.Lock()
	b.metadataBytes = 0
	b.mu.Unlock()
	<-b.enumerators
}

func acquireCopySlot(ctx context.Context, slots chan struct{}) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (b *copyBudget) acquireWorker(ctx context.Context) error {
	b.mu.Lock()
	bootstrapping := b.artifactBootstrap
	b.mu.Unlock()
	if bootstrapping {
		return syncstate.ErrArtifactUnreconciled
	}
	if err := acquireCopySlot(ctx, b.workers); err != nil {
		return err
	}
	if ctx.Err() != nil {
		<-b.workers
		return context.Cause(ctx)
	}
	b.mu.Lock()
	bootstrapping = b.artifactBootstrap
	b.mu.Unlock()
	if bootstrapping {
		<-b.workers
		return syncstate.ErrArtifactUnreconciled
	}
	return nil
}
func (b *copyBudget) releaseWorker()                          { <-b.workers }
func (b *copyBudget) acquireReader(ctx context.Context) error { return acquireCopySlot(ctx, b.readers) }
func (b *copyBudget) releaseReader()                          { <-b.readers }

func (b *copyBudget) reserveSpool(ctx context.Context, directory string, size int64) error {
	if size < 0 || size > b.spoolLimit {
		return errors.New("source exceeds the verified snapshot spool budget")
	}
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		b.mu.Lock()
		if b.spoolFailure != nil {
			err := b.spoolFailure
			b.mu.Unlock()
			return err
		}
		if b.artifactBootstrap {
			b.mu.Unlock()
			return syncstate.ErrArtifactUnreconciled
		}
		if err := b.artifactDirectory(directory); err != nil {
			b.mu.Unlock()
			return err
		}
		// Durable originals cannot free their charge inside this capture. Only
		// live captures may finish while we wait; report required recovery when
		// even all of those completions could not admit this file.
		if size > b.spoolLimit-(b.retainedBytes-b.liveArtifactBytes) {
			b.mu.Unlock()
			return syncstate.ErrArtifactRetained
		}
		if size <= b.spoolLimit-b.spoolBytes-b.retainedBytes {
			// Include outstanding reservations: simultaneous captures must not
			// each spend the same currently free space. This is conservative once
			// part of a reserved snapshot has already been written.
			err := checkSpoolSpace(directory, b.spoolBytes+b.retainedBytes+size+b.metadataBytes)
			if err == nil {
				b.spoolBytes += size
			}
			b.mu.Unlock()
			return err
		}
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

// Install only before any work. Retained bytes do not disappear when an inactive
// admission handle closes; they remain charged until verified registry disposal.
func (b *copyBudget) installArtifactOwner(owner string, retained int64, directories ...string) error {
	return b.installArtifactScope(owner, owner, retained, directories...)
}

func (b *copyBudget) installArtifactScope(owner, scope string, retained int64, directories ...string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if owner == "" || scope == "" || retained < 0 || retained > b.spoolLimit || b.spoolFailure != nil || b.artifactOwner != "" && (!b.artifactDetached || b.artifactScope != scope) || b.spoolBytes != 0 || b.liveArtifactBytes != 0 || len(b.workers) != 0 || len(b.readers) != 0 || len(b.enumerators) != 0 {
		return syncstate.ErrArtifactInUse
	}
	if len(directories) < 1 || len(directories) > 2 {
		return syncstate.ErrIdentityConflict
	}
	allowedDirectories := make([]string, 0, len(directories))
	for _, dir := range directories {
		absolute, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		if len(allowedDirectories) > 0 && filepath.Dir(absolute) != filepath.Dir(allowedDirectories[0]) {
			return syncstate.ErrIdentityConflict
		}
		allowedDirectories = append(allowedDirectories, absolute)
	}
	profile, err := os.Lstat(filepath.Dir(allowedDirectories[0]))
	if err != nil || !profile.IsDir() || profile.Mode()&os.ModeSymlink != 0 {
		return errors.Join(syncstate.ErrIdentityConflict, err)
	}
	if b.artifactDetached && !os.SameFile(profile, b.artifactProfile) {
		return syncstate.ErrIdentityConflict
	}
	b.artifactProfile = profile
	b.artifactDirectories = allowedDirectories
	b.artifactOwner = owner
	b.artifactScope = scope
	b.retainedBytes = retained
	b.artifactBootstrap = true
	b.artifactDetached = false
	return nil
}

// The optional hook cannot silently treat an arbitrary Direct Copy spool path
// as this admitted profile. Only the exact two private directories are allowed.
func (b *copyBudget) artifactDirectory(directory string) error {
	if b.artifactOwner == "" {
		return nil
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	allowed := false
	for _, dir := range b.artifactDirectories {
		if absolute == dir {
			allowed = true
			break
		}
	}
	if !allowed {
		return syncstate.ErrIdentityConflict
	}
	profile, err := os.Lstat(filepath.Dir(absolute))
	if err != nil || !os.SameFile(profile, b.artifactProfile) || profile.Mode()&os.ModeSymlink != 0 || profile.Mode().Perm()&0022 != 0 {
		return errors.Join(syncstate.ErrIdentityConflict, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.Join(syncstate.ErrIdentityConflict, err)
	}
	return nil
}
func (b *copyBudget) completeArtifactBootstrap(owner string, retained int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.artifactOwner != owner || !b.artifactBootstrap || retained < 0 || retained > b.spoolLimit || b.spoolBytes != 0 {
		return syncstate.ErrIdentityConflict
	}
	b.retainedBytes = retained
	b.artifactBootstrap = false
	close(b.changed)
	b.changed = make(chan struct{})
	return nil
}
func (b *copyBudget) retainReservation(owner string, size int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.artifactOwner != owner || size < 0 || size > b.spoolBytes {
		return syncstate.ErrIdentityConflict
	}
	b.spoolBytes -= size
	b.retainedBytes += size
	b.liveArtifactBytes += size
	return nil
}

func (b *copyBudget) finishArtifactCapture(owner string, size int64, retain bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.artifactOwner != owner || size < 0 || size > b.liveArtifactBytes || size > b.retainedBytes {
		return syncstate.ErrIdentityConflict
	}
	b.liveArtifactBytes -= size
	if !retain {
		b.retainedBytes -= size
	}
	// A completed failed capture may make further admission impossible even
	// though no bytes were freed. Wake existing waiters to report that state.
	close(b.changed)
	b.changed = make(chan struct{})
	return nil
}

func (b *copyBudget) releaseRetained(owner string, size int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.artifactOwner != owner || size < 0 || size > b.retainedBytes-b.liveArtifactBytes {
		return syncstate.ErrIdentityConflict
	}
	b.retainedBytes -= size
	close(b.changed)
	b.changed = make(chan struct{})
	return nil
}

func (b *copyBudget) blockSpool(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spoolFailure = err
	close(b.changed)
	b.changed = make(chan struct{})
}

func (b *copyBudget) releaseSpool(size int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spoolBytes -= size
	close(b.changed)
	b.changed = make(chan struct{})
}

type copyContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *copyContextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, context.Cause(r.ctx)
	}
	return r.reader.Read(p)
}

type snapshotWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *snapshotWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("source grew beyond its reserved snapshot")
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

type parentFlight struct {
	done chan struct{}
	err  error
}

type parentEnsurer struct {
	remote     Remote
	mu         sync.Mutex
	ready      map[string]*list.Element
	lru        *list.List
	inflight   map[string]*parentFlight
	generation uint64
}

func newParentEnsurer(r Remote) *parentEnsurer {
	return &parentEnsurer{remote: r, ready: make(map[string]*list.Element), lru: list.New(), inflight: make(map[string]*parentFlight)}
}

func (p *parentEnsurer) ensure(ctx context.Context, relative string) error {
	if relative == "." || relative == "" {
		return nil
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	p.mu.Lock()
	if ready := p.ready[relative]; ready != nil {
		p.lru.MoveToFront(ready)
		p.mu.Unlock()
		return nil
	}
	if flight := p.inflight[relative]; flight != nil {
		p.mu.Unlock()
		select {
		case <-flight.done:
			return flight.err
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	flight := &parentFlight{done: make(chan struct{})}
	p.inflight[relative] = flight
	generation := p.generation
	p.mu.Unlock()

	err := p.ensure(ctx, path.Dir(relative))
	if err == nil {
		var meta Metadata
		err = p.remote.request(ctx, "GET", "/api/v1/pluto/files?path="+url.QueryEscape(relative), nil, -1, nil, &meta)
		if err == nil {
			if meta.Type != "folder" {
				err = errors.New("destination directory conflicts with a file")
			}
		} else {
			var remote *HTTPError
			if errors.As(err, &remote) && remote.Status == 404 {
				err = p.remote.json(ctx, "POST", "/api/v1/pluto/folders", map[string]string{"path": relative}, nil)
			}
		}
	}

	p.mu.Lock()
	if err == nil && generation == p.generation {
		p.ready[relative] = p.lru.PushFront(relative)
		if p.lru.Len() > parentCacheSize {
			oldest := p.lru.Back()
			delete(p.ready, oldest.Value.(string))
			p.lru.Remove(oldest)
		}
	}
	flight.err = err
	delete(p.inflight, relative)
	close(flight.done)
	p.mu.Unlock()
	return err
}

// A destination disappearance/conflict invalidates assumptions for following
// jobs. Do not turn a failed publication into a blind retry or accepted receipt.
func (p *parentEnsurer) invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.generation++
	clear(p.ready)
	p.lru.Init()
}

type copyJob struct {
	sequence int
	filename string
	entry    fs.DirEntry
	done     chan struct{}
}

type copyFailure struct {
	sequence int
	filename string
	err      error
}

type copyResults struct {
	mu          sync.Mutex
	uploaded    int
	failedCount int
	failures    []copyFailure
	pending     map[string]chan struct{}
}

func (r *copyResults) record(sequence int, filename string, uploaded bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if uploaded {
		r.uploaded++
	}
	if err != nil {
		r.failedCount++
		r.failures = append(r.failures, copyFailure{sequence, filename, fmt.Errorf("%s: %w", filename, err)})
		// Select at most twenty deterministically by source ordinal and path.
		// Streaming enumeration deliberately promises no lexical transfer order.
		slices.SortFunc(r.failures, func(a, b copyFailure) int {
			if a.sequence != b.sequence {
				return a.sequence - b.sequence
			}
			if a.filename < b.filename {
				return -1
			}
			if a.filename > b.filename {
				return 1
			}
			return 0
		})
		if len(r.failures) > 20 {
			r.failures = r.failures[:20]
		}
	}
}

func copyPipeline(parent context.Context, remote Remote, sources []string, spoolDir string, budget *copyBudget) (int, error) {
	return copyPipelineWithFS(parent, remote, sources, spoolDir, budget, osCopyEnumerationFS{})
}

func copyPipelineWithFS(parent context.Context, remote Remote, sources []string, spoolDir string, budget *copyBudget, filesystem copyEnumerationFS) (uploaded int, finalErr error) {
	return copyPipelineConfigured(parent, remote, sources, spoolDir, budget, filesystem, copyMetadataDatabaseBytes)
}

func copyPipelineConfigured(parent context.Context, remote Remote, sources []string, spoolDir string, budget *copyBudget, filesystem copyEnumerationFS, maxMetadataBytes int64) (uploaded int, finalErr error) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	if err := budget.acquireEnumeration(ctx, spoolDir, maxMetadataBytes); err != nil {
		return 0, err
	}
	defer budget.releaseEnumeration()
	state, err := newCopyEnumerationState(ctx, spoolDir, maxMetadataBytes)
	if err != nil {
		return 0, errors.Join(errCopyEnumerationState, err)
	}
	defer func() {
		if err := state.close(); err != nil {
			cleanupErr := errors.Join(errSnapshotCleanup, err)
			budget.blockSpool(cleanupErr)
			finalErr = errors.Join(finalErr, cleanupErr)
		}
	}()
	parents := newParentEnsurer(remote)
	results := &copyResults{pending: make(map[string]chan struct{})}
	jobs := make(chan copyJob, copyQueueSize)
	var workers sync.WaitGroup
	stopOnFailure := func(err error) {
		var denied *HTTPError
		if (errors.As(err, &denied) && (denied.Status == 401 || denied.Status == 403)) || networkWaitState(err) != "" || errors.Is(err, errSnapshotCleanup) || errors.Is(err, errCopyEnumerationState) {
			cancel(err)
		}
	}
	report := func(sequence int, filename string, uploaded bool, err error) {
		if err == nil {
			progressFrom(ctx).checkedFile(uploaded)
		}
		stopOnFailure(err)
		if ctx.Err() == nil || uploaded {
			results.record(sequence, filename, uploaded, err)
		}
	}
	for range copyWorkers {
		workers.Go(func() {
			for job := range jobs {
				var uploaded bool
				err := context.Cause(ctx)
				if err == nil {
					uploaded, err = copyFile(ctx, remote, job.filename, job.entry, spoolDir, parents, budget, stopOnFailure)
				}
				results.mu.Lock()
				if err == nil {
					if stateErr := state.markCompleted(ctx, RelativePath(job.filename)); stateErr != nil {
						err = errors.Join(errCopyEnumerationState, stateErr)
						cancel(err)
					}
				}
				delete(results.pending, RelativePath(job.filename))
				close(job.done)
				results.mu.Unlock()
				report(job.sequence, job.filename, uploaded, err)
			}
		})
	}
	for sequence, source := range sources {
		err := streamCopySource(ctx, source, filesystem, state, func(filename string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			var err error
			if walkErr != nil {
				err = errors.New("source cannot be read by the Pluto service account; check directory traversal and file read permissions")
			} else if entry.IsDir() {
				err = parents.ensure(ctx, RelativePath(filename))
			} else {
				relative := RelativePath(filename)
				for {
					results.mu.Lock()
					completed, stateErr := state.hasCompleted(ctx, relative)
					if stateErr != nil {
						results.mu.Unlock()
						return errors.Join(errCopyEnumerationState, stateErr)
					}
					if completed {
						results.mu.Unlock()
						return nil
					}
					if pending := results.pending[relative]; pending != nil {
						results.mu.Unlock()
						select {
						case <-pending:
							continue
						case <-ctx.Done():
							return context.Cause(ctx)
						}
					}
					done := make(chan struct{})
					progressFrom(ctx).discover()
					results.pending[relative] = done
					results.mu.Unlock()
					select {
					case jobs <- copyJob{sequence, filename, entry, done}:
						return nil
					case <-ctx.Done():
						results.mu.Lock()
						delete(results.pending, relative)
						close(done)
						results.mu.Unlock()
						return context.Cause(ctx)
					}
				}
			}
			if err != nil {
				report(sequence, filename, false, err)
				if ctx.Err() != nil {
					return context.Cause(ctx)
				}
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
			}
			return nil
		})
		if err != nil {
			cancel(err)
			break
		}
	}
	close(jobs)
	if ctx.Err() == nil {
		progressFrom(ctx).enumerationComplete()
	}
	workers.Wait()
	if ctx.Err() != nil {
		return results.uploaded, context.Cause(ctx)
	}
	if results.failedCount > 0 {
		failures := make([]error, len(results.failures))
		for i, failure := range results.failures {
			failures[i] = failure.err
		}
		return results.uploaded, fmt.Errorf("%d source entries failed: %w", results.failedCount, errors.Join(failures...))
	}
	return results.uploaded, nil
}

func destinationChanged(err error) bool {
	var remote *HTTPError
	return errors.As(err, &remote) && (remote.Status == 404 || remote.Status == 409 || remote.Status == 412)
}

var errSnapshotCleanup = errors.New("verified snapshot cleanup failed; restart after cleaning the Pluto spool")
