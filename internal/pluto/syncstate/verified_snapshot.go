package syncstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// CaptureLimiter is supplied by Pluto's existing process-wide source/spool
// adapter. Calling CaptureGuarded without resource admission is unsupported.
type CaptureLimiter interface {
	ReserveCapture(context.Context, string, int64) (func(), error)
	RegisterCaptureArtifact(string, int64) error
	AcquireCaptureReader(context.Context) (func(), error)
}

// Optional durable lifecycle used only by the inactive registry admission hook.
// Existing generic captures retain their conservative temporary-file behavior.
type CaptureArtifacts interface {
	CreateCaptureArtifact(context.Context, string) (*os.File, string, error)
	SealCaptureArtifact(context.Context, *VerifiedSnapshot) error
	DisposeCaptureArtifact(context.Context, string) error
	RetainCaptureArtifact(context.Context, string) error
}
type VerifiedSnapshot struct {
	mu                     sync.Mutex
	evidence               SnapshotEvidence
	physicalPath, filename string
	sourceIdentity         string
	sealed                 os.FileInfo
	limiter                CaptureLimiter
	release                func()
	closed                 bool
	validation             *captureValidation
	scopeDisposition       string
}

func (v *VerifiedSnapshot) Evidence() SnapshotEvidence {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.evidence
}
func (v *VerifiedSnapshot) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.validation != nil {
		v.scopeDisposition = "close"
		return nil
	}
	if v.closed {
		return nil
	}
	var err error
	if artifacts, ok := v.limiter.(CaptureArtifacts); ok {
		err = artifacts.DisposeCaptureArtifact(context.Background(), v.filename)
	} else {
		err = os.Remove(v.filename)
	}
	if err == nil || errors.Is(err, os.ErrNotExist) {
		v.closed = true
		v.release()
		return nil
	}
	return err
}

// Retain joins this capture's reference without deleting bytes needed by an
// existing operation. Durable registry charge survives the handle/process.
func (v *VerifiedSnapshot) Retain() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.validation != nil {
		v.scopeDisposition = "retain"
		return nil
	}
	if v.closed {
		return nil
	}
	artifacts, ok := v.limiter.(CaptureArtifacts)
	if !ok {
		return ErrIdentityConflict
	}
	if err := artifacts.RetainCaptureArtifact(context.Background(), v.filename); err != nil {
		return err
	}
	v.closed = true
	v.release()
	return nil
}

type captureContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r captureContextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

type captureBoundWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *captureBoundWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, ErrCaptureChanged
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
func statIdentity(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d", st.Dev, st.Ino, st.Mode)
}
func statCTime(info os.FileInfo) int64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ctim.Sec*1e9 + st.Ctim.Nsec
}
func linkGuard(filename string) (string, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	guard := statIdentity(info)
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(filename)
		if err != nil {
			return "", err
		}
		guard += "/" + hashBytes([]byte(target))
	}
	return guard, nil
}

// CaptureGuarded seals exact bytes; it does not prove an atomic filesystem or
// application snapshot, future unchanged content, or continuous root history.
func CaptureGuarded(ctx context.Context, w SourceWitness, entry SourceEntry, spoolDirectory string, limiter CaptureLimiter) (snapshot *VerifiedSnapshot, err error) {
	return captureGuarded(ctx, w, entry, spoolDirectory, limiter, nil)
}
func captureGuarded(ctx context.Context, w SourceWitness, entry SourceEntry, spoolDirectory string, limiter CaptureLimiter, afterRead func()) (snapshot *VerifiedSnapshot, err error) {
	return captureGuardedUse(ctx, w, entry, spoolDirectory, limiter, afterRead, nil)
}

// CaptureAndUseGuarded keeps sealing and the synchronous consumer inside one
// validated private descriptor scope. A successful seal is still durable before
// use; transport hashing, receipt/CAS checks and retained recovery are unchanged.
// The consumer must join all users before returning and cannot retain this handle.
func CaptureAndUseGuarded(ctx context.Context, w SourceWitness, entry SourceEntry, spoolDirectory string, limiter CaptureLimiter, use func(*VerifiedSnapshot) error) error {
	if use == nil {
		return ErrIdentityConflict
	}
	_, err := captureGuardedUse(ctx, w, entry, spoolDirectory, limiter, nil, func(v *VerifiedSnapshot) (err error) {
		defer func() {
			v.mu.Lock()
			// Respect an explicit retain/close requested by the consumer. Otherwise
			// the lexical owner closes it; pending operations automatically retain.
			if v.scopeDisposition == "" {
				v.scopeDisposition = "close"
			}
			v.mu.Unlock()
		}()
		return use(v)
	})
	return err
}

func captureGuardedUse(ctx context.Context, w SourceWitness, entry SourceEntry, spoolDirectory string, limiter CaptureLimiter, afterRead func(), use func(*VerifiedSnapshot) error) (snapshot *VerifiedSnapshot, err error) {
	if limiter == nil || entry.Ambiguous || entry.Kind != "file" || entry.Presence != "PRESENT" || entry.Generation < 1 || entry.VerificationRequest < 1 || entry.SetID != w.SetID || w.OwnerID == "" || !validID(entry.SourceID) || entry.SourceIncarnation < 1 || entry.SizeBytes < 0 || entry.SizeBytes > MaxFileBytes {
		return nil, ErrIdentityConflict
	}
	// Admit before opening source descriptors: callers cannot accumulate open
	// files while waiting for the shared two-data-slot or plaintext budget.
	if err = os.MkdirAll(spoolDirectory, 0700); err != nil {
		return nil, err
	}
	directory, err := os.Lstat(spoolDirectory)
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIdentityConflict
	}
	release, err := limiter.ReserveCapture(ctx, spoolDirectory, entry.SizeBytes)
	if err != nil {
		return nil, err
	}
	keep, removed := false, true
	defer func() {
		if !keep && removed {
			release()
		}
	}()
	sourceObject, err := ObserveSourceIncarnation(entry.SourceRootPath)
	if err != nil {
		return nil, err
	}
	if sourceObject.object != entry.SourceObject {
		return nil, ErrCaptureChanged
	}
	beforeLink, err := linkGuard(entry.PhysicalPath)
	if err != nil {
		return nil, err
	}
	source, err := os.OpenFile(entry.PhysicalPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > MaxFileBytes || before.Size() < 0 || statIdentity(before) == "" {
		return nil, errors.New("capture requires a regular file no larger than256MiB")
	}
	if statIdentity(before) != entry.FileIdentity || before.Size() != entry.SizeBytes || before.ModTime().UnixNano() != entry.MTimeNS || statCTime(before) != entry.CTimeNS {
		return nil, ErrCaptureChanged
	}
	// Separate from Serve's legacy copy-* cleanup. The adapter refuses admission
	// on unknown artifacts after restart; R1b still needs durable intent recovery.
	var temp *os.File
	var id string
	if artifacts, ok := limiter.(CaptureArtifacts); ok {
		temp, id, err = artifacts.CreateCaptureArtifact(ctx, spoolDirectory)
	} else {
		temp, err = os.CreateTemp(spoolDirectory, "source-sealed-*")
		if err == nil {
			id, err = NewOperationID()
		}
	}
	defer func() {
		if !keep && temp != nil {
			temp.Close()
			var removeErr error
			if artifacts, ok := limiter.(CaptureArtifacts); ok {
				removeErr = artifacts.DisposeCaptureArtifact(context.Background(), temp.Name())
			} else {
				removeErr = os.Remove(temp.Name())
			}
			if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				removed = false
				err = errors.Join(err, removeErr)
			}
		}
	}()
	if err != nil {
		return nil, err
	}
	if err = limiter.RegisterCaptureArtifact(temp.Name(), before.Size()); err != nil {
		return nil, err
	}
	releaseReader, err := limiter.AcquireCaptureReader(ctx)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	n, copyErr := io.CopyBuffer(&captureBoundWriter{writer: io.MultiWriter(temp, digest), remaining: before.Size()}, captureContextReader{ctx, io.LimitReader(source, before.Size()+1)}, make([]byte, 65536))
	captureSourceReads.Add(1)
	captureSourceBytes.Add(n)
	releaseReader()
	if copyErr != nil {
		return nil, copyErr
	}
	if n != before.Size() {
		return nil, ErrCaptureChanged
	}
	if afterRead != nil {
		afterRead()
	}
	after, err := source.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Stat(entry.PhysicalPath)
	if err != nil {
		return nil, err
	}
	afterLink, err := linkGuard(entry.PhysicalPath)
	if err != nil {
		return nil, err
	}
	if statIdentity(before) != statIdentity(after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || statCTime(before) != statCTime(after) || beforeLink != afterLink {
		return nil, ErrCaptureChanged
	}
	currentObject, err := ObserveSourceIncarnation(entry.SourceRootPath)
	if err != nil {
		return nil, err
	}
	if currentObject.object != sourceObject.object {
		return nil, ErrCaptureChanged
	}
	if err = temp.Sync(); err != nil {
		return nil, err
	}
	if err = temp.Chmod(0400); err != nil {
		return nil, err
	}
	if err = temp.Sync(); err != nil {
		return nil, err
	}
	if err = temp.Close(); err != nil {
		return nil, err
	}
	sealed, err := os.Stat(temp.Name())
	if err != nil {
		return nil, err
	}
	evidence := SnapshotEvidence{SetID: w.SetID, SourceID: entry.SourceID, SourceIncarnation: entry.SourceIncarnation, Destination: entry.Destination, SnapshotID: id, SHA256: hex.EncodeToString(digest.Sum(nil)), GuardDigest: fingerprint([]any{beforeLink, statIdentity(before), before.Size(), before.ModTime().UnixNano(), statCTime(before), afterLink, sourceObject.object}), Witness: w, EntryGeneration: entry.Generation, VerificationRequest: entry.VerificationRequest, SizeBytes: n}
	snapshot = &VerifiedSnapshot{evidence: evidence, physicalPath: entry.PhysicalPath, sourceIdentity: statIdentity(before), filename: temp.Name(), sealed: sealed, limiter: limiter, release: release}
	sealAndUse := func() error {
		if artifacts, ok := limiter.(CaptureArtifacts); ok {
			if err := artifacts.SealCaptureArtifact(ctx, snapshot); err != nil {
				return err
			}
		}
		keep = true
		if use != nil {
			return use(snapshot)
		}
		return nil
	}
	if use != nil {
		err = WithValidatedCapture(ctx, snapshot, sealAndUse)
	} else {
		err = sealAndUse()
	}
	return snapshot, err
}
func (v *VerifiedSnapshot) integrity(ctx context.Context) error {
	if v.validation != nil {
		return v.validation.check(v, ctx)
	}
	if v.closed || v.filename == "" || v.release == nil || !validHash(v.evidence.SHA256) || !validHash(v.evidence.GuardDigest) {
		return ErrInvalidReceipt
	}
	file, err := os.OpenFile(v.filename, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, v.sealed) || !info.Mode().IsRegular() || info.Size() != v.evidence.SizeBytes {
		return ErrInvalidReceipt
	}
	done, err := v.limiter.AcquireCaptureReader(ctx)
	if err != nil {
		return err
	}
	defer done()
	h := sha256.New()
	n, err := io.CopyBuffer(h, captureContextReader{ctx, io.LimitReader(file, v.evidence.SizeBytes+1)}, make([]byte, 65536))
	capturePrivateReads.Add(1)
	capturePrivateBytes.Add(n)
	if err != nil {
		return err
	}
	if n != v.evidence.SizeBytes || hex.EncodeToString(h.Sum(nil)) != v.evidence.SHA256 {
		return ErrInvalidReceipt
	}
	return nil
}
func (s *Sources) RecordVerifiedSnapshot(ctx context.Context, w SourceWitness, v *VerifiedSnapshot) error {
	if v == nil {
		return ErrInvalidReceipt
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.evidence.Witness != w {
		return ErrStaleGeneration
	}
	if err := v.integrity(ctx); err != nil {
		return err
	}
	// Keep a registered capture's historical proof and the source generation in
	// one commit. The ordering matches sealing: private snapshot, registry, source.
	var registry *Artifacts
	if a := s.store.artifacts; a != nil && filepath.Dir(v.filename) == a.path {
		registry = a
		a.mu.Lock()
		defer a.mu.Unlock()
	}
	committed := v.evidence
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		set, err := s.checkWitness(ctx, tx, w)
		if err != nil {
			return err
		}
		e := v.evidence
		entry, err := readSourceEntry(ctx, tx, w.SetID, e.Destination)
		if err != nil {
			return err
		}
		if entry.Ambiguous || entry.Generation != e.EntryGeneration || entry.VerificationRequest != e.VerificationRequest || entry.PhysicalPath != v.physicalPath {
			return ErrStaleGeneration
		}
		binding, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1", w.SetID, e.SourceID)
		if err != nil {
			return err
		}
		if binding.IncarnationStatus != "LOCAL_OBSERVED" || binding.Incarnation != e.SourceIncarnation || entry.SourceID != e.SourceID || entry.SourceIncarnation != e.SourceIncarnation {
			return ErrStaleGeneration
		}
		var request int64
		if err = tx.QueryRowContext(ctx, "SELECT request FROM source_verification WHERE set_id=? AND destination=?", w.SetID, e.Destination).Scan(&request); err != nil {
			return err
		}
		if request != e.VerificationRequest {
			return ErrStaleGeneration
		}
		prior, readErr := readJSON[SnapshotEvidence](ctx, tx, "SELECT evidence_json FROM source_evidence WHERE set_id=? AND destination=?", w.SetID, e.Destination)
		if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
			return readErr
		}
		if readErr == nil && prior.SHA256 != e.SHA256 && prior.EntryGeneration == entry.Generation {
			entry.Generation++
			e.EntryGeneration = entry.Generation
			raw, _ := json.Marshal(entry)
			if _, err = tx.ExecContext(ctx, "UPDATE source_entries SET generation=?,descriptor_json=? WHERE set_id=? AND destination=?", entry.Generation, string(raw), w.SetID, e.Destination); err != nil {
				return err
			}
		}
		if registry != nil {
			if err := registry.promoteCapturedProof(ctx, tx, v, e, set.AttachedRootID); err != nil {
				return err
			}
		}
		raw, _ := json.Marshal(e)
		if _, err = tx.ExecContext(ctx, "INSERT INTO source_evidence(set_id,destination,evidence_json) VALUES(?,?,?) ON CONFLICT(set_id,destination) DO UPDATE SET evidence_json=excluded.evidence_json", w.SetID, e.Destination, string(raw)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM source_verification WHERE set_id=? AND destination=? AND request=?", w.SetID, e.Destination, e.VerificationRequest)
		if err == nil {
			committed = e
		}
		return err
	})
	if err == nil {
		v.evidence = committed
	}
	return err
}
func (s *Sources) Evidence(ctx context.Context, set, key string) (SnapshotEvidence, error) {
	return readJSON[SnapshotEvidence](ctx, s.store.db, "SELECT evidence_json FROM source_evidence WHERE set_id=? AND destination=?", set, key)
}

func DescribeSource(filename, destination string, expected int64) (SourceDescriptor, error) {
	d := SourceDescriptor{PhysicalPath: filename, Destination: destination, ExpectedGeneration: expected, Presence: "PRESENT"}
	info, err := os.Lstat(filename)
	if err != nil {
		return d, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		info, err = os.Stat(filename)
		if err != nil {
			return d, err
		}
		if !info.Mode().IsRegular() {
			return d, errors.New("directory/special symlinks are not followed")
		}
	}
	if info.IsDir() {
		d.Kind = "folder"
	} else if info.Mode().IsRegular() {
		d.Kind = "file"
	} else {
		return d, errors.New("special source refused")
	}
	d.FileIdentity = statIdentity(info)
	d.SizeBytes = info.Size()
	d.MTimeNS = info.ModTime().UnixNano()
	d.CTimeNS = statCTime(info)
	if d.Kind == "folder" {
		d.SizeBytes = 0
	}
	return d, checkSourceDescriptor(d)
}

// ScanClaim streams one claimed directory at a time; at most128 DirEntries are
// retained. The callback runs after each committed page, before enumeration EOF.
func (s *Sources) ScanClaim(ctx context.Context, c FrontierClaim, onPage func(FrontierClaim) error) error {
	return s.ScanClaimWithHooks(ctx, c, onPage, ScanHooks{})
}

type ScanHooks struct {
	Before    func(context.Context, FrontierClaim) error
	Entry     func(context.Context, string, SourceDescriptor) error
	Directory func(context.Context, string) error // Runs only after the bounded observation commit.
	Include   func(string) bool
}

func (s *Sources) ScanClaimWithHooks(ctx context.Context, c FrontierClaim, onPage func(FrontierClaim) error, hooks ScanHooks) error {
	if hooks.Before != nil {
		if err := hooks.Before(ctx, c); err != nil {
			return err
		}
	}
	scan, err := s.Scan(ctx, c.ScanID)
	if err != nil {
		return err
	}
	b, err := s.Binding(ctx, c.Witness.SetID, scan.SourceID)
	if err != nil {
		return err
	}
	observation, observeErr := ObserveSourceIncarnation(b.PhysicalPath)
	if observeErr == nil {
		if _, err = s.RecordSourceIncarnation(ctx, c.Witness, scan.SourceID, observation); err != nil {
			return err
		}
	}
	descriptor, err := DescribeSource(c.PhysicalPath, c.Destination, 0)
	fail := func(e error) error {
		_, saveErr := s.CommitScanPage(ctx, c, ScanPage{EOF: true, IncompleteReason: "source unreadable, missing, special or changed"})
		return errors.Join(e, saveErr)
	}
	if err != nil {
		return fail(err)
	}
	if old, e := s.SourceEntry(ctx, c.Witness.SetID, c.Destination); e == nil {
		descriptor.ExpectedGeneration = old.Generation
	} else if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if descriptor.Kind == "file" {
		_, err = s.CommitScanPage(ctx, c, ScanPage{Entries: []SourceDescriptor{descriptor}, EOF: true})
		if err == nil && onPage != nil {
			return onPage(c)
		}
		return err
	}
	dir, err := os.OpenFile(c.PhysicalPath, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fail(err)
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || statIdentity(info) != descriptor.FileIdentity {
		return fail(ErrCaptureChanged)
	}
	c, err = s.CommitScanPage(ctx, c, ScanPage{Entries: []SourceDescriptor{descriptor}})
	if err != nil {
		return err
	}
	if hooks.Directory != nil {
		if err = hooks.Directory(ctx, descriptor.Destination); err != nil {
			return err
		}
	}
	if onPage != nil {
		if err = onPage(c); err != nil {
			return err
		}
	}
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		batch, readErr := dir.ReadDir(MaxSourcePage)
		page := ScanPage{EOF: errors.Is(readErr, io.EOF)}
		for _, item := range batch {
			p := filepath.Join(c.PhysicalPath, item.Name())
			key := c.Destination + "/" + item.Name()
			if hooks.Include != nil && !hooks.Include(key) {
				continue
			}
			var generation int64
			if old, e := s.SourceEntry(ctx, c.Witness.SetID, key); e == nil {
				generation = old.Generation
			} else if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			d, e := DescribeSource(p, key, generation)
			if e != nil {
				page.IncompleteReason = "child unreadable, missing or unsupported"
				continue
			}
			page.Entries = append(page.Entries, d)
			if hooks.Entry != nil {
				if e := hooks.Entry(ctx, scan.SourceID, d); e != nil {
					return e
				}
			}
			if d.Kind == "folder" {
				page.Children = append(page.Children, d)
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			page.IncompleteReason = "directory read failed"
		}
		after, e := os.Stat(c.PhysicalPath)
		if e != nil || !os.SameFile(info, after) || statCTime(info) != statCTime(after) || info.ModTime() != after.ModTime() {
			page.IncompleteReason = "directory identity/content changed during enumeration"
		}
		c, err = s.CommitScanPage(ctx, c, page)
		if err != nil {
			return err
		}
		if onPage != nil {
			if err = onPage(c); err != nil {
				return err
			}
		}
		if page.IncompleteReason != "" {
			return ErrSourceIncomplete
		}
		if page.EOF {
			return nil
		}
	}
}
