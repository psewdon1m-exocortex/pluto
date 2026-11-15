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
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const smallBatchDirectoryName = "sync-batches-v1"

type smallBatchArtifacts struct {
	state *smallBatchStore
	mu    sync.Mutex
	// Directory publication/removal and snapshots of its recorded namespace
	// are atomic locally. Immutable network readers do not hold this lock.
	namespace      sync.RWMutex
	directory      *os.File
	path, identity string
	closed         bool
	live           map[string]bool
	reader         func(context.Context) (func(), error)
}

// Linux birth time is required for this optional optimization. Inode reuse or
// a filesystem lacking a stable birth identity must not qualify a saved spool.
func smallBatchNativeIdentity(file *os.File) (string, error) {
	var st unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_BTIME, &st); err != nil {
		return "", err
	}
	if st.Mask&(unix.STATX_INO|unix.STATX_BTIME) != (unix.STATX_INO|unix.STATX_BTIME) || st.Ino == 0 {
		return "", ErrIdentityConflict
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d", st.Dev_major, st.Dev_minor, st.Ino, st.Btime.Sec, st.Btime.Nsec), nil
}
func smallBatchPrivate(file *os.File, directory bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || directory && (!info.IsDir() || info.Mode().Perm() != 0700) || !directory && (!info.Mode().IsRegular() || st.Nlink != 1 || info.Mode().Perm()&0077 != 0) {
		return ErrIdentityConflict
	}
	return nil
}
func (s *smallBatchStore) enableArtifacts(ctx context.Context) (*smallBatchArtifacts, error) {
	store := s.remote.store
	store.sourceMu.Lock()
	defer store.sourceMu.Unlock()
	if store.batches != nil {
		return store.batches, nil
	}
	a := store.artifacts
	if a == nil {
		return nil, ErrArtifactUnreconciled
	}
	a.mu.Lock()
	reader := a.reader
	ready := a.ready && !a.closed
	a.mu.Unlock()
	if reader == nil || !ready {
		return nil, ErrArtifactUnreconciled
	}
	var version int
	if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version != smallBatchSchemaVersion && version != daemonSchemaVersion {
		return nil, ErrUnsupportedSchema
	}
	parentFD, err := unix.Open(filepath.Dir(store.filename), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(parentFD), filepath.Dir(store.filename))
	defer parent.Close()
	if err = smallBatchPrivate(parent, true); err != nil {
		return nil, err
	}
	if err = unix.Mkdirat(parentFD, smallBatchDirectoryName, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	fd, err := unix.Openat(parentFD, smallBatchDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), smallBatchDirectoryName)
	keep := false
	defer func() {
		if !keep {
			dir.Close()
		}
	}()
	if err = smallBatchPrivate(dir, true); err != nil {
		return nil, err
	}
	identity, err := smallBatchNativeIdentity(dir)
	if err != nil {
		return nil, err
	}
	b := &smallBatchArtifacts{state: s, directory: dir, path: filepath.Join(filepath.Dir(store.filename), smallBatchDirectoryName), identity: identity, live: map[string]bool{}, reader: reader}
	if err = b.checkNamespace(ctx); err != nil {
		return nil, err
	}
	if err = parent.Sync(); err != nil {
		return nil, err
	}
	store.batches = b
	keep = true
	return b, nil
}
func (b *smallBatchArtifacts) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.closed {
		return ErrStaleGeneration
	}
	if err := smallBatchPrivate(b.directory, true); err != nil {
		return err
	}
	identity, err := smallBatchNativeIdentity(b.directory)
	if err != nil || identity != b.identity {
		return errors.Join(ErrIdentityConflict, err)
	}
	current, err := os.Lstat(b.path)
	if err != nil {
		return err
	}
	held, err := b.directory.Stat()
	if err != nil || !os.SameFile(current, held) || !current.IsDir() || current.Mode().Perm() != 0700 {
		return errors.Join(ErrIdentityConflict, err)
	}
	return nil
}
func (b *smallBatchArtifacts) close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.live) != 0 {
		return ErrArtifactInUse
	}
	if b.closed {
		return nil
	}
	b.closed = true
	return b.directory.Close()
}
func (b *smallBatchArtifacts) inUse() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.live) != 0 }
func (b *smallBatchArtifacts) acquire(ctx context.Context, id string) (func(), error) {
	store := b.state.remote.store
	store.sourceMu.Lock()
	defer store.sourceMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !smallBatchToken(id) || b.live[id] || len(b.live) >= 4 {
		return nil, ErrArtifactInUse
	}
	if err := b.validate(ctx); err != nil {
		return nil, err
	}
	b.live[id] = true
	return func() { b.mu.Lock(); delete(b.live, id); b.mu.Unlock() }, nil
}
func (b *smallBatchArtifacts) open(record smallBatchRecord, name string, writable bool) (*os.File, error) {
	if record.Scope != b.state.remote.store.artifacts.scope || record.DirectoryIdentity != b.identity || record.FileIdentity == "" || name != record.Name && name != strings.TrimSuffix(record.Name, ".batch")+".drop" {
		return nil, ErrIdentityConflict
	}
	mode := unix.O_RDONLY
	if writable {
		mode = unix.O_RDWR
	}
	fd, err := unix.Openat(int(b.directory.Fd()), name, mode|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if err = smallBatchPrivate(file, false); err == nil {
		var identity string
		identity, err = smallBatchNativeIdentity(file)
		if err == nil && identity != record.FileIdentity {
			err = ErrIdentityConflict
		}
	}
	if err == nil {
		info, e := file.Stat()
		err = e
		if err == nil && (info.Size() < 0 || info.Size() > record.ExpectedBytes) {
			err = ErrIdentityConflict
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func (b *smallBatchArtifacts) checkNamespace(ctx context.Context) error {
	b.namespace.RLock()
	defer b.namespace.RUnlock()
	return b.checkNamespaceLocked(ctx)
}
func (b *smallBatchArtifacts) checkNamespaceLocked(ctx context.Context) error {
	if err := b.validate(ctx); err != nil {
		return err
	}
	rows, err := b.state.remote.store.db.QueryContext(ctx, "SELECT batch_id FROM small_batch_groups ORDER BY batch_id LIMIT 65")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if len(ids) > 64 {
		return ErrSourceQuota
	}
	known := map[string]smallBatchRecord{}
	for _, id := range ids {
		record, err := b.state.read(ctx, id)
		if err != nil {
			return err
		}
		if record.Phase == "GONE" {
			continue
		}
		known[record.Name] = record
		if record.Phase == "DISPOSING" {
			known[strings.TrimSuffix(record.Name, ".batch")+".drop"] = record
		}
	}
	fd, err := unix.Openat(int(b.directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), ".")
	defer dir.Close()
	entries, err := dir.ReadDir(129)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > 128 {
		return ErrSourceQuota
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		record, ok := known[entry.Name()]
		if !ok || record.Phase == "RESERVED" {
			return ErrArtifactUnreconciled
		}
		file, err := b.open(record, entry.Name(), false)
		if err != nil {
			return err
		}
		file.Close()
		if seen[record.ID] {
			return ErrArtifactUnreconciled
		}
		seen[record.ID] = true
	}
	for _, record := range known {
		if !seen[record.ID] && record.Phase != "RESERVED" && record.Phase != "DISPOSING" {
			return ErrArtifactUnreconciled
		}
	}
	return nil
}
func (b *smallBatchArtifacts) update(ctx context.Context, expected smallBatchRecord, phase, directory, file, digest string) (next smallBatchRecord, err error) {
	err = b.state.remote.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		current, e := readSmallBatchRecord(ctx, tx, expected.ID, &b.state.proofs)
		if e != nil {
			return e
		}
		if current.Revision != expected.Revision || current.Phase != expected.Phase || current.Scope != expected.Scope || !bytesEqualBatchManifest(current.Plan, expected.Plan) {
			return ErrStaleGeneration
		}
		changed, e := tx.ExecContext(ctx, "UPDATE small_batch_groups SET phase=?,revision=revision+1,directory_identity=?,file_identity=?,aggregate_sha256=? WHERE batch_id=? AND revision=?", phase, directory, file, digest, expected.ID, expected.Revision)
		if e != nil {
			return e
		}
		if n, e := changed.RowsAffected(); e != nil || n != 1 {
			return errors.Join(ErrStaleGeneration, e)
		}
		if phase == "GONE" {
			if _, e = tx.ExecContext(ctx, "UPDATE small_batch_members SET active=0 WHERE batch_id=?", expected.ID); e != nil {
				return e
			}
		}
		if e = b.state.remote.point("small_batch." + strings.ToLower(phase) + ".before_commit"); e != nil {
			return e
		}
		// The originals and immutable manifest were verified in this exact
		// transaction. Only these aggregate custody fields changed; there is no
		// need to reload and parse every original a second time before commit.
		next = current
		next.Phase, next.Revision = phase, current.Revision+1
		next.DirectoryIdentity, next.FileIdentity, next.SHA256 = directory, file, digest
		return nil
	})
	if err == nil {
		err = b.state.remote.point("small_batch." + strings.ToLower(phase) + ".after_commit")
	}
	return
}
func bytesEqualBatchManifest(a, c *smallBatchPlan) bool {
	return a != nil && c != nil && hashBytes(a.persistedBytes()) == hashBytes(c.persistedBytes())
}

// Build reads existing sealed originals, never the user's source tree. Each
// original reader is released before the next; all source snapshots are retained.
func (b *smallBatchArtifacts) build(ctx context.Context, plan *smallBatchPlan) (record smallBatchRecord, err error) {
	if plan == nil {
		return record, ErrIdentityConflict
	}
	release, err := b.acquire(ctx, plan.id)
	if err != nil {
		return record, err
	}
	defer release()
	b.namespace.Lock()
	defer b.namespace.Unlock()
	if err = b.checkNamespaceLocked(ctx); err != nil {
		return record, err
	}
	record, err = b.state.reserve(ctx, plan)
	if err != nil {
		return
	}
	if record.Phase == "READY" || record.Phase == "ATTEMPTED" {
		file, e := b.open(record, record.Name, false)
		if e != nil {
			return record, e
		}
		defer file.Close()
		return record, b.verify(ctx, record, file)
	}
	if record.Phase != "RESERVED" && record.Phase != "BUILDING" {
		return record, ErrArtifactRetained
	}
	var file *os.File
	if record.Phase == "RESERVED" {
		fd, e := unix.Openat(int(b.directory.Fd()), record.Name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return record, e
		}
		file = os.NewFile(uintptr(fd), record.Name)
		defer file.Close()
		if e = b.state.remote.point("small_batch.created.before_identity"); e != nil {
			return record, e
		}
		identity, e := smallBatchNativeIdentity(file)
		if e != nil {
			return record, e
		}
		if e = smallBatchPrivate(file, false); e != nil {
			return record, e
		}
		if e = b.directory.Sync(); e != nil {
			return record, e
		}
		record, e = b.update(ctx, record, "BUILDING", b.identity, identity, "")
		if e != nil {
			return record, e
		}
	} else {
		held, e := b.open(record, record.Name, false)
		if e != nil {
			return record, e
		}
		e = held.Chmod(0600)
		closeErr := held.Close()
		if e != nil || closeErr != nil {
			return record, errors.Join(e, closeErr)
		}
		file, err = b.open(record, record.Name, true)
		if err != nil {
			return
		}
		defer file.Close()
		if err = file.Truncate(0); err != nil {
			return
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return
		}
	}
	hash := sha256.New()
	written := int64(0)
	for _, entry := range record.Plan.entries {
		err = b.state.remote.store.artifacts.WithRecoveryReader(ctx, entry.original, b.reader, func(input io.Reader) error {
			n, e := io.CopyBuffer(io.MultiWriter(file, hash), io.LimitReader(input, entry.original.SizeBytes), make([]byte, smallBatchStreamChunk))
			written += n
			if e != nil {
				return e
			}
			if n != entry.original.SizeBytes {
				return io.ErrUnexpectedEOF
			}
			return nil
		})
		if err != nil {
			return
		}
		if err = b.state.remote.point("small_batch.copied_original"); err != nil {
			return
		}
	}
	if written != record.ExpectedBytes {
		return record, ErrIdentityConflict
	}
	if err = file.Chmod(0400); err != nil {
		return
	}
	if err = file.Sync(); err != nil {
		return
	}
	if err = b.directory.Sync(); err != nil {
		return
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	return b.update(ctx, record, "READY", b.identity, record.FileIdentity, digest)
}
func (b *smallBatchArtifacts) verify(ctx context.Context, record smallBatchRecord, file *os.File) error {
	return b.verifyNamed(ctx, record, file, record.Name)
}
func (b *smallBatchArtifacts) verifyNamed(ctx context.Context, record smallBatchRecord, file *os.File, name string) error {
	if err := b.validate(ctx); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	before, err := file.Stat()
	if err != nil {
		return err
	}
	if before.Mode().Perm() != 0400 || before.Size() != record.ExpectedBytes || !validHash(record.SHA256) {
		return ErrIdentityConflict
	}
	release, err := b.reader(ctx)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, copyErr := io.CopyBuffer(hash, captureContextReader{ctx, io.LimitReader(file, record.ExpectedBytes+1)}, make([]byte, smallBatchStreamChunk))
	release()
	after, statErr := file.Stat()
	if copyErr != nil || statErr != nil {
		return errors.Join(copyErr, statErr)
	}
	if n != record.ExpectedBytes || hex.EncodeToString(hash.Sum(nil)) != record.SHA256 || before.ModTime() != after.ModTime() || statCTime(before) != statCTime(after) {
		return ErrIdentityConflict
	}
	current, err := b.open(record, name, false)
	if err != nil {
		return err
	}
	current.Close()
	_, err = file.Seek(0, io.SeekStart)
	return err
}
func (b *smallBatchArtifacts) withAttempt(ctx context.Context, id string, use func(smallBatchRecord, io.ReadSeeker) error) (err error) {
	if use == nil {
		return ErrIdentityConflict
	}
	return b.withAttemptState(ctx, id, func(record smallBatchRecord, input io.ReadSeeker, _ bool) error { return use(record, input) })
}

// The recovery flag is determined while the native group is exclusively held.
// A caller must not infer it from an earlier unlocked phase read.
func (b *smallBatchArtifacts) withAttemptState(ctx context.Context, id string, use func(smallBatchRecord, io.ReadSeeker, bool) error) (err error) {
	if use == nil {
		return ErrIdentityConflict
	}
	release, err := b.acquire(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	record, err := b.state.read(ctx, id)
	if err != nil {
		return err
	}
	if err = b.checkNamespace(ctx); err != nil {
		return err
	}
	if record.Phase != "READY" && record.Phase != "ATTEMPTED" {
		return ErrArtifactRetained
	}
	file, err := b.open(record, record.Name, false)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = b.verify(ctx, record, file); err != nil {
		return err
	}
	recovery := record.Phase == "ATTEMPTED"
	if !recovery {
		record, err = b.update(ctx, record, "ATTEMPTED", record.DirectoryIdentity, record.FileIdentity, record.SHA256)
		if err != nil {
			return err
		}
	}
	return use(record, file, recovery)
}
func (b *smallBatchArtifacts) retainFallback(ctx context.Context, record smallBatchRecord) error {
	for _, entry := range record.Plan.entries {
		op, err := b.state.remote.store.Operation(ctx, entry.original.OperationID)
		if err != nil {
			return err
		}
		if op.Stage == "CLIENT_ACKED" {
			var raw string
			var receipt Receipt
			if err = b.state.remote.store.db.QueryRowContext(ctx, "SELECT CASE WHEN length(receipt_json)<=16384 THEN receipt_json ELSE '' END FROM operations WHERE operation_id=?", op.OperationID).Scan(&raw); err != nil {
				return err
			}
			if json.Unmarshal([]byte(raw), &receipt) != nil || !validCapturedReceipt(op, receipt) {
				return ErrInvalidReceipt
			}
			continue
		}
		if err = b.state.remote.store.artifacts.WithRecoveryReader(ctx, op, b.reader, func(input io.Reader) error {
			_, err := io.CopyBuffer(io.Discard, input, make([]byte, smallBatchStreamChunk))
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// Only a declared private aggregate is removed. Pending original snapshots must
// first be reverified, or a complete original publication receipt must exist.
// Renaming to a private quarantine name preserves an unexpected replacement.
func (b *smallBatchArtifacts) cleanup(ctx context.Context, id string) (err error) {
	release, err := b.acquire(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	b.namespace.Lock()
	defer b.namespace.Unlock()
	record, err := b.state.read(ctx, id)
	if err != nil {
		return err
	}
	if record.Phase == "GONE" {
		return b.checkNamespaceLocked(ctx)
	}
	if err = b.retainFallback(ctx, record); err != nil {
		return err
	}
	drop := strings.TrimSuffix(record.Name, ".batch") + ".drop"
	exists := func(name string) (bool, error) {
		var st unix.Stat_t
		e := unix.Fstatat(int(b.directory.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(e, os.ErrNotExist) {
			return false, nil
		}
		return e == nil, e
	}
	first, e1 := exists(record.Name)
	quarantined, e2 := exists(drop)
	if e1 != nil || e2 != nil {
		return errors.Join(e1, e2)
	}
	if first && quarantined {
		return ErrArtifactUnreconciled
	}
	if record.Phase == "RESERVED" && (first || quarantined) {
		return ErrArtifactUnreconciled
	}
	if record.Phase != "RESERVED" && record.Phase != "DISPOSING" && !first {
		return ErrArtifactUnreconciled
	}
	name := record.Name
	if quarantined {
		name = drop
	}
	if first || quarantined {
		file, e := b.open(record, name, false)
		if e != nil {
			return e
		}
		if record.SHA256 != "" {
			e = b.verifyNamed(ctx, record, file, name)
		} else {
			info, statErr := file.Stat()
			e = statErr
			if e == nil && (info.Size() < 0 || info.Size() > record.ExpectedBytes) {
				e = ErrIdentityConflict
			}
		}
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			return errors.Join(e, closeErr)
		}
	}
	if record.Phase != "DISPOSING" {
		record, err = b.update(ctx, record, "DISPOSING", record.DirectoryIdentity, record.FileIdentity, record.SHA256)
		if err != nil {
			return err
		}
	}
	if first {
		if err = unix.Renameat2(int(b.directory.Fd()), record.Name, int(b.directory.Fd()), drop, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		quarantined = true
		if err = b.directory.Sync(); err != nil {
			return err
		}
	}
	if err = b.state.remote.point("small_batch.quarantined"); err != nil {
		return err
	}
	if quarantined {
		file, e := b.open(record, drop, false)
		if e != nil {
			return e
		}
		if record.SHA256 != "" {
			e = b.verifyNamed(ctx, record, file, drop)
		}
		closeErr := file.Close()
		if e != nil || closeErr != nil {
			return errors.Join(e, closeErr)
		}
		if err = unix.Unlinkat(int(b.directory.Fd()), drop, 0); err != nil {
			return err
		}
	}
	if err = b.state.remote.point("small_batch.unlinked"); err != nil {
		return err
	}
	if err = b.directory.Sync(); err != nil {
		return err
	}
	_, err = b.update(ctx, record, "GONE", record.DirectoryIdentity, record.FileIdentity, record.SHA256)
	return err
}
func (b *smallBatchArtifacts) compact(ctx context.Context, limit int) (count int, err error) {
	if limit < 1 || limit > 16 {
		return 0, ErrSourceQuota
	}
	release, err := b.acquire(ctx, "local-retirement")
	if err != nil {
		return 0, err
	}
	defer release()
	b.namespace.Lock()
	defer b.namespace.Unlock()
	if err = b.checkNamespaceLocked(ctx); err != nil {
		return 0, err
	}
	err = b.state.remote.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, "SELECT batch_id FROM small_batch_groups WHERE phase='GONE' ORDER BY batch_id LIMIT ?", limit)
		if e != nil {
			return e
		}
		var ids []string
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		e = errors.Join(e, rows.Err(), rows.Close())
		if e != nil {
			return e
		}
		for _, id := range ids {
			record, e := readSmallBatchRecord(ctx, tx, id, &b.state.proofs)
			if e != nil {
				return e
			}
			if record.Scope != b.state.remote.store.artifacts.scope || record.Phase != "GONE" {
				return ErrIdentityConflict
			}
			for _, name := range []string{record.Name, strings.TrimSuffix(record.Name, ".batch") + ".drop"} {
				var st unix.Stat_t
				if e = unix.Fstatat(int(b.directory.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, os.ErrNotExist) {
					return ErrArtifactUnreconciled
				}
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM small_batch_members WHERE batch_id=? AND active=0", id); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM small_batch_groups WHERE batch_id=? AND phase='GONE'", id); e != nil {
				return e
			}
			count++
		}
		return nil
	})
	return
}
