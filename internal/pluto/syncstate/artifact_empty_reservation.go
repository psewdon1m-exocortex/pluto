package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// RecoverEmptyReservations closes the Reserve-before-Create crash window.
// It requires a joined owner and never removes filesystem content. A zero-byte
// unregistered creation gap is quarantined, never adopted as captured content.
// Nonempty, linked or otherwise ambiguous objects still block. Dispose
// revalidates the owner, operation references, phase and path before recording
// GONE. A file appearing between the checks is preserved and blocks admission.
func (a *Artifacts) RecoverEmptyReservations(ctx context.Context) error {
	a.mu.Lock()
	if len(a.live) != 0 {
		a.mu.Unlock()
		return ErrArtifactInUse
	}
	if err := a.validate(ctx, a.store.db); err != nil {
		a.mu.Unlock()
		return err
	}
	a.ready = false
	rows, err := a.store.db.QueryContext(ctx, "SELECT artifact_id FROM local_artifacts WHERE ((phase='RESERVED' AND file_identity='') OR (phase='CAPTURING' AND file_identity<>'')) AND size_bytes=0 AND sha256='' AND snapshot_id='' AND capture_json='' AND operation_id IS NULL ORDER BY artifact_id LIMIT ?", a.limits.Records+1)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	a.mu.Unlock()
	if err != nil {
		return err
	}
	if len(ids) > a.limits.Records {
		return ErrArtifactUnreconciled
	}
	for _, id := range ids {
		if !artifactUUID(id) {
			return ErrIdentityConflict
		}
		record, err := a.Record(ctx, id)
		if err != nil {
			return err
		}
		// Lstat also detects a foreign symlink or directory; none is deleted.
		if _, err = os.Lstat(filepath.Join(a.path, id+".snapshot")); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return err
			}
			if err = a.quarantineEmptyCreation(ctx, id); err != nil {
				return err
			}
		}
		if record.Phase == ArtifactCapturing {
			if err = a.retireQuarantinedEmptyCapture(ctx, record); err != nil {
				return err
			}
		}
		if err = a.Dispose(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// A crashed Create may already have committed its inode identity while still
// containing zero bytes. Only that exact private empty inode in quarantine
// permits retirement. Missing, replaced, linked or nonempty captures still block.
// Repeating after rename-before-commit is safe and keeps the original evidence.
func (a *Artifacts) retireQuarantinedEmptyCapture(ctx context.Context, expected ArtifactRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.live) != 0 {
		return ErrArtifactInUse
	}
	if err := a.validate(ctx, a.store.db); err != nil {
		return err
	}
	name := filepath.Join(filepath.Dir(a.path), artifactQuarantineDirectory, expected.Name)
	qi, err := os.Lstat(filepath.Dir(name))
	if err != nil {
		return errors.Join(ErrArtifactUnreconciled, err)
	}
	qs, ok := qi.Sys().(*syscall.Stat_t)
	if !ok || !qi.IsDir() || qi.Mode()&os.ModeSymlink != 0 || qi.Mode().Perm() != 0700 || qs.Uid != uint32(os.Geteuid()) {
		return ErrIdentityConflict
	}
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.Join(ErrArtifactUnreconciled, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !emptyPrivateArtifact(info) || artifactIdentity(info) != expected.FileIdentity {
		return ErrIdentityConflict
	}
	return a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if err := a.validate(ctx, tx); err != nil {
			return err
		}
		r, err := readArtifact(ctx, tx, expected.ID)
		if err != nil {
			return err
		}
		if r != expected || r.Phase != ArtifactCapturing || r.OperationID != "" || r.SnapshotID != "" || r.SHA256 != "" || r.SizeBytes != 0 {
			return ErrIdentityConflict
		}
		if _, err = artifactOperation(ctx, tx, r); !errors.Is(err, sql.ErrNoRows) {
			if err == nil {
				return ErrArtifactRetained
			}
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE local_artifacts SET phase='RESERVED',file_identity='' WHERE artifact_id=? AND phase='CAPTURING'", r.ID)
		return err
	})
}

const artifactQuarantineDirectory = "sync-artifacts-quarantine-v1"

func emptyPrivateArtifact(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Size() == 0 && info.Mode().Perm() == 0600 && st.Nlink == 1 && st.Uid == uint32(os.Geteuid())
}

func (a *Artifacts) quarantineEmptyCreation(ctx context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.live) != 0 {
		return ErrArtifactInUse
	}
	if err := a.validate(ctx, a.store.db); err != nil {
		return err
	}
	r, err := readArtifact(ctx, a.store.db, id)
	if err != nil {
		return err
	}
	if (r.Phase != ArtifactReserved || r.FileIdentity != "") && (r.Phase != ArtifactCapturing || r.FileIdentity == "") || r.SnapshotID != "" || r.OperationID != "" || r.SHA256 != "" || r.SizeBytes != 0 {
		return ErrIdentityConflict
	}
	if _, err = artifactOperation(ctx, a.store.db, r); !errors.Is(err, sql.ErrNoRows) {
		if err == nil {
			return ErrArtifactRetained
		}
		return err
	}
	fd, err := unix.Openat(int(a.directory.Fd()), r.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.Join(ErrArtifactUnreconciled, err)
	}
	f := os.NewFile(uintptr(fd), r.Name)
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return err
	}
	if !emptyPrivateArtifact(before) {
		return ErrArtifactUnreconciled
	}
	if r.Phase == ArtifactCapturing && artifactIdentity(before) != r.FileIdentity {
		return ErrIdentityConflict
	}
	parentFD, err := unix.Openat(int(a.directory.Fd()), "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(parentFD), filepath.Dir(a.path))
	defer parent.Close()
	if err = unix.Mkdirat(parentFD, artifactQuarantineDirectory, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	qfd, err := unix.Openat(parentFD, artifactQuarantineDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	q := os.NewFile(uintptr(qfd), artifactQuarantineDirectory)
	defer q.Close()
	qi, err := q.Stat()
	if err != nil {
		return err
	}
	qs, ok := qi.Sys().(*syscall.Stat_t)
	if !ok || !qi.IsDir() || qi.Mode().Perm() != 0700 || qs.Uid != uint32(os.Geteuid()) {
		return ErrIdentityConflict
	}
	entries, err := q.ReadDir(a.limits.Records + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) >= a.limits.Records {
		return ErrSourceQuota
	}
	if err = parent.Sync(); err != nil {
		return err
	}
	if err = unix.Renameat2(int(a.directory.Fd()), r.Name, qfd, r.Name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	// Both directories are synced before retiring the empty reservation. A crash
	// here leaves the exact inode in quarantine and an absent original path;
	// the next owner can retire that reservation without removing the evidence.
	if err = errors.Join(q.Sync(), a.directory.Sync()); err != nil {
		return err
	}
	after, err := os.Lstat(filepath.Join(filepath.Dir(a.path), artifactQuarantineDirectory, r.Name))
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || !emptyPrivateArtifact(after) {
		return ErrIdentityConflict
	}
	a.quarantinedEmpty++
	return nil
}
