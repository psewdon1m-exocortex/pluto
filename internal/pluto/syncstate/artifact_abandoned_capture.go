package syncstate

import (
	"context"
	"errors"
	"os"
)

// RecoverAbandonedCaptures retires owned temporary bytes from a crash before
// Seal committed any capture proof or operation. It never adopts those bytes
// as a snapshot. A future scan captures the source again. Submitted originals,
// sealed captures, unknown paths and changed inode identities remain untouched.
func (a *Artifacts) RecoverAbandonedCaptures(ctx context.Context) error {
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
	rows, err := a.store.db.QueryContext(ctx, `SELECT artifact_id FROM local_artifacts
WHERE phase IN ('CAPTURING','DISPOSING') AND file_identity<>'' AND size_bytes=0
AND sha256='' AND snapshot_id='' AND capture_json='' AND operation_id IS NULL
AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.snapshot_id=local_artifacts.artifact_id)
ORDER BY artifact_id LIMIT ?`, a.limits.Records+1)
	if err != nil {
		a.mu.Unlock()
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
	a.mu.Unlock()
	if err != nil {
		return err
	}
	if len(ids) > a.limits.Records {
		return ErrArtifactUnreconciled
	}
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return err
		}
		if !artifactUUID(id) {
			return ErrIdentityConflict
		}
		record, err := a.Record(ctx, id)
		if err != nil {
			return err
		}
		f, err := a.open(record) // exact registered private, single-link inode
		if errors.Is(err, os.ErrNotExist) && record.Phase == ArtifactDisposing {
			// Dispose had durably recorded its decision before the unlink.
		} else {
			if err != nil {
				return err
			}
			info, statErr := f.Stat()
			closeErr := f.Close()
			if err = errors.Join(statErr, closeErr); err != nil {
				return err
			}
			if info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 {
				return ErrIdentityConflict
			}
			if info.Size() == 0 && record.Phase == ArtifactCapturing {
				continue
			} // existing empty-inode quarantine
		}
		// Dispose revalidates ownership, operation references, inode and bounds,
		// and journals DISPOSING before unlink+fsync. No new operation is created.
		if err = a.Dispose(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
