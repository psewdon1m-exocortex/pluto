package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"golang.org/x/sys/unix"
)

// PruneDisposed removes only bounded proven-disposed accounting rows. It never
// evicts a pending operation, receipt, B, source evidence or retained plaintext.
// Registry locking joins reserve/dispose/users before exact-capability checks.
func (a *Artifacts) PruneDisposed(ctx context.Context, limit int) (removed int, err error) {
	if limit < 1 || limit > MaxSourcePage {
		return 0, ErrSourceQuota
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.ready {
		return 0, ErrArtifactUnreconciled
	}
	err = a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if e := a.validate(ctx, tx); e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, "SELECT artifact_id FROM local_artifacts WHERE phase='GONE' ORDER BY artifact_id LIMIT ?", limit)
		if e != nil {
			return e
		}
		ids := make([]string, 0, limit)
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = errors.Join(rows.Err(), rows.Close())
		if e != nil {
			return e
		}
		for _, id := range ids {
			r, e := readArtifact(ctx, tx, id)
			if e != nil {
				return e
			}
			if !artifactUUID(id) || r.Name != id+".snapshot" || r.Phase != ArtifactGone {
				return ErrIdentityConflict
			}
			if a.live[id] != nil {
				return ErrArtifactInUse
			}
			var st unix.Stat_t
			e = unix.Fstatat(int(a.directory.Fd()), r.Name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if e == nil {
				return ErrArtifactUnreconciled
			}
			if !errors.Is(e, unix.ENOENT) {
				return e
			}
			if e = acknowledgedArtifact(ctx, tx, r); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM local_artifacts WHERE artifact_id=? AND phase='GONE'", id); e != nil {
				return e
			}
			removed++
		}
		if a.crashPoint != nil {
			a.crashPoint("before-prune-commit")
		}
		return ctx.Err()
	})
	if err != nil {
		removed = 0
	}
	return
}
