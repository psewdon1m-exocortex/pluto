package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// An expired first import has never established R or B. Its expired preparation
// remains the durable retirement marker until bounded cache cleanup and the
// old read UUID archive are both durable. Old clients cannot publish it either:
// PrepareSnapshot/ImportSnapshotPage/PublishSnapshot reject the expired lease.
func (s *IsolatedHTTPSession) retireExpiredInitialImport(ctx context.Context) error {
	p, err := s.r.Preparation(ctx, s.root)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if time.Now().UnixMilli() < p.ExpiresMS {
		return nil
	}
	if _, err = s.initialImportReadFile(p.Snapshot.SnapshotID); err != nil {
		return err
	}
	done := false
	for page := 0; page < 8192; page++ {
		count := int64(0)
		err = s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
			if e := s.checkInitialImportRetirement(ctx, tx, p); e != nil {
				return e
			}
			for _, query := range []string{
				"DELETE FROM remote_entries WHERE root_id=? AND generation=? AND node_id IN (SELECT node_id FROM remote_entries WHERE root_id=? AND generation=? ORDER BY node_id LIMIT ?)",
				"DELETE FROM remote_snapshot_pages WHERE root_id=? AND generation=? AND request_cursor IN (SELECT request_cursor FROM remote_snapshot_pages WHERE root_id=? AND generation=? ORDER BY request_cursor LIMIT ?)",
			} {
				result, e := tx.ExecContext(ctx, query, s.root, p.Generation, s.root, p.Generation, MaxRemotePage)
				if e != nil {
					return e
				}
				n, e := result.RowsAffected()
				if e != nil {
					return e
				}
				count += n
			}
			return nil
		})
		if err != nil {
			return err
		}
		if count == 0 {
			done = true
			break
		}
		if err = s.r.point("initial_import.pruned"); err != nil {
			return err
		}
	}
	if !done {
		return ErrSourceQuota
	}
	if err = s.archiveExpiredInitialImportRead(p.Snapshot.SnapshotID); err != nil {
		return err
	}
	if err = s.r.point("initial_import.read_archived"); err != nil {
		return err
	}
	return s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if e := s.checkInitialImportRetirement(ctx, tx, p); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM remote_preparations WHERE root_id=?", s.root); e != nil {
			return e
		}
		return s.r.point("initial_import.before_commit")
	})
}

func (s *IsolatedHTTPSession) checkInitialImportRetirement(ctx context.Context, tx *sql.Tx, expected SnapshotPreparation) error {
	p, err := readPreparation(ctx, tx, s.root)
	if err != nil {
		return err
	}
	root, err := readRoot(ctx, tx, s.root)
	if err != nil {
		return err
	}
	if fingerprint(p) != fingerprint(expected) || p.RootID != s.root || p.Generation != 2 || p.PreviousGeneration != 1 || root.ActiveRemoteGeneration != 1 || p.TrustGeneration != root.TrustGeneration || p.Snapshot.Binding != s.binding || !httpUUID(p.Snapshot.SnapshotID) || p.ExpiresMS <= 0 || time.Now().UnixMilli() < p.ExpiresMS || root.DeviceID != s.identity.DeviceID || root.RemoteRootID != s.binding.RootID || root.ServerIdentity != s.binding.ServerIdentity {
		return ErrStaleGeneration
	}
	var debt int
	if err = tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM remote_candidate_roots WHERE root_id=?) OR
		EXISTS(SELECT 1 FROM operations WHERE root_id=?) OR
		EXISTS(SELECT 1 FROM remote_seen_bindings WHERE root_id=?) OR
		EXISTS(SELECT 1 FROM remote_entries WHERE root_id=? AND generation=1)`, s.root, s.root, s.root, s.root).Scan(&debt); err != nil {
		return err
	}
	if debt != 0 {
		return ErrRemoteUnqualified
	}
	return nil
}

func (s *IsolatedHTTPSession) initialImportReadFile(id string) (string, error) {
	if !httpUUID(id) {
		return "", ErrIdentityConflict
	}
	dirname := filepath.Dir(s.r.store.filename)
	filename := filepath.Join(dirname, "http-snapshot-binding-"+fingerprint(s.binding)+".json")
	if _, err := os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		if _, e := os.Lstat(filename + ".expired-" + id); errors.Is(e, os.ErrNotExist) {
			filename = filepath.Join(dirname, "http-snapshot-"+hashBytes([]byte(s.binding.RootID))+".json")
		} else if e != nil {
			return "", e
		}
	} else if err != nil {
		return "", err
	}
	archive := filename + ".expired-" + id
	read := filename
	if _, err := os.Lstat(read); errors.Is(err, os.ErrNotExist) {
		read = archive
	} else if err != nil {
		return "", err
	}
	if _, err := os.Lstat(read); err != nil {
		return "", err
	}
	got, err := s.r.pendingHTTPSnapshotFile(s.binding, read, false)
	if err != nil {
		return "", err
	}
	if got != id {
		return "", ErrIdentityConflict
	}
	return filename, nil
}

func (s *IsolatedHTTPSession) archiveExpiredInitialImportRead(id string) error {
	filename, err := s.initialImportReadFile(id)
	if err != nil {
		return err
	}
	dirname := filepath.Dir(filename)
	archive := filename + ".expired-" + id
	_, err = os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		// A crash after unlink may only resume an already durable exact archive.
		if _, err = os.Lstat(archive); err != nil {
			return err
		}
		got, e := s.r.pendingHTTPSnapshotFile(s.binding, archive, false)
		if e != nil {
			return e
		}
		if got != id {
			return ErrIdentityConflict
		}
	} else if err != nil {
		return err
	} else {
		got, e := s.r.pendingHTTPSnapshotFile(s.binding, filename, false)
		if e != nil {
			return e
		}
		if got != id {
			return ErrIdentityConflict
		}
		archives, e := filepath.Glob(filename + ".expired-*")
		if e != nil {
			return e
		}
		_, archived := os.Lstat(archive)
		if len(archives) >= 16 && errors.Is(archived, os.ErrNotExist) {
			return ErrHTTPRebootstrapLimit
		}
		if e = os.Link(filename, archive); errors.Is(e, os.ErrExist) {
			a, ea := os.Lstat(filename)
			b, eb := os.Lstat(archive)
			if ea != nil || eb != nil || !os.SameFile(a, b) {
				return ErrIdentityConflict
			}
		} else if e != nil {
			return e
		}
		if e = s.r.point("initial_import.read_linked"); e != nil {
			return e
		}
		if e = os.Remove(filename); e != nil {
			return e
		}
	}
	directory, err := os.OpenFile(dirname, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
