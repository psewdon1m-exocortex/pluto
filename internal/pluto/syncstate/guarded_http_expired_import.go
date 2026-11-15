package syncstate

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// A READY read lease can expire after some pages have been imported. Those
// invisible cache pages cannot establish authority. Persist retirement before
// dropping the preparation marker, so a crash resumes bounded cache cleanup
// without changing B, publication identities, sealed artifacts or dirty work.
func (s *IsolatedHTTPSession) beginExpiredImportRetirement(ctx context.Context, expected RemoteCandidate, preparation SnapshotPreparation, now time.Time) (RemoteCandidate, error) {
	var result RemoteCandidate
	if !validHTTPCheckpoint(expected, s.transportPin) || expected.HTTPRebootstrap.Phase != httpBootstrapPreparing {
		return result, ErrRemoteUnqualified
	}
	err := s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		current, err := s.checkImportRetirementOwner(ctx, tx, expected)
		if err != nil {
			return err
		}
		p, err := readPreparation(ctx, tx, s.root)
		if err != nil {
			return err
		}
		if fingerprint(p) != fingerprint(preparation) || p.RootID != s.root || p.Generation != current.Generation+1 || p.PreviousGeneration != current.Generation || p.TrustGeneration != current.TrustGeneration || p.Snapshot.SnapshotID != current.HTTPRebootstrap.SnapshotID || p.Snapshot.Binding != s.binding || p.ExpiresMS <= 0 || now.UnixMilli() < p.ExpiresMS {
			return ErrStaleGeneration
		}
		checkpoint := *current.HTTPRebootstrap
		if checkpoint.RetiredSnapshotIDs != "" && len(strings.Split(checkpoint.RetiredSnapshotIDs, ",")) >= 16 {
			return ErrHTTPRebootstrapLimit
		}
		checkpoint.Phase = httpBootstrapRetiringImport
		checkpoint.RetiringGeneration, checkpoint.RetiringExpiresMS = p.Generation, p.ExpiresMS
		current.HTTPRebootstrap = &checkpoint
		if !validHTTPCheckpoint(current, s.transportPin) {
			return ErrIdentityConflict
		}
		if err = saveCandidate(ctx, tx, current); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM remote_preparations WHERE root_id=?", s.root); err != nil {
			return err
		}
		result = current
		return s.r.point("http_rebootstrap.expired_import_before_commit")
	})
	return result, err
}

func (s *IsolatedHTTPSession) checkImportRetirementOwner(ctx context.Context, tx *sql.Tx, expected RemoteCandidate) (RemoteCandidate, error) {
	c, err := readCandidate(ctx, tx, s.root)
	if err != nil {
		return c, err
	}
	root, err := readRoot(ctx, tx, s.root)
	if err != nil {
		return c, err
	}
	if fingerprint(c) != fingerprint(expected) || !validHTTPCheckpoint(c, s.transportPin) || c.Binding != s.binding || root.ActiveRemoteGeneration != c.Generation || root.TrustGeneration != c.TrustGeneration || root.DeviceID != s.identity.DeviceID || root.RemoteRootID != s.binding.RootID || root.ServerIdentity != s.binding.ServerIdentity {
		return c, ErrStaleGeneration
	}
	return c, s.validateRetainedHTTPIdentity(ctx, tx)
}

func (s *IsolatedHTTPSession) finishExpiredImportRetirement(ctx context.Context, expected RemoteCandidate) (RemoteCandidate, error) {
	var result RemoteCandidate
	if !validHTTPCheckpoint(expected, s.transportPin) || expected.HTTPRebootstrap.Phase != httpBootstrapRetiringImport {
		return result, ErrRemoteUnqualified
	}
	// Verify the durable owner before any cleanup; PruneRemoteGeneration also
	// refuses active or prepared generations on every bounded transaction.
	if err := s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error { _, e := s.checkImportRetirementOwner(ctx, tx, expected); return e }); err != nil {
		return result, err
	}
	done := false
	for page := 0; page < 8192; page++ {
		n, err := s.r.PruneRemoteGeneration(ctx, s.root, expected.HTTPRebootstrap.RetiringGeneration, MaxRemotePage)
		if err != nil {
			return result, err
		}
		if n == 0 {
			done = true
			break
		}
		if err = s.r.point("http_rebootstrap.expired_import_pruned"); err != nil {
			return result, err
		}
	}
	if !done {
		return result, ErrSourceQuota
	}
	id, err := NewOperationID()
	if err != nil {
		return result, err
	}
	err = s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		current, err := s.checkImportRetirementOwner(ctx, tx, expected)
		if err != nil {
			return err
		}
		p := *current.HTTPRebootstrap
		var remaining int
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remote_preparations WHERE root_id=?) OR EXISTS(SELECT 1 FROM remote_entries WHERE root_id=? AND generation=?) OR EXISTS(SELECT 1 FROM remote_snapshot_pages WHERE root_id=? AND generation=?)`, s.root, s.root, p.RetiringGeneration, s.root, p.RetiringGeneration).Scan(&remaining); err != nil {
			return err
		}
		if remaining != 0 {
			return ErrRemoteIncomplete
		}
		if p.RetiredSnapshotIDs != "" && len(strings.Split(p.RetiredSnapshotIDs, ",")) >= 16 {
			return ErrHTTPRebootstrapLimit
		}
		if p.RetiredSnapshotIDs != "" {
			p.RetiredSnapshotIDs += ","
		}
		p.RetiredSnapshotIDs += p.SnapshotID
		p.SnapshotID, p.Phase = id, httpBootstrapPreparing
		p.RetiringGeneration, p.RetiringExpiresMS = 0, 0
		current.HTTPRebootstrap = &p
		if !validHTTPCheckpoint(current, s.transportPin) {
			return ErrIdentityConflict
		}
		if err = saveCandidate(ctx, tx, current); err != nil {
			return err
		}
		result = current
		return s.r.point("http_rebootstrap.expired_import_finished_before_commit")
	})
	return result, err
}
