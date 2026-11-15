package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// v8 is additive. Original operations, receipts, captures and batch memberships
// remain byte-for-byte unchanged. Old writers refuse the new schema.
const daemonSchemaVersion = 8
const daemonSchema = `
CREATE TABLE source_observers(set_id TEXT PRIMARY KEY REFERENCES source_sets(set_id),owner_id TEXT NOT NULL,sequence INTEGER NOT NULL DEFAULT 0,gap_sequence INTEGER NOT NULL DEFAULT 0,gap INTEGER NOT NULL DEFAULT 1,reason TEXT NOT NULL DEFAULT 'cold restart');
CREATE TABLE source_dirty(set_id TEXT NOT NULL REFERENCES source_sets(set_id),source_id TEXT NOT NULL,destination TEXT NOT NULL,physical_path TEXT NOT NULL,generation INTEGER NOT NULL,first_ms INTEGER NOT NULL,last_ms INTEGER NOT NULL,mask INTEGER NOT NULL,cookie INTEGER NOT NULL,PRIMARY KEY(set_id,source_id,destination));
CREATE INDEX source_dirty_ready ON source_dirty(set_id,first_ms,source_id,destination);
CREATE TABLE operation_retry(operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),attempt INTEGER NOT NULL,state TEXT NOT NULL,next_ms INTEGER NOT NULL,reason TEXT NOT NULL);
CREATE TABLE parent_cache(root_id TEXT NOT NULL REFERENCES roots(root_id),binding_key TEXT NOT NULL,destination TEXT NOT NULL,node_id TEXT NOT NULL,metadata_version TEXT NOT NULL,expires_ms INTEGER NOT NULL,PRIMARY KEY(root_id,binding_key,destination));
CREATE INDEX local_portable_namespace ON local_entries(root_id,COALESCE(parent_id,''),lower(json_extract(descriptor_json,'$.Name'))) WHERE json_extract(descriptor_json,'$.Presence')='PRESENT';
CREATE INDEX remote_portable_namespace ON remote_entries(root_id,generation,json_extract(descriptor_json,'$.ParentID'),lower(json_extract(descriptor_json,'$.Name')),node_id) WHERE json_extract(descriptor_json,'$.Presence')='PRESENT';
CREATE TABLE profile_policy(root_id TEXT PRIMARY KEY REFERENCES roots(root_id),revision INTEGER NOT NULL,digest TEXT NOT NULL,codec TEXT NOT NULL,policy_json TEXT NOT NULL);
CREATE TABLE stream_progress(operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),status_json TEXT NOT NULL DEFAULT '',pending_json TEXT NOT NULL DEFAULT '',source_verified INTEGER NOT NULL DEFAULT 0);
CREATE TABLE profile_rebinding(root_id TEXT PRIMARY KEY REFERENCES roots(root_id),old_binding TEXT NOT NULL,new_binding TEXT NOT NULL,cursor TEXT NOT NULL DEFAULT '',unmatched INTEGER NOT NULL DEFAULT 0,phase TEXT NOT NULL DEFAULT 'AUTHORIZED');
CREATE INDEX folder_receipt_node ON operations(root_id,json_extract(receipt_json,'$.Description.NodeID'),operation_id) WHERE kind='ENSURE_DIRECTORY' AND stage='CLIENT_ACKED';
`

func (r *RemoteImport) EnableDaemonState(ctx context.Context) error {
	if _, err := r.enableSmallBatches(ctx); err != nil {
		return err
	}
	r.store.sourceMu.Lock()
	defer r.store.sourceMu.Unlock()
	var version int
	if err := r.store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == daemonSchemaVersion {
		return nil
	}
	if version != smallBatchSchemaVersion {
		return ErrUnsupportedSchema
	}
	u, err := r.sources.DiskUsage(ctx)
	if err != nil {
		return err
	}
	projected := u.PageCount * u.PageSize
	if u.Backup+projected > r.sources.limits.BackupBytes || u.Free-projected < r.sources.limits.FreeDiskBytes {
		return ErrSourceQuota
	}
	backup, err := backupVersion(ctx, filepath.Dir(r.store.filename), r.store.filename, version)
	if err != nil {
		return err
	}
	if backup == nil {
		return ErrUnsupportedSchema
	}
	manifest, _ := json.Marshal(map[string]any{"fromVersion": version, "toVersion": daemonSchemaVersion, "backup": backup.Filename, "backupSHA256": backup.SHA256, "module": "daemon-observer/v1", "originalOperationsAndBaselines": "unchanged"})
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		var current int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
			return err
		}
		if current != version {
			return ErrStaleGeneration
		}
		if _, err := tx.ExecContext(ctx, daemonSchema); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", daemonSchemaVersion)); err != nil {
			return err
		}
		if err := r.point("daemon.migration.before_commit"); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", daemonSchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(manifest))
		return err
	})
}

type DirtyHint struct {
	SourceID, Destination, PhysicalPath string
	Generation, FirstMS, LastMS         int64
	Mask, Cookie                        uint32
}
type ObserverState struct {
	Sequence, GapSequence int64
	Gap                   bool
	Reason                string
	Pending               int64
	OldestMS              int64
}

func (s *Sources) StartObserver(ctx context.Context, w SourceWitness) error {
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO source_observers(set_id,owner_id) VALUES(?,?) ON CONFLICT(set_id) DO UPDATE SET owner_id=excluded.owner_id,gap=1,sequence=sequence+1,gap_sequence=sequence+1,reason='cold restart or observation resumed'`, w.SetID, w.OwnerID)
		return err
	})
}

// Hints are invalidations, never content equality or absence evidence. Coalescing
// retains first age and the latest generation; ACK(g) cannot consume g+1.
func (s *Sources) RecordDirty(ctx context.Context, w SourceWitness, hints []DirtyHint) error {
	if len(hints) > MaxSourcePage {
		return ErrSourceQuota
	}
	for _, h := range hints {
		if !validID(h.SourceID) || !validDestination(h.Destination) || !validSourcePath(h.PhysicalPath) {
			return ErrIdentityConflict
		}
	}
	return s.change(ctx, 4<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		var seq int64
		if err := tx.QueryRowContext(ctx, "SELECT sequence FROM source_observers WHERE set_id=? AND owner_id=?", w.SetID, w.OwnerID).Scan(&seq); err != nil {
			return err
		}
		now := time.Now().UnixMilli()
		for _, h := range hints {
			if seq == int64(^uint64(0)>>1) {
				return ErrSourceQuota
			}
			seq++
			_, err := tx.ExecContext(ctx, `INSERT INTO source_dirty(set_id,source_id,destination,physical_path,generation,first_ms,last_ms,mask,cookie) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(set_id,source_id,destination) DO UPDATE SET physical_path=excluded.physical_path,generation=excluded.generation,last_ms=excluded.last_ms,mask=source_dirty.mask|excluded.mask,cookie=excluded.cookie`, w.SetID, h.SourceID, h.Destination, h.PhysicalPath, seq, now, now, h.Mask, h.Cookie)
			if err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, "UPDATE source_observers SET sequence=? WHERE set_id=? AND owner_id=?", seq, w.SetID, w.OwnerID)
		return err
	})
}
func (s *Sources) ObserverGap(ctx context.Context, w SourceWitness, reason string) error {
	if len(reason) == 0 || len(reason) > 512 {
		return ErrIdentityConflict
	}
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE source_observers SET gap=1,sequence=sequence+1,gap_sequence=sequence+1,reason=? WHERE set_id=? AND owner_id=?", reason, w.SetID, w.OwnerID)
		return err
	})
}
func (s *Sources) ObserverStatus(ctx context.Context, w SourceWitness) (ObserverState, error) {
	var out ObserverState
	err := s.store.db.QueryRowContext(ctx, `SELECT sequence,gap_sequence,gap,reason,(SELECT COUNT(*) FROM source_dirty WHERE set_id=?),(SELECT COALESCE(MIN(first_ms),0) FROM source_dirty WHERE set_id=?) FROM source_observers WHERE set_id=? AND owner_id=?`, w.SetID, w.SetID, w.SetID, w.OwnerID).Scan(&out.Sequence, &out.GapSequence, &out.Gap, &out.Reason, &out.Pending, &out.OldestMS)
	return out, err
}
func (s *Sources) DirtyPage(ctx context.Context, w SourceWitness, now time.Time) ([]DirtyHint, error) {
	rows, err := s.store.db.QueryContext(ctx, `SELECT source_id,destination,physical_path,generation,first_ms,last_ms,mask,cookie FROM source_dirty WHERE set_id=? AND (last_ms<=? OR first_ms<=?) ORDER BY first_ms,source_id,destination LIMIT ?`, w.SetID, now.Add(-750*time.Millisecond).UnixMilli(), now.Add(-5*time.Second).UnixMilli(), MaxSourcePage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirtyHint
	for rows.Next() {
		var h DirtyHint
		if err = rows.Scan(&h.SourceID, &h.Destination, &h.PhysicalPath, &h.Generation, &h.FirstMS, &h.LastMS, &h.Mask, &h.Cookie); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
func (s *Sources) AckDirty(ctx context.Context, w SourceWitness, h DirtyHint) error {
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM source_dirty WHERE set_id=? AND source_id=? AND destination=? AND generation<=?", w.SetID, h.SourceID, h.Destination, h.Generation)
		return err
	})
}
func (s *Sources) ReconciledObserver(ctx context.Context, w SourceWitness, cut int64) error {
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		// A new gap during traversal cannot be cleared by an old cut. The owner
		// additionally fences overflow before this call.
		_, err := tx.ExecContext(ctx, "UPDATE source_observers SET gap=0,reason='' WHERE set_id=? AND owner_id=? AND gap_sequence=?", w.SetID, w.OwnerID, cut)
		return err
	})
}

// BeginTargetScan reuses the bounded scanner and membership machinery for one
// observed path. It cannot broaden authority beyond its configured source.
func (s *Sources) BeginTargetScan(ctx context.Context, w SourceWitness, h DirtyHint, id string) (Scan, error) {
	b, err := s.Binding(ctx, w.SetID, h.SourceID)
	if err != nil {
		return Scan{}, err
	}
	rel, err := filepath.Rel(b.PhysicalPath, h.PhysicalPath)
	if err != nil || rel == ".." || filepath.IsAbs(rel) || len(rel) > 3 && rel[:3] == "../" {
		return Scan{}, ErrIdentityConflict
	}
	dest := b.Destination
	if rel != "." {
		dest += "/" + filepath.ToSlash(rel)
	}
	if dest != h.Destination {
		return Scan{}, ErrIdentityConflict
	}
	// Restart an interrupted target traversal. Its hint and all publication
	// originals remain durable; a partial target must never masquerade as a
	// complete source reconciliation after a later health deadline.
	if err = s.retireTargetScan(ctx, w, h.SourceID, false); err != nil {
		return Scan{}, err
	}
	scan, err := s.BeginScan(ctx, w, h.SourceID, id)
	if err != nil {
		return scan, err
	}
	err = s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE source_scans SET reason='targeted observation' WHERE scan_id=?", id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE source_frontier SET physical_path=?,destination=? WHERE scan_id=? AND work_id=1", h.PhysicalPath, h.Destination, id)
		return err
	})
	return scan, err
}

// RetryScan resumes only an existing scan under this exact live owner. Lost
// directory cookies are reread; completed frontier entries remain retired.
func (s *Sources) RetryScan(ctx context.Context, w SourceWitness, source string) (Scan, error) {
	if err := s.retireTargetScan(ctx, w, source, true); err != nil {
		return Scan{}, err
	}
	var id string
	err := s.store.db.QueryRowContext(ctx, "SELECT scan_id FROM source_scans WHERE set_id=? AND source_id=? AND owner_id=? AND owner_sequence=? AND gap_generation=? AND status='DISCOVERING' ORDER BY scan_id LIMIT 1", w.SetID, source, w.OwnerID, w.OwnerSequence, w.GapGeneration).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Scan{}, err
	}
	if err != nil {
		return Scan{}, err
	}
	err = s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE source_frontier SET claim_token='' WHERE scan_id=?", id)
		return err
	})
	if err != nil {
		return Scan{}, err
	}
	return s.Scan(ctx, id)
}

func (s *Sources) retireTargetScan(ctx context.Context, w SourceWitness, source string, onlyTargets bool) error {
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		query := "UPDATE source_scans SET status='INCOMPLETE',reason='rescheduled observation; originals retained' WHERE set_id=? AND source_id=? AND owner_id=? AND owner_sequence=? AND gap_generation=? AND status='DISCOVERING'"
		if onlyTargets {
			query += " AND reason='targeted observation'"
		}
		_, err := tx.ExecContext(ctx, query, w.SetID, source, w.OwnerID, w.OwnerSequence, w.GapGeneration)
		return err
	})
}
