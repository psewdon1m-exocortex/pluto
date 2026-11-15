package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"pluto/internal/syncproto"
	"time"
)

func readPreparation(ctx context.Context, q queryer, root string) (SnapshotPreparation, error) {
	return readJSON[SnapshotPreparation](ctx, q, "SELECT descriptor_json FROM remote_preparations WHERE root_id=?", root)
}
func savePreparation(ctx context.Context, tx *sql.Tx, p SnapshotPreparation) error {
	raw, _ := json.Marshal(p)
	_, err := tx.ExecContext(ctx, "INSERT INTO remote_preparations(root_id,generation,descriptor_json) VALUES(?,?,?) ON CONFLICT(root_id) DO UPDATE SET generation=excluded.generation,descriptor_json=excluded.descriptor_json", p.RootID, p.Generation, string(raw))
	return err
}

func (r *RemoteImport) Preparation(ctx context.Context, root string) (SnapshotPreparation, error) {
	return readPreparation(ctx, r.store.db, root)
}

// PrepareSnapshot stages a shape-validated remote snapshot beside the active R.
// The candidate root binding must match the configured actual remote root. A
// READY response is not a capability handshake and never establishes B.
func (r *RemoteImport) PrepareSnapshot(ctx context.Context, rootID string, trust int64, raw []byte, now time.Time) (SnapshotPreparation, error) {
	return r.prepareSnapshot(ctx, rootID, trust, raw, now, nil)
}

func (r *RemoteImport) prepareSnapshot(ctx context.Context, rootID string, trust int64, raw []byte, now time.Time, continuation *HTTPRebootstrapCheckpoint) (SnapshotPreparation, error) {
	var result SnapshotPreparation
	if !validID(rootID) || trust < 1 {
		return result, ErrIdentityConflict
	}
	snapshot, err := syncproto.ReadSnapshot(raw)
	if err != nil {
		return result, err
	}
	if now.UnixMilli() < 0 || now.UnixMilli() > math.MaxInt64-snapshot.LeaseSeconds*1000 {
		return result, ErrIdentityConflict
	}
	err = r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		root, err := readRoot(ctx, tx, rootID)
		if err != nil {
			return err
		}
		if root.TrustGeneration != trust || root.ServerIdentity != snapshot.ServerIdentity || root.RemoteRootID != snapshot.RootID || root.ActiveRemoteGeneration == math.MaxInt64 {
			return ErrStaleGeneration
		}
		old, e := readPreparation(ctx, tx, rootID)
		if e == nil {
			if old.Snapshot != snapshot || old.TrustGeneration != trust || old.PreviousGeneration != root.ActiveRemoteGeneration || now.UnixMilli() >= old.ExpiresMS {
				return ErrIdentityConflict
			}
			result = old
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var seen int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM remote_seen_bindings WHERE root_id=? AND binding_version=?", rootID, snapshot.BindingVersion).Scan(&seen); err != nil {
			return err
		}
		if seen != 0 {
			current, err := readCandidate(ctx, tx, rootID)
			qualifiedContinuation := err == nil && continuation != nil && validHTTPCheckpoint(current, continuation.TransportPin) && current.HTTPRebootstrap.Phase == httpBootstrapPreparing && *current.HTTPRebootstrap == *continuation && snapshot.SnapshotID == continuation.SnapshotID && snapshot.Binding == continuation.Original.Binding
			if err != nil || !current.Valid && !qualifiedContinuation || current.TrustGeneration != trust || current.Binding != snapshot.Binding {
				return ErrIdentityConflict
			}
		}
		generation := root.ActiveRemoteGeneration + 1
		var existing int
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM remote_entries WHERE root_id=? AND generation=? LIMIT 1)", rootID, generation).Scan(&existing); err != nil {
			return err
		}
		if existing != 0 {
			return ErrRemoteIncomplete
		} // Explicit bounded cleanup is required.
		result = SnapshotPreparation{RootID: rootID, Generation: generation, PreviousGeneration: root.ActiveRemoteGeneration, TrustGeneration: trust, Snapshot: snapshot, Cursor: snapshot.EntriesCursor, ExpiresMS: now.UnixMilli() + snapshot.LeaseSeconds*1000}
		return savePreparation(ctx, tx, result)
	})
	return result, err
}

func remoteFromDescriptor(root string, generation, seq int64, binding RemoteBinding, d syncproto.Descriptor, operation string) RemoteEntry {
	size, _ := syncproto.Integer64(d.SizeBytes)
	e := RemoteEntry{RootID: root, NodeID: d.NodeID, Name: d.Name, Kind: d.Type, Epoch: binding.ServerEpoch, Version: d.Version, Generation: generation, SizeBytes: size, LastSeq: seq, Presence: "PRESENT", Availability: d.Availability, RemoteBinding: &binding, OperationID: operation}
	if d.ParentID != nil {
		e.ParentID = *d.ParentID
	}
	if d.ContentSHA256 != nil {
		e.SHA256 = *d.ContentSHA256
	}
	if d.ContentVersionID != nil {
		e.ContentVersionID = *d.ContentVersionID
	}
	return e
}
func descriptorFromRemote(e RemoteEntry) syncproto.Descriptor {
	d := syncproto.Descriptor{NodeID: e.NodeID, Name: e.Name, Type: e.Kind, SizeBytes: remoteDecimal(e.SizeBytes), Version: e.Version, Availability: e.Availability}
	if e.ParentID != "" {
		parent := e.ParentID
		d.ParentID = &parent
	}
	if e.SHA256 != "" {
		sha := e.SHA256
		d.ContentSHA256 = &sha
	}
	if e.ContentVersionID != "" {
		version := e.ContentVersionID
		d.ContentVersionID = &version
	}
	return d
}
func saveRemoteCandidateEntry(ctx context.Context, tx *sql.Tx, e RemoteEntry) error {
	raw, _ := json.Marshal(e)
	_, err := tx.ExecContext(ctx, "INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES(?,?,?,?,?) ON CONFLICT(root_id,generation,node_id) DO UPDATE SET last_seq=excluded.last_seq,descriptor_json=excluded.descriptor_json", e.RootID, e.Generation, e.NodeID, e.LastSeq, string(raw))
	return err
}

// AbandonPreparation drops only the preparation CAS marker. Its staged rows and
// replay identities remain retained until explicit bounded local cache pruning.
// Neither active R nor B/dirty/intents are affected.
func (r *RemoteImport) AbandonPreparation(ctx context.Context, expected SnapshotPreparation) error {
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		p, err := readPreparation(ctx, tx, expected.RootID)
		if err != nil {
			return err
		}
		if fingerprint(p) != fingerprint(expected) {
			return ErrStaleGeneration
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM remote_preparations WHERE root_id=?", expected.RootID)
		return err
	})
}

// PruneRemoteGeneration is local cache cleanup, never a server-delete effect.
// It cannot touch an active/prepared generation and deletes at most 500 entries
// plus 500 bounded page receipts per call. Crash/retry is idempotent.
func (r *RemoteImport) PruneRemoteGeneration(ctx context.Context, root string, generation int64, limit int) (int, error) {
	if generation < 1 || limit < 1 || limit > MaxRemotePage {
		return 0, ErrSourceQuota
	}
	count := 0
	err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		actual, err := readRoot(ctx, tx, root)
		if err != nil {
			return err
		}
		if generation == actual.ActiveRemoteGeneration {
			return ErrStaleGeneration
		}
		var prepared int
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM remote_preparations WHERE root_id=? AND generation=?)", root, generation).Scan(&prepared); err != nil {
			return err
		}
		if prepared != 0 {
			return ErrRemoteIncomplete
		}
		result, err := tx.ExecContext(ctx, "DELETE FROM remote_entries WHERE root_id=? AND generation=? AND node_id IN (SELECT node_id FROM remote_entries WHERE root_id=? AND generation=? ORDER BY node_id LIMIT ?)", root, generation, root, generation, limit)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		count += int(n)
		result, err = tx.ExecContext(ctx, "DELETE FROM remote_snapshot_pages WHERE root_id=? AND generation=? AND request_cursor IN (SELECT request_cursor FROM remote_snapshot_pages WHERE root_id=? AND generation=? ORDER BY request_cursor LIMIT ?)", root, generation, root, generation, limit)
		if err != nil {
			return err
		}
		n, err = result.RowsAffected()
		count += int(n)
		return err
	})
	return count, err
}

// ImportSnapshotPage commits one bounded page and its key/cursor atomically.
// Retrying a committed request must reproduce its exact raw bytes. Incomplete
// prepared generations are invisible and never imply remote absence.
func (r *RemoteImport) ImportSnapshotPage(ctx context.Context, root, requestCursor string, raw []byte, now time.Time) (SnapshotPreparation, error) {
	var result SnapshotPreparation
	if !validID(root) || len(requestCursor) < 1 || len(requestCursor) > 4096 {
		return result, ErrIdentityConflict
	}
	if len(raw) > syncproto.MaxBytes {
		return result, syncproto.ErrLimit
	}
	err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		p, err := readPreparation(ctx, tx, root)
		if err != nil {
			return err
		}
		actual, err := readRoot(ctx, tx, root)
		if err != nil {
			return err
		}
		if actual.TrustGeneration != p.TrustGeneration || actual.ActiveRemoteGeneration != p.PreviousGeneration || now.UnixMilli() < 0 || now.UnixMilli() >= p.ExpiresMS {
			return ErrStaleGeneration
		}
		var priorHash, priorResult string
		err = tx.QueryRowContext(ctx, "SELECT response_hash,result_json FROM remote_snapshot_pages WHERE root_id=? AND generation=? AND request_cursor=?", root, p.Generation, requestCursor).Scan(&priorHash, &priorResult)
		if err == nil {
			if priorHash != hashBytes(raw) {
				return ErrIdentityConflict
			}
			// A duplicate older page reports current preparation; it never rolls
			// back a persisted key or creates another generation.
			result = p
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if p.Complete || requestCursor != p.Cursor {
			return ErrStaleGeneration
		}
		page, err := syncproto.ReadSnapshotEntries(raw, p.Snapshot, p.AfterNodeID)
		if err != nil {
			return err
		}
		if page.HasMore && page.NextCursor == requestCursor {
			return ErrIdentityConflict
		}
		cut, _ := syncproto.Integer64(p.Snapshot.CutSeq)
		for _, d := range page.Items {
			e := remoteFromDescriptor(root, p.Generation, cut, p.Snapshot.Binding, d, "")
			if err = saveRemoteCandidateEntry(ctx, tx, e); err != nil {
				return err
			}
		}
		p.AfterNodeID = page.LastNodeID
		p.Cursor = page.NextCursor
		p.Complete = !page.HasMore
		if err = r.point("snapshot.before_cursor"); err != nil {
			return err
		}
		if err = savePreparation(ctx, tx, p); err != nil {
			return err
		}
		rawResult, _ := json.Marshal(p)
		if _, err = tx.ExecContext(ctx, "INSERT INTO remote_snapshot_pages(root_id,generation,request_cursor,response_hash,result_json) VALUES(?,?,?,?,?)", root, p.Generation, requestCursor, hashBytes(raw), string(rawResult)); err != nil {
			return err
		}
		result = p
		return nil
	})
	return result, err
}

// PublishSnapshot swaps only candidate R and its opaque feed cursor. Dirty debt
// is a durable indexed frontier, not a whole-tree in-memory enumeration. The
// legacy remote cursor remains invalid because shape validation isn't authority.
func (r *RemoteImport) PublishSnapshot(ctx context.Context, root string, expected SnapshotPreparation, now time.Time) (RemoteCandidate, error) {
	var result RemoteCandidate
	err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		p, err := readPreparation(ctx, tx, root)
		if err != nil {
			return err
		}
		if fingerprint(p) != fingerprint(expected) || !p.Complete {
			return ErrRemoteIncomplete
		}
		current, err := readRoot(ctx, tx, root)
		if err != nil {
			return err
		}
		if current.TrustGeneration != p.TrustGeneration || current.ActiveRemoteGeneration != p.PreviousGeneration || now.UnixMilli() < 0 || now.UnixMilli() >= p.ExpiresMS {
			return ErrStaleGeneration
		}
		old, e := readCandidate(ctx, tx, root)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		revision := int64(1)
		if e == nil {
			if old.Revision == math.MaxInt64 {
				return ErrStaleGeneration
			}
			revision = old.Revision + 1
		}
		cut, _ := syncproto.Integer64(p.Snapshot.CutSeq)
		result = RemoteCandidate{RemoteWitness: RemoteWitness{RootID: root, TrustGeneration: current.TrustGeneration, Generation: p.Generation, Revision: revision, Position: cut, Binding: p.Snapshot.Binding, Cursor: p.Snapshot.ChangesCursor, Valid: true}, SnapshotID: p.Snapshot.SnapshotID}
		if old.HTTPRebootstrap != nil {
			if !validHTTPCheckpoint(old, old.HTTPRebootstrap.TransportPin) || old.HTTPRebootstrap.Phase != httpBootstrapPreparing || p.Snapshot.SnapshotID != old.HTTPRebootstrap.SnapshotID || p.Snapshot.Binding != old.HTTPRebootstrap.Original.Binding || cut < old.HTTPRebootstrap.Original.Position {
				return ErrIdentityConflict
			}
			checkpoint := *old.HTTPRebootstrap
			checkpoint.Phase = httpBootstrapAwaitFeed
			result.HTTPRebootstrap = &checkpoint
			result.Valid = false
		}
		if _, err = tx.ExecContext(ctx, "UPDATE roots SET active_remote_generation=? WHERE root_id=?", p.Generation, root); err != nil {
			return err
		}
		if err = saveCandidate(ctx, tx, result); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO remote_seen_bindings(root_id,binding_version) VALUES(?,?)", root, result.Binding.BindingVersion); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO journal_cursors(root_id,stream,epoch,position,valid) VALUES(?,'remote',?,?,0) ON CONFLICT(root_id,stream) DO UPDATE SET epoch=excluded.epoch,position=excluded.position,valid=0", root, result.Binding.ServerEpoch, cut); err != nil {
			return err
		}
		if err = queueAllRemoteWork(ctx, tx, root, p.Generation, cut); err != nil {
			return err
		}
		if err = r.point("snapshot.before_publish"); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM remote_preparations WHERE root_id=?", root)
		return err
	})
	return result, err
}
