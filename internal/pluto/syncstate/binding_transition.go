package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Authorization is written only by digest-bound offline adoption. It does not
// rewrite original operations or itself establish agreement with a new server.
func (s *Store) AuthorizeBindingTransition(ctx context.Context, root string, old, next RemoteBinding) error {
	if old == next || old.RootID != next.RootID || old.ServerIdentity != next.ServerIdentity || old.Protocol != next.Protocol || old.DescriptorSchema != next.DescriptorSchema {
		return ErrIdentityConflict
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var version, pending int
		if e := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
			return e
		}
		if version != daemonSchemaVersion {
			return ErrUnsupportedSchema
		}
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations WHERE root_id=? AND stage<>'CLIENT_ACKED'", root).Scan(&pending); e != nil {
			return e
		}
		if pending != 0 {
			return ErrArtifactRetained
		}
		candidate, e := readCandidate(ctx, tx, root)
		if e != nil {
			return e
		}
		if candidate.Binding != old || candidate.HTTPRebootstrap != nil {
			return ErrStaleGeneration
		}
		var priorOld, priorNext, phase string
		e = tx.QueryRowContext(ctx, "SELECT old_binding,new_binding,phase FROM profile_rebinding WHERE root_id=?", root).Scan(&priorOld, &priorNext, &phase)
		oldJSON, nextJSON := string(mustJSON(old)), string(mustJSON(next))
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && phase != "COMPLETE" {
			if priorOld == oldJSON && priorNext == nextJSON {
				return nil
			}
			return ErrIdentityConflict
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO profile_rebinding(root_id,old_binding,new_binding) VALUES(?,?,?) ON CONFLICT(root_id) DO UPDATE SET old_binding=excluded.old_binding,new_binding=excluded.new_binding,cursor='',unmatched=0,phase='AUTHORIZED'", root, oldJSON, nextJSON)
		return e
	})
}

// After the HTTPS handshake and complete imported snapshot, rebind only exact
// historical node/content agreement. Moved/changed/missing data stays conflicted.
// Cursor and bounded page updates commit together; interruption resumes safely.
func (s *IsolatedHTTPSession) ReconcileBindingTransition(ctx context.Context) error {
	for {
		finished := false
		err := s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
			var oldRaw, nextRaw, cursor, phase string
			e := tx.QueryRowContext(ctx, "SELECT old_binding,new_binding,cursor,phase FROM profile_rebinding WHERE root_id=?", s.root).Scan(&oldRaw, &nextRaw, &cursor, &phase)
			if errors.Is(e, sql.ErrNoRows) {
				finished = true
				return nil
			}
			if e != nil {
				return e
			}
			if phase == "COMPLETE" {
				finished = true
				return nil
			}
			var old, next RemoteBinding
			if json.Unmarshal([]byte(oldRaw), &old) != nil || json.Unmarshal([]byte(nextRaw), &next) != nil || next != s.binding {
				return ErrIdentityConflict
			}
			candidate, e := readCandidate(ctx, tx, s.root)
			if e != nil {
				return e
			}
			if !candidate.Valid || candidate.Binding != next || candidate.HTTPRebootstrap != nil {
				return ErrRemoteUnqualified
			}
			root, e := readRoot(ctx, tx, s.root)
			if e != nil {
				return e
			}
			if root.ActiveRemoteGeneration != candidate.Generation || root.TrustGeneration != candidate.TrustGeneration {
				return ErrStaleGeneration
			}
			var pending bool
			if e = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM operations WHERE root_id=? AND stage<>'CLIENT_ACKED')", s.root).Scan(&pending); e != nil {
				return e
			}
			if pending {
				return ErrArtifactRetained
			}
			rows, e := tx.QueryContext(ctx, "SELECT entry_id,descriptor_json FROM baselines WHERE root_id=? AND entry_id>? ORDER BY entry_id LIMIT 128", s.root, cursor)
			if e != nil {
				return e
			}
			type item struct{ id, raw string }
			page := []item{}
			bytes := 0
			for rows.Next() {
				var v item
				if e = rows.Scan(&v.id, &v.raw); e != nil {
					rows.Close()
					return e
				}
				bytes += len(v.raw)
				if bytes > MaxSourcePageBytes {
					rows.Close()
					return ErrSourceQuota
				}
				page = append(page, v)
			}
			e = errors.Join(rows.Err(), rows.Close())
			if e != nil {
				return e
			}
			unmatched := 0
			for _, v := range page {
				cursor = v.id
				var base Baseline
				if json.Unmarshal([]byte(v.raw), &base) != nil {
					return ErrIdentityConflict
				}
				if base.RemoteBinding == nil || *base.RemoteBinding != old {
					unmatched++
					continue
				}
				remote, e := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", s.root, candidate.Generation, base.NodeID)
				if e != nil && !errors.Is(e, sql.ErrNoRows) {
					return e
				}
				if e != nil || !currentRemoteBinding(remote, candidate.RemoteWitness) || remote.Availability != "AVAILABLE" || remote.Presence != base.Presence || base.Presence != "PRESENT" || remote.ParentID != base.RemoteParentID || remote.Name != base.Name || remote.Kind != base.Kind {
					unmatched++
					continue
				}
				if base.Kind == "file" && (remote.Version != base.Version || remote.ContentVersionID != base.ContentVersionID || remote.SizeBytes != base.SizeBytes || remote.SHA256 != base.SHA256) {
					unmatched++
					continue
				}
				base.RemoteBinding = &next
				base.TrustGeneration = candidate.TrustGeneration
				base.Epoch = next.ServerEpoch
				base.LastSeq = remote.LastSeq
				base.Version = remote.Version
				if _, e = tx.ExecContext(ctx, "UPDATE baselines SET descriptor_json=? WHERE root_id=? AND entry_id=?", string(mustJSON(base)), s.root, v.id); e != nil {
					return e
				}
			}
			phase = "RECONCILING"
			if len(page) < 128 {
				phase = "COMPLETE"
				finished = true
			}
			_, e = tx.ExecContext(ctx, "UPDATE profile_rebinding SET cursor=?,unmatched=unmatched+?,phase=? WHERE root_id=?", cursor, unmatched, phase, s.root)
			return e
		})
		if err != nil {
			return err
		}
		if finished {
			return nil
		}
	}
}
