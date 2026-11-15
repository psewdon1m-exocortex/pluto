package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"pluto/internal/syncproto"
	"reflect"
	"strconv"
)

func remoteDecimal(n int64) string { return strconv.FormatInt(n, 10) }
func queueAllRemoteWork(ctx context.Context, tx *sql.Tx, root string, generation, seq int64) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO remote_replan_all(root_id,generation,after_entry,remote_seq) VALUES(?,?,'',?) ON CONFLICT(root_id) DO UPDATE SET generation=excluded.generation,after_entry='',remote_seq=MAX(remote_seq,excluded.remote_seq)", root, generation, seq)
	return err
}

// ImportFeed consumes actual bounded raw bytes. It atomically persists R,
// namespace, derived work and the opaque cursor. It remains a candidate adapter;
// no signed cursor or server fence is fabricated from a sequence integer.
func (r *RemoteImport) ImportFeed(ctx context.Context, w RemoteWitness, raw []byte) (RemoteCandidate, error) {
	return r.importFeed(ctx, w, raw, nil)
}

// The explicit private continuity path cannot make an unfinished recovery
// visible to old readers. Public ImportFeed still requires an ordinary valid R.
func (r *RemoteImport) importFeed(ctx context.Context, w RemoteWitness, raw []byte, checkpoint *HTTPRebootstrapCheckpoint) (RemoteCandidate, error) {
	var result RemoteCandidate
	feed, err := syncproto.ReadFeed(raw, w.Binding, remoteDecimal(w.Position))
	if err != nil {
		return result, err
	}
	if feed.HasMore && feed.NextCursor == w.Cursor {
		return result, ErrIdentityConflict
	}
	err = r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		c, err := readCandidate(ctx, tx, w.RootID)
		if err != nil {
			return err
		}
		if c.RemoteWitness != w {
			if c.Valid && c.Binding == w.Binding && c.TrustGeneration == w.TrustGeneration && c.Generation == w.Generation && c.LastFeedHash == hashBytes(raw) && c.LastFeedCursor == w.Cursor && c.LastFeedFrom == w.Position {
				result = c
				return nil
			}
			return ErrStaleGeneration
		}
		root, err := readRoot(ctx, tx, w.RootID)
		if err != nil {
			return err
		}
		qualifiedContinuation := checkpoint != nil && c.HTTPRebootstrap != nil && *c.HTTPRebootstrap == *checkpoint && checkpoint.Phase == httpBootstrapAwaitFeed && validHTTPCheckpoint(c, checkpoint.TransportPin)
		if !c.Valid && !qualifiedContinuation || root.TrustGeneration != w.TrustGeneration || root.ActiveRemoteGeneration != w.Generation {
			return ErrStaleGeneration
		}
		if c.Revision == math.MaxInt64 {
			return ErrStaleGeneration
		}
		for _, item := range feed.Items {
			seq, _ := syncproto.Integer64(item.Seq)
			e := remoteFromDescriptor(w.RootID, w.Generation, seq, w.Binding, item.Descriptor, item.OperationID)
			prior, readErr := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", w.RootID, w.Generation, e.NodeID)
			if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
				return readErr
			}
			var schema int
			if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&schema); err != nil {
				return err
			}
			if schema == daemonSchemaVersion {
				if _, err = tx.ExecContext(ctx, "DELETE FROM parent_cache WHERE root_id=? AND (node_id=? OR destination=? OR destination=? OR destination=lower(?) OR destination=lower(?))", w.RootID, e.NodeID, e.ParentID+"/"+e.Name, prior.ParentID+"/"+prior.Name, e.ParentID+"/"+e.Name, prior.ParentID+"/"+prior.Name); err != nil {
					return err
				}
			}
			if item.Kind == "tombstone" {
				// Full pre-state is required; a missing record/metadata404 is not
				// authoritative absence. Only metadata version changes in the event.
				if readErr != nil || prior.Presence != "PRESENT" || prior.RemoteBinding == nil || *prior.RemoteBinding != w.Binding || prior.Version != item.BeforeVersion {
					return ErrIdentityConflict
				}
				before := item.Descriptor
				before.Version = item.BeforeVersion
				if !reflect.DeepEqual(descriptorFromRemote(prior), before) {
					return ErrIdentityConflict
				}
				e.Presence = "ABSENT"
			}
			if err = saveRemoteCandidateEntry(ctx, tx, e); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO remote_replan_nodes(root_id,node_id,generation,after_entry,remote_seq) VALUES(?,?,?,'',?) ON CONFLICT(root_id,node_id) DO UPDATE SET generation=excluded.generation,after_entry='',remote_seq=MAX(remote_seq,excluded.remote_seq)", w.RootID, e.NodeID, w.Generation, seq); err != nil {
				return err
			}
			// Folder namespace changes can retarget arbitrarily many children.
			// Persist bounded global replan debt rather than traversing them here.
			if e.Kind == "folder" || readErr == nil && prior.Kind == "folder" {
				if err = queueAllRemoteWork(ctx, tx, w.RootID, w.Generation, seq); err != nil {
					return err
				}
			}
		}
		if err = r.point("feed.before_cursor"); err != nil {
			return err
		}
		c.Position, _ = syncproto.Integer64(feed.ToInclusive)
		c.Cursor = feed.NextCursor
		c.Revision++
		c.LastFeedHash = hashBytes(raw)
		c.LastFeedCursor = w.Cursor
		c.LastFeedFrom = w.Position
		if err = saveCandidate(ctx, tx, c); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE journal_cursors SET epoch=?,position=?,valid=0 WHERE root_id=? AND stream='remote'", c.Binding.ServerEpoch, c.Position, c.RootID); err != nil {
			return err
		}
		result = c
		return nil
	})
	return result, err
}

// DrainRemoteWork visits at most limit indexed local rows in one transaction.
// Snapshot replacement/folder changes may require O(N) work over many calls;
// a scalar file feed uses the (root,node,entry) keyset instead of ACK history.
func (r *RemoteImport) DrainRemoteWork(ctx context.Context, root string, limit int) (int, error) {
	if limit < 1 || limit > MaxRemotePage {
		return 0, ErrSourceQuota
	}
	count := 0
	err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		var generation, seq int64
		var after, node string
		all := true
		err := tx.QueryRowContext(ctx, "SELECT generation,after_entry,remote_seq FROM remote_replan_all WHERE root_id=?", root).Scan(&generation, &after, &seq)
		if errors.Is(err, sql.ErrNoRows) {
			all = false
			err = tx.QueryRowContext(ctx, "SELECT node_id,generation,after_entry,remote_seq FROM remote_replan_nodes WHERE root_id=? ORDER BY node_id LIMIT 1", root).Scan(&node, &generation, &after, &seq)
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		actual, err := readRoot(ctx, tx, root)
		if err != nil {
			return err
		}
		if actual.ActiveRemoteGeneration != generation {
			if all {
				_, err = tx.ExecContext(ctx, "DELETE FROM remote_replan_all WHERE root_id=?", root)
			} else {
				_, err = tx.ExecContext(ctx, "DELETE FROM remote_replan_nodes WHERE root_id=? AND node_id=?", root, node)
			}
			return err
		}
		query := "SELECT entry_id,generation FROM local_entries WHERE root_id=? AND entry_id>? ORDER BY entry_id LIMIT ?"
		args := []any{root, after, limit}
		if !all {
			query = "SELECT b.entry_id,l.generation FROM baselines b JOIN local_entries l ON l.root_id=b.root_id AND l.entry_id=b.entry_id WHERE b.root_id=? AND b.node_id=? AND b.entry_id>? ORDER BY b.entry_id LIMIT ?"
			args = []any{root, node, after, limit}
		}
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		type match struct {
			id         string
			generation int64
		}
		matches := make([]match, 0, limit)
		for rows.Next() {
			var m match
			if err = rows.Scan(&m.id, &m.generation); err != nil {
				rows.Close()
				return err
			}
			matches = append(matches, m)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, m := range matches {
			if err = addDirty(ctx, tx, root, m.id, m.generation, seq, "remote"); err != nil {
				return err
			}
			after = m.id
			count++
		}
		if all {
			if count < limit {
				_, err = tx.ExecContext(ctx, "DELETE FROM remote_replan_all WHERE root_id=?", root)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE remote_replan_all SET after_entry=? WHERE root_id=?", after, root)
			}
		} else {
			if count < limit {
				_, err = tx.ExecContext(ctx, "DELETE FROM remote_replan_nodes WHERE root_id=? AND node_id=?", root, node)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE remote_replan_nodes SET after_entry=? WHERE root_id=? AND node_id=?", after, root, node)
			}
		}
		return err
	})
	return count, err
}
