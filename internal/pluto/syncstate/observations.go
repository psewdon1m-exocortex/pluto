package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

func readJSON[T any](ctx context.Context, q queryer, statement string, args ...any) (T, error) {
	var value T
	var raw string
	err := q.QueryRowContext(ctx, statement, args...).Scan(&raw)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &value)
	}
	return value, err
}

func readCursor(ctx context.Context, q queryer, root, stream string) (Cursor, error) {
	value := Cursor{RootID: root, Stream: stream}
	err := q.QueryRowContext(ctx, "SELECT epoch,position,valid FROM journal_cursors WHERE root_id=? AND stream=?", root, stream).Scan(&value.Epoch, &value.Position, &value.Valid)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return value, err
}

func (s *Store) Cursor(ctx context.Context, root, stream string) (Cursor, error) {
	return readCursor(ctx, s.db, root, stream)
}

func checkCursorTransition(before, next Cursor, stream string) error {
	if !validID(next.RootID) || !validID(next.Epoch) || before.RootID != next.RootID || before.Stream != stream || next.Stream != stream || before.Position < 0 || next.Position < 0 {
		return errors.New("cursor identity/bounds invalid")
	}
	if before.Epoch != "" && before.Epoch != next.Epoch && before.Valid {
		return errors.New("journal changed without recording an observation gap")
	}
	if before.Epoch == next.Epoch && next.Position < before.Position {
		return errors.New("cursor cannot move backwards")
	}
	return nil
}

func saveCursor(ctx context.Context, tx *sql.Tx, before, next Cursor) error {
	current, err := readCursor(ctx, tx, next.RootID, next.Stream)
	if err != nil {
		return err
	}
	if current != before {
		return ErrStaleGeneration
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO journal_cursors(root_id,stream,epoch,position,valid) VALUES(?,?,?,?,?) ON CONFLICT(root_id,stream) DO UPDATE SET epoch=excluded.epoch,position=excluded.position,valid=excluded.valid`, next.RootID, next.Stream, next.Epoch, next.Position, next.Valid)
	return err
}

func addDirty(ctx context.Context, tx *sql.Tx, root, entry string, generation, seq int64, reason string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO dirty_entries(root_id,entry_id,observed_generation,remote_seq,reasons,first_dirty_ms) VALUES(?,?,?,?,?,?) ON CONFLICT(root_id,entry_id) DO UPDATE SET observed_generation=MAX(observed_generation,excluded.observed_generation),remote_seq=MAX(remote_seq,excluded.remote_seq),reasons=CASE WHEN reasons=excluded.reasons OR reasons='local,remote' THEN reasons ELSE 'local,remote' END`, root, entry, generation, seq, reason, time.Now().UTC().UnixMilli())
	return err
}

// CaptureLocal persists the cursor and all resulting observations/work together.
// Duplicate/change signals may increase generation; metadata equality never
// grants permission to skip content checks or to infer a deletion operation.
func (s *Store) CaptureLocal(ctx context.Context, trustGeneration int64, before, next Cursor, entries []Observation) error {
	if err := checkBatch(len(entries)); err != nil {
		return err
	}
	if err := checkCursorTransition(before, next, "local"); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := checkObservation(entry); err != nil {
			return err
		}
		if entry.RootID != next.RootID || entry.NameKey != entry.Name {
			return errors.New("legacy namespace requires the original exact name/root")
		}
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		root, err := readRoot(ctx, tx, next.RootID)
		if err != nil {
			return err
		}
		if root.TrustGeneration != trustGeneration {
			return ErrStaleGeneration
		}
		statement, err := tx.PrepareContext(ctx, `INSERT INTO local_entries(root_id,entry_id,parent_id,name_key,generation,descriptor_json) VALUES(?,?,?,?,?,?) ON CONFLICT(root_id,entry_id) DO UPDATE SET parent_id=excluded.parent_id,name_key=excluded.name_key,generation=excluded.generation,descriptor_json=excluded.descriptor_json WHERE generation=?`)
		if err != nil {
			return err
		}
		defer statement.Close()
		for _, entry := range entries {
			current, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", entry.RootID, entry.EntryID)
			if errors.Is(err, sql.ErrNoRows) {
				if entry.ExpectedGeneration != 0 {
					return ErrStaleGeneration
				}
			} else if err != nil {
				return err
			} else if current.Generation != entry.ExpectedGeneration {
				return ErrStaleGeneration
			}
			var parent any
			if entry.ParentID != "" {
				parentEntry, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", entry.RootID, entry.ParentID)
				if err != nil || parentEntry.Kind != "folder" || parentEntry.Presence != "PRESENT" {
					return errors.New("local parent is not a known folder in this root")
				}
				var cycle int
				if err = tx.QueryRowContext(ctx, `WITH RECURSIVE ancestors(id) AS (SELECT ? UNION SELECT l.parent_id FROM local_entries l JOIN ancestors a ON l.entry_id=a.id WHERE l.root_id=? AND l.parent_id IS NOT NULL) SELECT COUNT(*) FROM ancestors WHERE id=?`, entry.ParentID, entry.RootID, entry.EntryID).Scan(&cycle); err != nil {
					return err
				}
				if cycle != 0 {
					return errors.New("local directory parent cycle rejected")
				}
				parent = entry.ParentID
			}
			entry.Generation = entry.ExpectedGeneration + 1
			raw, _ := json.Marshal(entry)
			result, err := statement.ExecContext(ctx, entry.RootID, entry.EntryID, parent, entry.NameKey, entry.Generation, string(raw), entry.ExpectedGeneration)
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrStaleGeneration
			}
			if err = addDirty(ctx, tx, entry.RootID, entry.EntryID, entry.Generation, 0, "local"); err != nil {
				return err
			}
		}
		return saveCursor(ctx, tx, before, next)
	})
}

// ApplyRemote stores R and remote dirty signals without changing B. The adapter
// must provide a contiguous committed feed range; this store does not manufacture
// that server capability from HTTP metadata responses.
func (s *Store) ApplyRemote(ctx context.Context, trustGeneration int64, before, next Cursor, entries []RemoteEntry) error {
	if err := checkBatch(len(entries)); err != nil {
		return err
	}
	if err := checkCursorTransition(before, next, "remote"); err != nil {
		return err
	}
	if before.Epoch != "" && before.Epoch != next.Epoch {
		return errors.New("remote epoch change requires shadow reconciliation")
	}
	if next.Position-before.Position != int64(len(entries)) {
		return errors.New("remote feed range is not contiguous")
	}
	for i, entry := range entries {
		if err := checkRemote(entry); err != nil {
			return err
		}
		if entry.RootID != next.RootID || entry.Epoch != next.Epoch || entry.LastSeq != before.Position+int64(i)+1 {
			return errors.New("remote feed entries are not a committed ordered prefix")
		}
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		root, err := readRoot(ctx, tx, next.RootID)
		if err != nil {
			return err
		}
		if root.TrustGeneration != trustGeneration {
			return ErrStaleGeneration
		}
		for _, entry := range entries {
			if entry.Generation != root.ActiveRemoteGeneration {
				return ErrStaleGeneration
			}
			raw, _ := json.Marshal(entry)
			if _, err = tx.ExecContext(ctx, `INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES(?,?,?,?,?) ON CONFLICT(root_id,generation,node_id) DO UPDATE SET last_seq=excluded.last_seq,descriptor_json=excluded.descriptor_json WHERE excluded.last_seq>last_seq`, entry.RootID, entry.Generation, entry.NodeID, entry.LastSeq, string(raw)); err != nil {
				return err
			}
			rows, err := tx.QueryContext(ctx, `SELECT b.entry_id,l.generation FROM baselines b JOIN local_entries l ON l.root_id=b.root_id AND l.entry_id=b.entry_id WHERE b.root_id=? AND b.node_id=?`, entry.RootID, entry.NodeID)
			if err != nil {
				return err
			}
			var matches []struct {
				id  string
				gen int64
			}
			for rows.Next() {
				var match struct {
					id  string
					gen int64
				}
				if err = rows.Scan(&match.id, &match.gen); err != nil {
					rows.Close()
					return err
				}
				matches = append(matches, match)
				if len(matches) > MaxBatch {
					rows.Close()
					return errors.New("remote node maps to too many local entries")
				}
			}
			rowErr := rows.Err()
			rows.Close()
			if rowErr != nil {
				return rowErr
			}
			for _, match := range matches {
				if err = addDirty(ctx, tx, entry.RootID, match.id, match.gen, entry.LastSeq, "remote"); err != nil {
					return err
				}
			}
		}
		return saveCursor(ctx, tx, before, next)
	})
}

func (s *Store) Entry(ctx context.Context, root, entry string) (EntryState, error) {
	var state EntryState
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		local, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", root, entry)
		if err != nil {
			return err
		}
		state.Local = local
		base, err := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", root, entry)
		if err == nil {
			state.Base = &base
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if state.Base != nil {
			remote, err := readJSON[RemoteEntry](ctx, tx, `SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=(SELECT active_remote_generation FROM roots WHERE root_id=?) AND node_id=?`, root, root, base.NodeID)
			if err == nil {
				state.Remote = &remote
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		var dirty Dirty
		err = tx.QueryRowContext(ctx, "SELECT root_id,entry_id,observed_generation,remote_seq,reasons FROM dirty_entries WHERE root_id=? AND entry_id=?", root, entry).Scan(&dirty.RootID, &dirty.EntryID, &dirty.ObservedGeneration, &dirty.RemoteSeq, &dirty.Reasons)
		if err == nil {
			state.Dirty = &dirty
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return nil
	})
	return state, err
}

func (s *Store) DirtyPage(ctx context.Context, root, after string, limit int) ([]Dirty, error) {
	if limit < 1 || limit > MaxBatch {
		return nil, errors.New("dirty page limit invalid")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT root_id,entry_id,observed_generation,remote_seq,reasons FROM dirty_entries WHERE root_id=? AND entry_id>? ORDER BY entry_id LIMIT ?", root, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]Dirty, 0, limit)
	for rows.Next() {
		var value Dirty
		if err = rows.Scan(&value.RootID, &value.EntryID, &value.ObservedGeneration, &value.RemoteSeq, &value.Reasons); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
