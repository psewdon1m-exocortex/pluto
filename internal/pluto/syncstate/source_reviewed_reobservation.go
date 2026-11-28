package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
)

// MatchesPendingIncarnation permits only a mount-ID change within the same
// already observed file/link/boot incarnation. It does not accept a reboot,
// replacement file, changed link or unknown mount on behalf of the caller.
func (o SourceIncarnationObservation) MatchesPendingIncarnation(pending SourceObject) bool {
	return o.object == pending || mountOnlyReobservation(pending, o.object)
}

// ReobservePendingIncarnation is for an explicit reviewed offline operator.
// A later operator container has a different mount ID from the stopped daemon
// that recorded UNKNOWN. Refresh only that exact pending local incarnation,
// preserving UNKNOWN and an additional observation gap. Ordinary startup does
// not call this method. AcceptSourceIncarnation and a full scan remain separate.
func (s *Sources) ReobservePendingIncarnation(ctx context.Context, w SourceWitness, sourceID string, incarnation int64, pending SourceObject, observed SourceIncarnationObservation) (SourceWitness, error) {
	next := w
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		set, err := s.checkWitness(ctx, tx, w)
		if err != nil {
			return err
		}
		b, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1", w.SetID, sourceID)
		if err != nil {
			return err
		}
		if b.IncarnationStatus != "UNKNOWN" || b.Incarnation != incarnation || b.PendingObject != pending || b.PhysicalPath != observed.physical || observed.physical == "" {
			return ErrStaleGeneration
		}
		if !observed.MatchesPendingIncarnation(pending) {
			return ErrSourceIncomplete
		}
		if b.PendingObject == observed.object {
			return nil
		}
		if set.GapGeneration == math.MaxInt64 {
			return ErrSourceQuota
		}
		b.PendingObject = observed.object
		raw, err := json.Marshal(b)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE source_bindings SET descriptor_json=? WHERE set_id=? AND source_id=?", string(raw), w.SetID, sourceID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE source_sets SET gap_generation=gap_generation+1 WHERE set_id=?", w.SetID); err != nil {
			return err
		}
		next.GapGeneration++
		reason := "reviewed pending incarnation mount re-observation old=" + fingerprint(pending) + " new=" + fingerprint(observed.object)
		_, err = tx.ExecContext(ctx, "INSERT INTO source_gaps(set_id,generation,reason,owner_id) VALUES(?,?,?,?)", w.SetID, next.GapGeneration, reason, w.OwnerID)
		return err
	})
	if err != nil {
		return w, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owners[w.SetID] != w {
		return w, ErrStaleGeneration
	}
	if _, err = checkSourceWitness(ctx, s.store.db, next); err != nil {
		return w, err
	}
	s.owners[w.SetID] = next
	return next, nil
}
