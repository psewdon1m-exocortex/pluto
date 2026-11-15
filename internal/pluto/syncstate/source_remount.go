package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
)

// RequalifyOwnerMounts is an explicit opt-in pre-scan observation step. A
// mount-only change establishes a new local incarnation and keeps the gap;
// it does not establish content continuity, a local cut or current B. The
// caller must subsequently perform a complete guarded content observation.
// Legacy Copy/Serve do not call this method.
func (s *Sources) RequalifyOwnerMounts(ctx context.Context, w SourceWitness, sourceIDs []string) (SourceWitness, error) {
	return s.requalifyOwnerMounts(ctx, w, sourceIDs, ObserveSourceIncarnation)
}

func (s *Sources) requalifyOwnerMounts(ctx context.Context, w SourceWitness, sourceIDs []string, observe func(string) (SourceIncarnationObservation, error)) (SourceWitness, error) {
	if len(sourceIDs) < 1 || len(sourceIDs) > MaxSources || observe == nil {
		return w, ErrSourceQuota
	}
	// Validate the whole authoritative configured set before observation or a
	// durable transition. Records are bounded, never all source-file entries.
	bindings := make([]SourceBinding, 0, len(sourceIDs))
	seen := make(map[string]bool, len(sourceIDs))
	s.mu.Lock()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err == nil {
		_, err = s.checkWitness(ctx, tx, w)
		var count int
		if err == nil {
			err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM source_bindings WHERE set_id=? AND active=1", w.SetID).Scan(&count)
			if err == nil && count != len(sourceIDs) {
				err = ErrIdentityConflict
			}
		}
		bytes := 0
		for _, id := range sourceIDs {
			if err != nil {
				break
			}
			if !validID(id) || seen[id] {
				err = ErrIdentityConflict
				break
			}
			seen[id] = true
			var size int
			err = tx.QueryRowContext(ctx, "SELECT length(CAST(descriptor_json AS BLOB)) FROM source_bindings WHERE set_id=? AND source_id=? AND active=1 AND revision=?", w.SetID, id, w.Revision).Scan(&size)
			bytes += size
			if err == nil && (size < 1 || bytes > MaxSourcePageBytes) {
				err = ErrSourceQuota
			}
			if err != nil {
				break
			}
			b, e := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1 AND revision=?", w.SetID, id, w.Revision)
			err = e
			if err == nil && (b.ID != id || b.Revision != w.Revision || !b.Active || !validSourcePath(b.PhysicalPath)) {
				err = ErrIdentityConflict
			}
			bindings = append(bindings, b)
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback()
		}
	}
	s.mu.Unlock()
	if err != nil {
		return w, err
	}
	for _, b := range bindings {
		if err = ctx.Err(); err != nil {
			return w, err
		}
		first, e := observe(b.PhysicalPath)
		if e != nil {
			return w, e
		}
		if err = ctx.Err(); err != nil {
			return w, err
		}
		second, e := observe(b.PhysicalPath)
		if e != nil {
			return w, e
		}
		if first != second || first.physical != b.PhysicalPath {
			return w, ErrCaptureChanged
		}
		// RecordSourceIncarnation persists UNKNOWN+gap before any acceptance.
		// Already-UNKNOWN state remains unchanged until the exact pending CAS.
		w, e = s.RecordSourceIncarnation(ctx, w, b.ID, second)
		if e == nil {
			continue
		}
		if !errors.Is(e, ErrSourceIncomplete) || !mountOnlyReobservation(b.Object, second.object) {
			return w, e
		}
		if err = ctx.Err(); err != nil {
			return w, err
		}
		if b.IncarnationStatus == "UNKNOWN" && b.PendingObject != second.object {
			// A second process/container restart can recreate the mount again.
			// Persist another explicit gap before accepting the new pending
			// object; a replacement/boot/link change cannot take this path.
			w, err = s.replacePendingOwnerMount(ctx, w, b, second)
			if err != nil {
				return w, err
			}
		}
		// Source/owner/config/gap/incarnation/pending-observation checks remain
		// in the existing transaction. No intent, B or dirty row is rewritten.
		if err = s.AcceptSourceIncarnation(ctx, w, b.ID, b.Incarnation, second); err != nil {
			return w, err
		}
	}
	return w, nil
}

func mountOnlyReobservation(old, observed SourceObject) bool {
	return old.MountKnown && observed.MountKnown && old.MountID != "" && observed.MountID != "" && old.MountID != observed.MountID && old.FileIdentity != "" && old.FileIdentity == observed.FileIdentity && old.LinkGuard != "" && old.LinkGuard == observed.LinkGuard && old.BootIdentity != "" && old.BootIdentity == observed.BootIdentity
}

func (s *Sources) replacePendingOwnerMount(ctx context.Context, w SourceWitness, expected SourceBinding, observed SourceIncarnationObservation) (SourceWitness, error) {
	if expected.IncarnationStatus != "UNKNOWN" || observed.physical != expected.PhysicalPath || !mountOnlyReobservation(expected.Object, expected.PendingObject) || !mountOnlyReobservation(expected.PendingObject, observed.object) || !mountOnlyReobservation(expected.Object, observed.object) {
		return w, ErrSourceIncomplete
	}
	next := w
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		set, err := s.checkWitness(ctx, tx, w)
		if err != nil {
			return err
		}
		b, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND revision=? AND active=1", w.SetID, expected.ID, w.Revision)
		if err != nil {
			return err
		}
		if b != expected || set.GapGeneration == math.MaxInt64 {
			return ErrStaleGeneration
		}
		b.PendingObject = observed.object
		raw, _ := json.Marshal(b)
		if _, err = tx.ExecContext(ctx, "UPDATE source_bindings SET descriptor_json=? WHERE set_id=? AND source_id=? AND revision=? AND active=1", string(raw), w.SetID, b.ID, w.Revision); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE source_sets SET gap_generation=gap_generation+1 WHERE set_id=?", w.SetID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE source_scans SET status='INCOMPLETE',reason='pre-scan mount re-observation' WHERE set_id=? AND status='DISCOVERING'", w.SetID); err != nil {
			return err
		}
		next.GapGeneration++
		reason := "pre-scan mount re-observation old=" + fingerprint(expected.Object) + " pending=" + fingerprint(expected.PendingObject) + " new=" + fingerprint(observed.object)
		_, err = tx.ExecContext(ctx, "INSERT INTO source_gaps(set_id,generation,reason,owner_id) VALUES(?,?,?,?)", w.SetID, next.GapGeneration, reason, w.OwnerID)
		return err
	})
	if err != nil {
		return w, err
	}
	// Publish only the committed witness. A concurrently advanced owner cannot
	// be overwritten by this process-local ownership update.
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

func (s *Sources) sourceWitnessCurrent(ctx context.Context, w SourceWitness) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.checkWitness(ctx, s.store.db, w)
	return err == nil
}

// CapturedSourceGap is a bounded diagnostic at the end of an aborted scan. Its
// current witness is not adopted by that scan and grants no capture authority.
type CapturedSourceGap struct {
	Expected         SourceWitness
	Current          *SourceWitness
	Reason           string
	ObservationError string `json:",omitempty"`
}

func (s *Sources) sourceGapDiagnostic(ctx context.Context, w SourceWitness) CapturedSourceGap {
	out := CapturedSourceGap{Expected: w}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		out.ObservationError = err.Error()
		return out
	}
	defer tx.Rollback()
	set, err := readSourceSet(ctx, tx, w.SetID)
	if err == nil {
		current := witness(set)
		out.Current = &current
		// Do not transport an unbounded stored reason before checking its bytes.
		var size int
		err = tx.QueryRowContext(ctx, "SELECT length(CAST(reason AS BLOB)) FROM source_gaps WHERE set_id=? AND generation=?", w.SetID, set.GapGeneration).Scan(&size)
		if errors.Is(err, sql.ErrNoRows) {
			err = nil // Owner/config fencing can change without a new gap row.
		} else if err == nil {
			if size < 0 || size > 512 {
				err = ErrSourceQuota
			} else {
				err = tx.QueryRowContext(ctx, "SELECT reason FROM source_gaps WHERE set_id=? AND generation=?", w.SetID, set.GapGeneration).Scan(&out.Reason)
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		out.Current = nil
		out.Reason = ""
		out.ObservationError = err.Error()
	}
	return out
}
