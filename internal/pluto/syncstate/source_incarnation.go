package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// SourceIncarnationObservation has a private origin; arbitrary caller structs
// cannot fabricate an observed mount/boot/source binding. It is local evidence.
type SourceIncarnationObservation struct {
	physical string
	object   SourceObject
}

func (o SourceIncarnationObservation) Object() SourceObject { return o.object }
func ObserveSourceIncarnation(filename string) (SourceIncarnationObservation, error) {
	first, err := os.Stat(filename)
	if err != nil {
		return SourceIncarnationObservation{}, err
	}
	if !first.Mode().IsRegular() && !first.IsDir() {
		return SourceIncarnationObservation{}, ErrIdentityConflict
	}
	link, err := linkGuard(filename)
	if err != nil {
		return SourceIncarnationObservation{}, err
	}
	object := SourceObject{FileIdentity: statIdentity(first), LinkGuard: link}
	boot, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return SourceIncarnationObservation{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(boot, 65))
	boot.Close()
	if err != nil || len(raw) > 64 {
		return SourceIncarnationObservation{}, ErrIdentityConflict
	}
	object.BootIdentity = strings.TrimSpace(string(raw))
	if !validID(object.BootIdentity) {
		return SourceIncarnationObservation{}, ErrIdentityConflict
	}
	var stat unix.Statx_t
	if err = unix.Statx(unix.AT_FDCWD, filename, 0, unix.STATX_MNT_ID, &stat); err == nil && stat.Mask&unix.STATX_MNT_ID != 0 {
		object.MountKnown = true
		object.MountID = stringID(stat.Mnt_id)
	}
	second, err := os.Stat(filename)
	afterLink, linkErr := linkGuard(filename)
	if err != nil || linkErr != nil || !os.SameFile(first, second) || link != afterLink {
		return SourceIncarnationObservation{}, ErrCaptureChanged
	}
	return SourceIncarnationObservation{filename, object}, nil
}
func stringID(value uint64) string { // Avoid an int64 cast on a kernel identifier.
	if value == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for value > 0 {
		i--
		b[i] = byte('0' + value%10)
		value /= 10
	}
	return string(b[i:])
}

// RecordSourceIncarnation records first observed local identity. A replacement
// persists UNKNOWN+gap, blocks stale scans, and never resets B/remote trust.
func (s *Sources) RecordSourceIncarnation(ctx context.Context, w SourceWitness, sourceID string, observed SourceIncarnationObservation) (SourceWitness, error) {
	next := w
	changed := false
	if observed.physical == "" || observed.object.FileIdentity == "" || observed.object.BootIdentity == "" {
		return w, ErrIdentityConflict
	}
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		b, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1", w.SetID, sourceID)
		if err != nil {
			return err
		}
		if b.PhysicalPath != observed.physical {
			return ErrIdentityConflict
		}
		if b.IncarnationStatus == "UNKNOWN" {
			return ErrSourceIncomplete
		}
		if b.Incarnation == 0 {
			b.Object = observed.object
			b.Incarnation = 1
			b.IncarnationStatus = "LOCAL_OBSERVED"
		} else if b.Object != observed.object {
			b.IncarnationStatus = "UNKNOWN"
			b.PendingObject = observed.object
			changed = true
			if _, err = tx.ExecContext(ctx, "UPDATE source_sets SET gap_generation=gap_generation+1 WHERE set_id=?", w.SetID); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE source_scans SET status='INCOMPLETE',reason='source incarnation changed' WHERE set_id=? AND status='DISCOVERING'", w.SetID); err != nil {
				return err
			}
			set, e := readSourceSet(ctx, tx, w.SetID)
			if e != nil {
				return e
			}
			next = witness(set)
			s.owners[w.SetID] = next
			if _, err = tx.ExecContext(ctx, "INSERT INTO source_gaps(set_id,generation,reason,owner_id) VALUES(?,?,'source incarnation changed',?)", w.SetID, next.GapGeneration, w.OwnerID); err != nil {
				return err
			}
		} else {
			return nil
		}
		raw, _ := json.Marshal(b)
		_, err = tx.ExecContext(ctx, "UPDATE source_bindings SET descriptor_json=? WHERE set_id=? AND source_id=?", string(raw), w.SetID, sourceID)
		return err
	})
	if err != nil {
		return w, err
	}
	if changed {
		return next, ErrSourceIncomplete
	}
	return next, nil
}

// AcceptSourceIncarnation is an explicit local reconciliation CAS. It cannot
// establish an agreed baseline, clear remote/local work, or qualify root history.
func (s *Sources) AcceptSourceIncarnation(ctx context.Context, w SourceWitness, sourceID string, expected int64, observed SourceIncarnationObservation) error {
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		b, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1", w.SetID, sourceID)
		if err != nil {
			return err
		}
		if b.IncarnationStatus != "UNKNOWN" || b.Incarnation != expected || observed.physical != b.PhysicalPath || observed.object != b.PendingObject || observed.physical == "" {
			return ErrStaleGeneration
		}
		b.Incarnation++
		b.Object = observed.object
		b.PendingObject = SourceObject{}
		b.IncarnationStatus = "LOCAL_OBSERVED"
		raw, _ := json.Marshal(b)
		_, err = tx.ExecContext(ctx, "UPDATE source_bindings SET descriptor_json=? WHERE set_id=? AND source_id=?", string(raw), w.SetID, sourceID)
		return err
	})
}
