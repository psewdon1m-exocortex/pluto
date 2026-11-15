package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

func readSourceSet(ctx context.Context, q queryer, id string) (SourceSet, error) {
	var set SourceSet
	var root sql.NullString
	err := q.QueryRowContext(ctx, "SELECT set_id,config_digest,revision,owner_id,owner_sequence,gap_generation,attached_root_id FROM source_sets WHERE set_id=?", id).Scan(&set.ID, &set.ConfigDigest, &set.Revision, &set.OwnerID, &set.OwnerSequence, &set.GapGeneration, &root)
	set.AttachedRootID = root.String
	return set, err
}
func (s *Sources) Set(ctx context.Context, id string) (SourceSet, error) {
	return readSourceSet(ctx, s.store.db, id)
}
func witness(set SourceSet) SourceWitness {
	return SourceWitness{set.ID, set.OwnerID, set.Revision, set.GapGeneration, set.OwnerSequence}
}
func checkSourceWitness(ctx context.Context, q queryer, w SourceWitness) (SourceSet, error) {
	set, err := readSourceSet(ctx, q, w.SetID)
	if err != nil {
		return set, err
	}
	if w.OwnerID == "" || w != witness(set) {
		return set, ErrStaleGeneration
	}
	return set, nil
}
func (s *Sources) checkWitness(ctx context.Context, q queryer, w SourceWitness) (SourceSet, error) {
	if s.owners[w.SetID] != w {
		return SourceSet{}, ErrStaleGeneration
	}
	return checkSourceWitness(ctx, q, w)
}

// BindSourceSet stores only an explicit projection of the caller's authoritative
// config. It reads/writes no config/token/status file. A changed projection needs
// a caller-supplied CAS revision; uncertainty cannot silently select a winner.
func (s *Sources) BindSourceSet(ctx context.Context, id, configDigest string, expected int64, specs []SourceSpec) (SourceSet, error) {
	if !validID(id) || !validHash(configDigest) || expected < 0 || expected >= int64(^uint64(0)>>1) || len(specs) < 1 || len(specs) > MaxSources {
		return SourceSet{}, ErrIdentityConflict
	}
	bindings := make([]SourceBinding, 0, len(specs))
	seen := map[string]bool{}
	bytes := 0
	for _, spec := range specs {
		if !validID(spec.ID) || seen[spec.ID] || !validSourcePath(spec.SelectedPath) || !validDestination(sourceDestination(spec.SelectedPath)) {
			return SourceSet{}, ErrIdentityConflict
		}
		seen[spec.ID] = true
		physical := spec.SelectedPath
		if !filepath.IsAbs(physical) {
			if !filepath.IsAbs(spec.WorkingDirectory) || !validSourcePath(spec.WorkingDirectory) {
				return SourceSet{}, ErrIdentityConflict
			}
			physical = filepath.Join(spec.WorkingDirectory, physical)
		}
		if !validSourcePath(physical) {
			return SourceSet{}, ErrIdentityConflict
		}
		stateRelative, relErr := filepath.Rel(filepath.Clean(physical), filepath.Dir(s.store.filename))
		if relErr != nil || stateRelative == "." || (!strings.HasPrefix(stateRelative, ".."+string(filepath.Separator)) && stateRelative != "..") {
			return SourceSet{}, errors.New("selected source contains the local state; explicit operator policy required")
		}
		binding := SourceBinding{SourceSpec: spec, Destination: sourceDestination(spec.SelectedPath), PhysicalPath: filepath.Clean(physical), Revision: expected + 1, Active: true}
		raw, _ := json.Marshal(binding)
		bytes += len(raw)
		bindings = append(bindings, binding)
	}
	if bytes > MaxSourcePageBytes {
		return SourceSet{}, ErrSourceQuota
	}
	var out SourceSet
	err := s.change(ctx, 16<<20, func(tx *sql.Tx) error {
		old, err := readSourceSet(ctx, tx, id)
		if errors.Is(err, sql.ErrNoRows) {
			if expected != 0 {
				return ErrStaleGeneration
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO source_sets(set_id,config_digest,revision) VALUES(?,?,1)", id, configDigest); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			if old.Revision != expected {
				return ErrStaleGeneration
			}
			// A stable set identity and previous attachment survive changed membership.
			if _, err = tx.ExecContext(ctx, "UPDATE source_sets SET config_digest=?,revision=revision+1,gap_generation=gap_generation+1 WHERE set_id=?", configDigest, id); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE source_scans SET status='INCOMPLETE',reason='source-set revision changed' WHERE set_id=? AND status='DISCOVERING'", id); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE source_bindings SET active=0 WHERE set_id=? AND active=1", id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM source_prefix_work WHERE set_id=?", id); err != nil {
			return err
		}
		for _, b := range bindings {
			prior, readErr := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=?", id, b.ID)
			if readErr == nil && (prior.SelectedPath != b.SelectedPath || prior.WorkingDirectory != b.WorkingDirectory) {
				return ErrIdentityConflict
			}
			if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
				return readErr
			}
			if readErr == nil {
				b.Object = prior.Object
				b.PendingObject = prior.PendingObject
				b.Incarnation = prior.Incarnation
				b.IncarnationStatus = prior.IncarnationStatus
			}
			raw, _ := json.Marshal(b)
			if _, err = tx.ExecContext(ctx, "INSERT INTO source_bindings(set_id,source_id,revision,active,descriptor_json) VALUES(?,?,?,1,?) ON CONFLICT(set_id,source_id) DO UPDATE SET revision=excluded.revision,active=1,descriptor_json=excluded.descriptor_json", id, b.ID, b.Revision, string(raw)); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO source_prefix_work(set_id,source_id,revision) VALUES(?,?,?)", id, b.ID, b.Revision); err != nil {
				return err
			}
		}
		out, err = readSourceSet(ctx, tx, id)
		return err
	})
	return out, err
}
func (s *Sources) AttachSourceSet(ctx context.Context, id string, expected int64, rootID string) error {
	if !validID(rootID) {
		return ErrIdentityConflict
	}
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		set, err := readSourceSet(ctx, tx, id)
		if err != nil {
			return err
		}
		if set.Revision != expected {
			return ErrStaleGeneration
		}
		if set.AttachedRootID != "" && set.AttachedRootID != rootID {
			return ErrIdentityConflict
		}
		root, err := readRoot(ctx, tx, rootID)
		if err != nil {
			return err
		}
		if root.SourceIdentity != id || root.EngineReady {
			return ErrIdentityConflict
		}
		_, err = tx.ExecContext(ctx, "UPDATE source_sets SET attached_root_id=? WHERE set_id=?", rootID, id)
		return err
	})
}
func (s *Sources) Binding(ctx context.Context, set, source string) (SourceBinding, error) {
	b, err := readJSON[SourceBinding](ctx, s.store.db, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=?", set, source)
	if err == nil {
		var active bool
		err = s.store.db.QueryRowContext(ctx, "SELECT active FROM source_bindings WHERE set_id=? AND source_id=?", set, source).Scan(&active)
		b.Active = active
	}
	return b, err
}

// BeginSourceOwner always records a gap. Persisted admitted pages cannot replay a
// lost kernel instance; this changes local verification only, never remote trust/B.
func (s *Sources) BeginSourceOwner(ctx context.Context, id string, expected int64, owner string) (SourceWitness, error) {
	if !validID(owner) {
		return SourceWitness{}, ErrIdentityConflict
	}
	var w SourceWitness
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		set, err := readSourceSet(ctx, tx, id)
		if err != nil {
			return err
		}
		if set.Revision != expected || owner == set.OwnerID {
			return ErrStaleGeneration
		}
		if _, exists := s.owners[id]; !exists && len(s.owners) >= MaxSources {
			return ErrSourceQuota
		}
		if _, err = tx.ExecContext(ctx, "UPDATE source_sets SET owner_id=?,owner_sequence=owner_sequence+1,gap_generation=gap_generation+1 WHERE set_id=?", owner, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE source_scans SET status='INCOMPLETE',reason='observer owner changed' WHERE set_id=? AND status='DISCOVERING'", id); err != nil {
			return err
		}
		set, err = readSourceSet(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO source_gaps(set_id,generation,reason,owner_id) VALUES(?,?,'owner restart or uncommitted read gap',?)", id, set.GapGeneration, owner); err != nil {
			return err
		}
		w = witness(set)
		s.owners[id] = w
		return nil
	})
	return w, err
}
func (s *Sources) RecordSourceGap(ctx context.Context, w SourceWitness, reason string) (SourceWitness, error) {
	if reason == "" || len(reason) > 512 {
		return SourceWitness{}, ErrIdentityConflict
	}
	var next SourceWitness
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE source_sets SET gap_generation=gap_generation+1 WHERE set_id=?", w.SetID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE source_scans SET status='INCOMPLETE',reason=? WHERE set_id=? AND status='DISCOVERING'", reason, w.SetID); err != nil {
			return err
		}
		set, err := readSourceSet(ctx, tx, w.SetID)
		if err != nil {
			return err
		}
		next = witness(set)
		s.owners[w.SetID] = next
		_, err = tx.ExecContext(ctx, "INSERT INTO source_gaps(set_id,generation,reason,owner_id) VALUES(?,?,?,?)", w.SetID, next.GapGeneration, reason, w.OwnerID)
		return err
	})
	return next, err
}
func (s *Sources) SourceEntry(ctx context.Context, set, key string) (SourceEntry, error) {
	return readSourceEntry(ctx, s.store.db, set, key)
}
func readSourceEntry(ctx context.Context, q queryer, set, key string) (SourceEntry, error) {
	var e SourceEntry
	var raw string
	var g, r int64
	var ambiguous bool
	err := q.QueryRowContext(ctx, "SELECT descriptor_json,generation,verification_request,ambiguous FROM source_entries WHERE set_id=? AND destination=?", set, key).Scan(&raw, &g, &r, &ambiguous)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &e)
		e.Generation = g
		e.VerificationRequest = r
		e.Ambiguous = ambiguous
	}
	return e, err
}

// PrepareSourcePrefixes drains one bounded source's virtual dependencies; binding
// 128 deep sources never expands all their ancestor paths in a single transaction.
// A prefix carries no filesystem observation or remote namespace authority.
func (s *Sources) PrepareSourcePrefixes(ctx context.Context, w SourceWitness, sourceID string) error {
	return s.change(ctx, 4<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		var revision int64
		err := tx.QueryRowContext(ctx, "SELECT revision FROM source_prefix_work WHERE set_id=? AND source_id=?", w.SetID, sourceID).Scan(&revision)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if revision != w.Revision {
			return ErrStaleGeneration
		}
		b, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1 AND revision=?", w.SetID, sourceID, w.Revision)
		if err != nil {
			return err
		}
		parts := strings.Split(b.Destination, "/")
		if len(parts) > MaxSourceDepth {
			return ErrSourceQuota
		}
		for i := 1; i < len(parts); i++ {
			if _, err = tx.ExecContext(ctx, "INSERT INTO source_prefixes(set_id,source_id,destination,revision) VALUES(?,?,?,?) ON CONFLICT(set_id,source_id,destination) DO UPDATE SET revision=excluded.revision", w.SetID, sourceID, strings.Join(parts[:i], "/"), revision); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM source_prefix_work WHERE set_id=? AND source_id=?", w.SetID, sourceID)
		return err
	})
}
