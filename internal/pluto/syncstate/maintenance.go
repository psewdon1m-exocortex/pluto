package syncstate

import (
	"context"
	"path/filepath"
)

func OpenReadOnly(ctx context.Context, directory string) (*Store, error) {
	filename := filepath.Join(directory, "sync-state.sqlite")
	if err := preflight(ctx, filename); err != nil {
		return nil, err
	}
	db, err := openDB(filename, true)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, filename: filename}, nil
}

type ProfileInspection struct {
	SchemaVersion                                             int `json:"schemaVersion"`
	Roots, PendingOperations, DirtyEntries, RetainedArtifacts int64
	CompatibleWriter                                          string           `json:"compatibleWriter"`
	RollbackAllowed                                           bool             `json:"rollbackAllowed"`
	RetryStates                                               map[string]int64 `json:"retryStates,omitempty"`
	RetainedStreams                                           int64            `json:"retainedStreams,omitempty"`
	BindingTransitions                                        map[string]int64 `json:"bindingTransitions,omitempty"`
	UnmatchedRebindings                                       int64            `json:"unmatchedRebindings,omitempty"`
}

func InspectProfile(ctx context.Context, directory string) (ProfileInspection, error) {
	var out ProfileInspection
	filename := filepath.Join(directory, "sync-state.sqlite")
	if err := preflight(ctx, filename); err != nil {
		return out, err
	}
	db, err := openDB(filename, true)
	if err != nil {
		return out, err
	}
	defer db.Close()
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&out.SchemaVersion); err != nil {
		return out, err
	}
	queries := []struct {
		sql   string
		value *int64
	}{{"SELECT COUNT(*) FROM roots", &out.Roots}, {"SELECT COUNT(*) FROM operations WHERE stage<>'CLIENT_ACKED'", &out.PendingOperations}, {"SELECT COUNT(*) FROM dirty_entries", &out.DirtyEntries}}
	for _, q := range queries {
		if err = db.QueryRowContext(ctx, q.sql).Scan(q.value); err != nil {
			return out, err
		}
	}
	out.CompatibleWriter = "pluto-indexed-v" + stringID(uint64(out.SchemaVersion))
	if out.SchemaVersion >= ArtifactSchemaVersion {
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM local_artifacts WHERE phase<>'GONE'").Scan(&out.RetainedArtifacts); err != nil {
			return out, err
		}
	}
	// Legacy binaries ignore indexed state; no automatic binary rollback is safe
	// once publication/receipts or pending originals exist.
	var operations int64
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations").Scan(&operations); err != nil {
		return out, err
	}
	out.RollbackAllowed = operations == 0 && out.SchemaVersion <= HTTPBindingSchemaVersion
	if out.SchemaVersion == daemonSchemaVersion {
		out.BindingTransitions = map[string]int64{}
		rows, e := db.QueryContext(ctx, "SELECT phase,COUNT(*),SUM(unmatched) FROM profile_rebinding GROUP BY phase LIMIT 4")
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var phase string
			var count, unmatched int64
			if e = rows.Scan(&phase, &count, &unmatched); e != nil {
				rows.Close()
				return out, e
			}
			out.BindingTransitions[phase] = count
			out.UnmatchedRebindings += unmatched
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		out.RetryStates = map[string]int64{}
		rows, e = db.QueryContext(ctx, "SELECT state,COUNT(*) FROM operation_retry GROUP BY state LIMIT 8")
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var state string
			var count int64
			if e = rows.Scan(&state, &count); e != nil {
				rows.Close()
				return out, e
			}
			out.RetryStates[state] = count
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		if e = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM stream_progress p JOIN operations o ON p.operation_id=o.operation_id WHERE o.stage<>'CLIENT_ACKED'").Scan(&out.RetainedStreams); e != nil {
			return out, e
		}
	}
	return out, nil
}
func (s *Store) Checkpoint(ctx context.Context) error {
	var busy, log, done int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); err != nil {
		return err
	}
	if busy != 0 {
		return ErrStateInUse
	}
	return nil
}

type ProfileBackup struct{ Filename, SHA256 string }

func (s *Store) Backup(ctx context.Context) (ProfileBackup, error) {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return ProfileBackup{}, err
	}
	b, err := backupVersion(ctx, filepath.Dir(s.filename), s.filename, version)
	if err != nil {
		return ProfileBackup{}, err
	}
	if b == nil {
		return ProfileBackup{}, ErrUnsupportedSchema
	}
	return ProfileBackup{b.Filename, b.SHA256}, nil
}
