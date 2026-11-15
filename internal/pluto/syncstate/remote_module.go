package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sync/atomic"
	"time"
)

const remoteSchema = `
CREATE TABLE remote_candidate_roots(root_id TEXT PRIMARY KEY REFERENCES roots(root_id),revision INTEGER NOT NULL CHECK(revision>0),descriptor_json TEXT NOT NULL);
CREATE TABLE remote_seen_bindings(root_id TEXT NOT NULL REFERENCES roots(root_id),binding_version TEXT NOT NULL,PRIMARY KEY(root_id,binding_version));
CREATE TABLE remote_preparations(root_id TEXT PRIMARY KEY REFERENCES roots(root_id),generation INTEGER NOT NULL,descriptor_json TEXT NOT NULL);
CREATE TABLE remote_snapshot_pages(root_id TEXT NOT NULL REFERENCES roots(root_id),generation INTEGER NOT NULL,request_cursor TEXT NOT NULL,response_hash TEXT NOT NULL,result_json TEXT NOT NULL,PRIMARY KEY(root_id,generation,request_cursor));
CREATE INDEX remote_candidate_namespace ON remote_entries(root_id,generation,json_extract(descriptor_json,'$.ParentID'),json_extract(descriptor_json,'$.Name'),node_id) WHERE json_extract(descriptor_json,'$.Presence')='PRESENT';
CREATE TABLE remote_replan_all(root_id TEXT PRIMARY KEY REFERENCES roots(root_id),generation INTEGER NOT NULL,after_entry TEXT NOT NULL,remote_seq INTEGER NOT NULL);
CREATE TABLE remote_replan_nodes(root_id TEXT NOT NULL REFERENCES roots(root_id),node_id TEXT NOT NULL,generation INTEGER NOT NULL,after_entry TEXT NOT NULL,remote_seq INTEGER NOT NULL,PRIMARY KEY(root_id,node_id));
CREATE INDEX remote_baseline_entry ON baselines(root_id,node_id,entry_id);
CREATE TABLE captured_local_entries(root_id TEXT NOT NULL,entry_id TEXT NOT NULL,set_id TEXT NOT NULL,destination TEXT NOT NULL,local_generation INTEGER NOT NULL,evidence_json TEXT NOT NULL,PRIMARY KEY(root_id,entry_id),UNIQUE(set_id,destination),FOREIGN KEY(root_id,entry_id) REFERENCES local_entries(root_id,entry_id),FOREIGN KEY(set_id,destination) REFERENCES source_entries(set_id,destination));
`

type RemoteImport struct {
	store            *Store
	sources          *Sources
	testPoint        func(string) error
	metadataObserver atomic.Pointer[SourceWitness]
}

func (r *RemoteImport) point(name string) error {
	if r.testPoint != nil {
		return r.testPoint(name)
	}
	return nil
}

// EnableRemoteImport is explicit and inactive. It neither opens a remote
// connection nor sets EngineReady, imports a guessed B, or edits legacy config.
func (s *Store) EnableRemoteImport(ctx context.Context) (*RemoteImport, error) {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if s.remoteImport != nil {
		return s.remoteImport, nil
	}
	if s.sources == nil || s.artifacts == nil {
		return nil, errors.New("sources and artifacts must be enabled first")
	}
	if err := s.sources.admit(ctx, MaxSourcePageBytes); err != nil {
		return nil, err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version == ArtifactSchemaVersion {
		u, err := s.sources.DiskUsage(ctx)
		if err != nil {
			return nil, err
		}
		projected := u.PageCount * u.PageSize
		if u.Backup+projected > s.sources.limits.BackupBytes || u.Free-projected < s.sources.limits.FreeDiskBytes {
			return nil, ErrSourceQuota
		}
		backup, err := backupVersion(ctx, filepath.Dir(s.filename), s.filename, ArtifactSchemaVersion)
		if err != nil {
			return nil, err
		}
		if backup == nil {
			return nil, ErrUnsupportedSchema
		}
		raw, _ := json.Marshal(map[string]any{"fromVersion": ArtifactSchemaVersion, "toVersion": RemoteSchemaVersion, "backup": backup.Filename, "backupSHA256": backup.SHA256, "module": "candidate-remote-import/v1", "engineActivated": false, "baseline": "unchanged"})
		if err = s.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
			var current int
			if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
				return err
			}
			if current != ArtifactSchemaVersion {
				return ErrStaleGeneration
			}
			if _, err := tx.ExecContext(ctx, remoteSchema); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", RemoteSchemaVersion)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", RemoteSchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(raw))
			return err
		}); err != nil {
			return nil, err
		}
	} else if version != RemoteSchemaVersion && version != HTTPBindingSchemaVersion && version != smallBatchSchemaVersion && version != daemonSchemaVersion {
		return nil, ErrUnsupportedSchema
	}
	r := &RemoteImport{store: s, sources: s.sources}
	s.remoteImport = r
	return r, nil
}

func readCandidate(ctx context.Context, q queryer, root string) (RemoteCandidate, error) {
	return readJSON[RemoteCandidate](ctx, q, "SELECT descriptor_json FROM remote_candidate_roots WHERE root_id=?", root)
}
func (r *RemoteImport) Candidate(ctx context.Context, root string) (RemoteCandidate, error) {
	return readCandidate(ctx, r.store.db, root)
}
func saveCandidate(ctx context.Context, tx *sql.Tx, c RemoteCandidate) error {
	raw, _ := json.Marshal(c)
	_, err := tx.ExecContext(ctx, "INSERT INTO remote_candidate_roots(root_id,revision,descriptor_json) VALUES(?,?,?) ON CONFLICT(root_id) DO UPDATE SET revision=excluded.revision,descriptor_json=excluded.descriptor_json", c.RootID, c.Revision, string(raw))
	return err
}

// InvalidateRemote records a remote observation gap. It does not delete B or
// intents. A subsequent snapshot requires a new binding_version: a backend
// uncertainty must never revive the previous imported binding.
func (r *RemoteImport) InvalidateRemote(ctx context.Context, w RemoteWitness) error {
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		c, err := readCandidate(ctx, tx, w.RootID)
		if err != nil {
			return err
		}
		if c.RemoteWitness != w {
			return ErrStaleGeneration
		}
		root, err := readRoot(ctx, tx, w.RootID)
		if err != nil {
			return err
		}
		if root.TrustGeneration != w.TrustGeneration {
			return ErrStaleGeneration
		}
		if c.Revision == math.MaxInt64 || c.TrustGeneration == math.MaxInt64 {
			return ErrStaleGeneration
		}
		c.Valid = false
		c.Revision++
		c.TrustGeneration++
		if err = saveCandidate(ctx, tx, c); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE roots SET trust_generation=trust_generation+1,trust=? WHERE root_id=? AND trust_generation=?", TrustRequired, w.RootID, w.TrustGeneration); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE journal_cursors SET valid=0 WHERE root_id=? AND stream='remote'", w.RootID)
		return err
	})
}
