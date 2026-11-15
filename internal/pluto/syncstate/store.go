package syncstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const applicationID = 0x504c5353

type Store struct {
	db               *sql.DB
	lock             *os.File
	legacyCheckpoint string
	filename         string
	sourceMu         sync.Mutex
	sources          *Sources
	artifacts        *Artifacts
	remoteImport     *RemoteImport
	batches          *smallBatchArtifacts
}

const schema = `
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL, manifest_json TEXT NOT NULL);
CREATE TABLE roots(
 root_id TEXT PRIMARY KEY, mapping_id TEXT NOT NULL UNIQUE,
 server_identity TEXT NOT NULL, remote_root_id TEXT NOT NULL, device_id TEXT NOT NULL, source_identity TEXT NOT NULL,
 trust_generation INTEGER NOT NULL DEFAULT 1, active_remote_generation INTEGER NOT NULL DEFAULT 1,
 trust TEXT NOT NULL DEFAULT 'RECONCILIATION_REQUIRED', name_codec TEXT NOT NULL DEFAULT 'legacy',
 max_file_bytes INTEGER NOT NULL DEFAULT 268435456 CHECK(max_file_bytes=268435456),
 max_active_versions INTEGER NOT NULL DEFAULT 10 CHECK(max_active_versions=10),
 allows_delete INTEGER NOT NULL DEFAULT 0 CHECK(allows_delete=0), engine_ready INTEGER NOT NULL DEFAULT 0 CHECK(engine_ready=0),
 legacy_checkpoint TEXT NOT NULL,
 UNIQUE(server_identity,remote_root_id)
);
CREATE TABLE local_entries(
 root_id TEXT NOT NULL REFERENCES roots(root_id), entry_id TEXT NOT NULL, parent_id TEXT,
 name_key TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0), descriptor_json TEXT NOT NULL,
 PRIMARY KEY(root_id,entry_id), FOREIGN KEY(root_id,parent_id) REFERENCES local_entries(root_id,entry_id)
);
CREATE UNIQUE INDEX local_sibling_key ON local_entries(root_id,COALESCE(parent_id,''),name_key);
CREATE TABLE baselines(
 root_id TEXT NOT NULL, entry_id TEXT NOT NULL, node_id TEXT NOT NULL,
 descriptor_json TEXT NOT NULL, PRIMARY KEY(root_id,entry_id),
 FOREIGN KEY(root_id,entry_id) REFERENCES local_entries(root_id,entry_id)
);
CREATE INDEX baseline_remote_node ON baselines(root_id,node_id);
CREATE TABLE remote_entries(
 root_id TEXT NOT NULL REFERENCES roots(root_id), generation INTEGER NOT NULL, node_id TEXT NOT NULL,
 last_seq INTEGER NOT NULL, descriptor_json TEXT NOT NULL, PRIMARY KEY(root_id,generation,node_id)
);
CREATE TABLE dirty_entries(
 root_id TEXT NOT NULL, entry_id TEXT NOT NULL, observed_generation INTEGER NOT NULL,
 remote_seq INTEGER NOT NULL DEFAULT 0, reasons TEXT NOT NULL, first_dirty_ms INTEGER NOT NULL,
 PRIMARY KEY(root_id,entry_id), FOREIGN KEY(root_id,entry_id) REFERENCES local_entries(root_id,entry_id)
);
CREATE TABLE operations(
 operation_id TEXT PRIMARY KEY, root_id TEXT NOT NULL, entry_id TEXT NOT NULL, local_generation INTEGER NOT NULL,
 kind TEXT NOT NULL, intent_json TEXT NOT NULL, intent_fingerprint TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('PLANNED','SEALED','SUBMITTED','CLIENT_ACKED')),
 sha256 TEXT NOT NULL DEFAULT '', snapshot_id TEXT NOT NULL DEFAULT '', sealed_fingerprint TEXT NOT NULL DEFAULT '', receipt_json TEXT,
 FOREIGN KEY(root_id,entry_id) REFERENCES local_entries(root_id,entry_id),
 UNIQUE(root_id,entry_id,local_generation,kind)
);
CREATE INDEX pending_operations ON operations(root_id,stage,operation_id);
CREATE INDEX pending_entry_operations ON operations(root_id,entry_id,local_generation,kind) WHERE stage<>'CLIENT_ACKED';
CREATE TABLE operation_dependencies(
 operation_id TEXT NOT NULL REFERENCES operations(operation_id), dependency_id TEXT NOT NULL REFERENCES operations(operation_id),
 PRIMARY KEY(operation_id,dependency_id), CHECK(operation_id<>dependency_id)
);
CREATE TABLE journal_cursors(
 root_id TEXT NOT NULL REFERENCES roots(root_id), stream TEXT NOT NULL CHECK(stream IN ('local','remote')),
 epoch TEXT NOT NULL, position INTEGER NOT NULL CHECK(position>=0), valid INTEGER NOT NULL CHECK(valid IN (0,1)),
 PRIMARY KEY(root_id,stream)
);
`

// Open uses a new database generation beside legacy JSON state. It never
// imports guessed baselines or rewrites config/status/credentials.
func Open(ctx context.Context, stateDir string) (*Store, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	filename := filepath.Join(stateDir, "sync-state.sqlite")
	lock, err := lockStateWriter(stateDir)
	if err != nil {
		return nil, err
	}
	s := &Store{lock: lock, filename: filename}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("sync state must be a regular private file")
		}
		if err = preflight(ctx, filename); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	backup, err := backupVersionOne(ctx, stateDir, filename)
	if err != nil {
		return nil, err
	}
	checkpoint, raw, err := readLegacyCheckpoint(stateDir)
	if err != nil {
		return nil, err
	}
	s.legacyCheckpoint = checkpoint
	if _, err = os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		if err = initialize(ctx, stateDir, filename, checkpoint, raw); err != nil {
			return nil, err
		}
	}
	s.db, err = openDB(filename, false)
	if err != nil {
		return nil, err
	}
	if err = s.migratePendingIndex(ctx, backup); err != nil {
		return nil, err
	}
	if err = s.transaction(ctx, func(tx *sql.Tx) error {
		// A legacy binary ignores this new database. A changed old checkpoint
		// invalidates observation trust; retained baselines/operations survive.
		_, err := tx.ExecContext(ctx, `UPDATE journal_cursors SET valid=0 WHERE root_id IN (SELECT root_id FROM roots WHERE legacy_checkpoint<>?)`, checkpoint)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE roots SET trust_generation=trust_generation+1, trust=?, legacy_checkpoint=? WHERE legacy_checkpoint<>?`, TrustRequired, checkpoint, checkpoint)
		return err
	}); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func lockStateWriter(stateDir string) (*os.File, error) {
	lock, err := os.OpenFile(filepath.Join(stateDir, "sync-state-writer.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, ErrStateInUse
	}
	return lock, nil
}

func openDB(filename string, readOnly bool) (*sql.DB, error) {
	return openStateDB(filename, readOnly, true)
}

func openStateDB(filename string, readOnly, enableWAL bool) (*sql.DB, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	q := u.Query()
	if readOnly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rw")
		if enableWAL {
			q.Add("_pragma", "journal_mode(WAL)")
		}
		q.Add("_pragma", "synchronous(FULL)")
		q.Add("_pragma", "foreign_keys(ON)")
		q.Add("_pragma", "busy_timeout(5000)")
		q.Add("_pragma", "cache_size(-8192)")
		q.Add("_pragma", "wal_autocheckpoint(1024)")
		q.Set("_txlock", "immediate")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open(stateSQLiteDriverName, u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func preflight(ctx context.Context, filename string) error {
	db, err := openDB(filename, true)
	if err != nil {
		return err
	}
	defer db.Close()
	var version, appID int
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return fmt.Errorf("sync state preflight: %w", err)
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if (version != 1 && version != SchemaVersion && version != SourceSchemaVersion && version != ArtifactSchemaVersion && version != RemoteSchemaVersion && version != HTTPBindingSchemaVersion && version != smallBatchSchemaVersion && version != daemonSchemaVersion) || appID != applicationID {
		return ErrUnsupportedSchema
	}
	rows, err := db.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return err
	}
	for rows.Next() {
		var integrity string
		if err = rows.Scan(&integrity); err != nil || integrity != "ok" {
			rows.Close()
			return errors.New("sync state is corrupt; preserve it for recovery")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// Validate the complete recognized DDL before opening a writable connection.
	// A matching user_version alone cannot identify a missing/replaced table.
	expected := map[string]bool{}
	for _, statement := range strings.Split(schemaAtVersion(version), ";") {
		normalized := strings.Join(strings.Fields(statement), " ")
		if normalized != "" {
			expected[normalized] = true
		}
	}
	rows, err = db.QueryContext(ctx, "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return err
	}
	for rows.Next() {
		var ddl string
		if err = rows.Scan(&ddl); err != nil {
			rows.Close()
			return err
		}
		normalized := strings.Join(strings.Fields(ddl), " ")
		if !expected[normalized] {
			rows.Close()
			return ErrUnsupportedSchema
		}
		delete(expected, normalized)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		return ErrUnsupportedSchema
	}
	rows, err = db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	violation := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if violation {
		return errors.New("sync state foreign keys are corrupt; preserve it for recovery")
	}
	return nil
}

func readLegacyCheckpoint(dir string) (string, []byte, error) {
	name := filepath.Join(dir, "status.json")
	info, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 {
		return "", nil, errors.New("legacy checkpoint is not a bounded regular file")
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return "", nil, err
	}
	if !json.Valid(raw) {
		return "", nil, errors.New("legacy checkpoint is invalid; migration stopped")
	}
	return hashBytes(raw), raw, nil
}

func initialize(ctx context.Context, dir, final, checkpoint string, raw []byte) error {
	if raw != nil {
		backupDir := filepath.Join(dir, "sync-state-backups")
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			return err
		}
		name := filepath.Join(backupDir, "legacy-checkpoint-"+checkpoint+".json")
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if errors.Is(err, os.ErrExist) {
			existing, err := os.ReadFile(name)
			if err != nil || !bytes.Equal(existing, raw) {
				return errors.New("legacy checkpoint backup does not match")
			}
		} else if err != nil {
			return err
		} else {
			_, err = file.Write(raw)
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	temp, err := os.CreateTemp(dir, ".sync-state-init-*.sqlite")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	if err = temp.Close(); err != nil {
		return err
	}
	// A failed/crashed initialization leaves its private generation for diagnosis;
	// only a complete checkpointed generation is renamed to the canonical path.
	db, err := openDB(tempName, false)
	if err != nil {
		return err
	}
	s := &Store{db: db}
	manifest := map[string]any{"source": "legacy-json-or-new-profile", "schemaVersion": SchemaVersion, "baseline": "UNKNOWN", "legacyCheckpointBackup": checkpoint, "engineActivated": false}
	manifestRaw, _ := json.Marshal(manifest)
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d; PRAGMA user_version=%d", applicationID, SchemaVersion)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", SchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(manifestRaw))
		return err
	})
	if err == nil {
		_, err = db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	}
	closeErr := db.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tempName, final); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *Store) Close() error {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if s.batches != nil && s.batches.inUse() {
		return ErrArtifactInUse
	}
	if s.artifacts != nil {
		if err := s.artifacts.Close(); err != nil {
			return err // Live snapshot users retain the writer lock and database.
		}
	}
	if s.batches != nil {
		if err := s.batches.close(); err != nil {
			return err
		}
	}
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		err = errors.Join(err, s.lock.Close())
		s.lock = nil
	}
	return err
}

func (s *Store) transaction(ctx context.Context, change func(*sql.Tx) error) error {
	stateTransactions.Add(1)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if tx.Rollback() == nil {
			stateRollbacks.Add(1)
		}
	}()
	if err = change(tx); err != nil {
		return err
	}
	err = tx.Commit()
	if err == nil {
		stateCommits.Add(1)
	}
	return err
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readRoot(ctx context.Context, q queryer, id string) (Root, error) {
	var r Root
	err := q.QueryRowContext(ctx, `SELECT root_id,mapping_id,server_identity,remote_root_id,device_id,source_identity,trust_generation,active_remote_generation,trust,name_codec,max_file_bytes,max_active_versions,allows_delete,engine_ready FROM roots WHERE root_id=?`, id).Scan(
		&r.RootID, &r.MappingID, &r.ServerIdentity, &r.RemoteRootID, &r.DeviceID, &r.SourceIdentity, &r.TrustGeneration, &r.ActiveRemoteGeneration, &r.Trust, &r.NameCodec, &r.MaxFileBytes, &r.MaxActiveVersions, &r.AllowsDelete, &r.EngineReady)
	return r, err
}

func (s *Store) Root(ctx context.Context, id string) (Root, error) { return readRoot(ctx, s.db, id) }

func (s *Store) BindRoot(ctx context.Context, binding RootBinding) error {
	if err := checkBinding(binding); err != nil {
		return err
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		old, err := readRoot(ctx, tx, binding.RootID)
		if err == nil {
			if old.RootBinding != binding {
				return ErrIdentityConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var conflicts int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM roots WHERE mapping_id=? OR (server_identity=? AND remote_root_id=?)`, binding.MappingID, binding.ServerIdentity, binding.RemoteRootID).Scan(&conflicts); err != nil {
			return err
		}
		if conflicts != 0 {
			return ErrIdentityConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO roots(root_id,mapping_id,server_identity,remote_root_id,device_id,source_identity,legacy_checkpoint) VALUES(?,?,?,?,?,?,?)`, binding.RootID, binding.MappingID, binding.ServerIdentity, binding.RemoteRootID, binding.DeviceID, binding.SourceIdentity, s.legacyCheckpoint)
		return err
	})
}

func (s *Store) InvalidateTrust(ctx context.Context, rootID string, expected int64) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE roots SET trust_generation=trust_generation+1,trust=? WHERE root_id=? AND trust_generation=?`, TrustRequired, rootID, expected)
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
		_, err = tx.ExecContext(ctx, "UPDATE journal_cursors SET valid=0 WHERE root_id=?", rootID)
		return err
	})
}
