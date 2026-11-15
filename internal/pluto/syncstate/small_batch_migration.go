package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

const smallBatchSchemaVersion = 7
const smallBatchStateSchema = `
CREATE TABLE small_batch_groups(batch_id TEXT PRIMARY KEY CHECK(length(batch_id) BETWEEN 1 AND 128),root_id TEXT NOT NULL REFERENCES roots(root_id),artifact_scope TEXT NOT NULL REFERENCES artifact_scope(scope_id),phase TEXT NOT NULL CHECK(phase IN('RESERVED','BUILDING','READY','ATTEMPTED','DISPOSING','GONE')),revision INTEGER NOT NULL CHECK(revision>0),manifest BLOB NOT NULL CHECK(length(manifest) BETWEEN 1 AND 4194304),manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64),expected_bytes INTEGER NOT NULL CHECK(expected_bytes BETWEEN 0 AND 33554432),filename TEXT NOT NULL UNIQUE CHECK(length(filename)=42),directory_identity TEXT NOT NULL DEFAULT '' CHECK(length(directory_identity)<=256),file_identity TEXT NOT NULL DEFAULT '' CHECK(length(file_identity)<=256),aggregate_sha256 TEXT NOT NULL DEFAULT '' CHECK(length(aggregate_sha256) IN(0,64)));
CREATE INDEX live_small_batch_groups ON small_batch_groups(root_id,batch_id) WHERE phase<>'GONE';
CREATE TABLE small_batch_members(batch_id TEXT NOT NULL REFERENCES small_batch_groups(batch_id),ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 499),operation_id TEXT NOT NULL REFERENCES operations(operation_id),source_generation INTEGER NOT NULL CHECK(source_generation>0),source_identity TEXT NOT NULL CHECK(length(source_identity)=64),offset_bytes INTEGER NOT NULL CHECK(offset_bytes BETWEEN 0 AND 33554432),size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 262144),active INTEGER NOT NULL CHECK(active IN(0,1)),PRIMARY KEY(batch_id,ordinal),UNIQUE(batch_id,operation_id));
CREATE UNIQUE INDEX active_small_batch_original ON small_batch_members(operation_id) WHERE active=1;
`

type smallBatchStore struct {
	remote *RemoteImport
	proofs smallJobProofCache
}

// Explicit optional migration. Merely constructing an HTTP session or opening
// an existing profile still uses v6 and never enables packet scheduling.
func (r *RemoteImport) enableSmallBatches(ctx context.Context) (*smallBatchStore, error) {
	r.store.sourceMu.Lock()
	defer r.store.sourceMu.Unlock()
	if r.sources == nil || r.store.artifacts == nil {
		return nil, ErrArtifactUnreconciled
	}
	var version int
	if err := r.store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version == smallBatchSchemaVersion || version == daemonSchemaVersion {
		return &smallBatchStore{remote: r}, nil
	}
	if version != HTTPBindingSchemaVersion {
		return nil, ErrUnsupportedSchema
	}
	usage, err := r.sources.DiskUsage(ctx)
	if err != nil {
		return nil, err
	}
	projected := usage.PageCount * usage.PageSize
	if usage.Backup+projected > r.sources.limits.BackupBytes || usage.Free-projected < r.sources.limits.FreeDiskBytes {
		return nil, ErrSourceQuota
	}
	backup, err := backupVersion(ctx, filepath.Dir(r.store.filename), r.store.filename, HTTPBindingSchemaVersion)
	if err != nil {
		return nil, err
	}
	if backup == nil {
		return nil, ErrUnsupportedSchema
	}
	manifest, _ := json.Marshal(map[string]any{"fromVersion": HTTPBindingSchemaVersion, "toVersion": smallBatchSchemaVersion, "backup": backup.Filename, "backupSHA256": backup.SHA256, "module": "small-batch-references/v1", "engineActivated": false, "originalOperationsAndBaselines": "unchanged"})
	err = r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		var current int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
			return err
		}
		if current != HTTPBindingSchemaVersion {
			return ErrStaleGeneration
		}
		if _, err := tx.ExecContext(ctx, smallBatchStateSchema); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", smallBatchSchemaVersion)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", smallBatchSchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(manifest)); err != nil {
			return err
		}
		return r.point("small_batch.migration.before_commit")
	})
	if err != nil {
		return nil, err
	}
	return &smallBatchStore{remote: r}, nil
}

// Shared with ordinary artifact admission, in the same SQLite write transaction.
// A packet is additional plaintext until its physical cleanup is committed.
func smallBatchReservedBytes(ctx context.Context, q queryer) (int64, error) {
	var version int
	if err := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, err
	}
	if version != smallBatchSchemaVersion && version != daemonSchemaVersion {
		return 0, nil
	}
	var rows, live, total int64
	err := q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN phase='GONE' THEN 0 ELSE 1 END),0),COALESCE(SUM(CASE WHEN phase='GONE' THEN 0 ELSE expected_bytes END),0) FROM (SELECT phase,expected_bytes FROM small_batch_groups LIMIT 65)").Scan(&rows, &live, &total)
	if err != nil {
		return 0, err
	}
	if rows > 64 || live > 4 || total < 0 || total > 4*smallBatchMaximumDataBytes {
		return 0, ErrSourceQuota
	}
	return total, nil
}
