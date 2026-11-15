package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

func (r *RemoteImport) enableHTTPBindings(ctx context.Context) error {
	r.store.sourceMu.Lock()
	defer r.store.sourceMu.Unlock()
	var version int
	if err := r.store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == HTTPBindingSchemaVersion || (version == smallBatchSchemaVersion || version == daemonSchemaVersion) {
		return nil
	}
	if version != RemoteSchemaVersion {
		return ErrUnsupportedSchema
	}
	u, err := r.sources.DiskUsage(ctx)
	if err != nil {
		return err
	}
	projected := u.PageCount * u.PageSize
	if u.Backup+projected > r.sources.limits.BackupBytes || u.Free-projected < r.sources.limits.FreeDiskBytes {
		return ErrSourceQuota
	}
	backup, err := backupVersion(ctx, filepath.Dir(r.store.filename), r.store.filename, RemoteSchemaVersion)
	if err != nil {
		return err
	}
	if backup == nil {
		return ErrUnsupportedSchema
	}
	raw, _ := json.Marshal(map[string]any{"fromVersion": RemoteSchemaVersion, "toVersion": HTTPBindingSchemaVersion, "backup": backup.Filename, "backupSHA256": backup.SHA256, "module": "http-upload-association/v1", "engineActivated": false, "intentAndBaseline": "unchanged"})
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		var current int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
			return err
		}
		if current != RemoteSchemaVersion {
			return ErrStaleGeneration
		}
		if _, err := tx.ExecContext(ctx, "ALTER TABLE operations ADD COLUMN "+httpBindingColumn); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, httpBindingIndexDDL); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, currentScanIndexDDL); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, pendingRootIndexDDL); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", HTTPBindingSchemaVersion)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", HTTPBindingSchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(raw))
		if err != nil {
			return err
		}
		return r.point("http_binding.migration.before_commit")
	})
}
