package syncstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

const pendingIndexDDL = "CREATE INDEX pending_entry_operations ON operations(root_id,entry_id,local_generation,kind) WHERE stage<>'CLIENT_ACKED'"

func schemaAtVersion(version int) string {
	if version == daemonSchemaVersion {
		return schemaAtVersion(smallBatchSchemaVersion) + daemonSchema
	}
	if version == smallBatchSchemaVersion {
		return schemaAtVersion(HTTPBindingSchemaVersion) + smallBatchStateSchema
	}
	if version == HTTPBindingSchemaVersion {
		return strings.Replace(schema, "receipt_json TEXT,", "receipt_json TEXT, "+httpBindingColumn+",", 1) + sourceSchema + artifactSchema + remoteSchema + httpBindingIndexDDL + ";" + currentScanIndexDDL + ";" + pendingRootIndexDDL + ";"
	}
	if version == 1 {
		return strings.Replace(schema, pendingIndexDDL+";", "", 1)
	}
	if version == ArtifactSchemaVersion {
		return schema + sourceSchema + artifactSchema
	}
	if version == RemoteSchemaVersion {
		return schema + sourceSchema + artifactSchema + remoteSchema
	}
	if version == SourceSchemaVersion {
		return schema + sourceSchema
	}
	return schema
}

type migrationBackup struct{ Filename, SHA256 string }

func fileDigest(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.CopyBuffer(h, f, make([]byte, 65536)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// backupVersionOne uses the SQLite backup API, which includes committed WAL
// pages. A raw copy of the main file could silently omit durable operations.
// The caller holds the private state writer lock throughout backup+migration.
func backupVersionOne(ctx context.Context, dir, filename string) (*migrationBackup, error) {
	return backupVersion(ctx, dir, filename, 1)
}

func backupVersion(ctx context.Context, dir, filename string, wanted int) (*migrationBackup, error) {
	if _, err := os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	source, err := openDB(filename, true)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	var version int
	if err = source.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version != wanted {
		return nil, nil
	}
	backupDir := filepath.Join(dir, "sync-state-backups")
	if err = os.MkdirAll(backupDir, 0700); err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(backupDir, fmt.Sprintf(".schema-v%d-backup-*.sqlite", wanted))
	if err != nil {
		return nil, err
	}
	tempName := temp.Name()
	if err = temp.Close(); err != nil {
		return nil, err
	}
	// Interrupted private generations remain available for diagnosis.
	conn, err := source.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	err = conn.Raw(func(driverConn any) error {
		backupSource, ok := driverConn.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver has no qualified backup API")
		}
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(tempName)}
		b, err := backupSource.NewBackup(u.String())
		if err != nil {
			return err
		}
		for {
			if err = ctx.Err(); err != nil {
				return errors.Join(err, b.Finish())
			}
			more, stepErr := b.Step(128)
			if stepErr != nil {
				return errors.Join(stepErr, b.Finish())
			}
			if !more {
				return b.Finish()
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if err = preflight(ctx, tempName); err != nil {
		return nil, fmt.Errorf("migration backup validation: %w", err)
	}
	f, err := os.OpenFile(tempName, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	digest, err := fileDigest(tempName)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("schema-v%d-%s.sqlite", wanted, digest)
	final := filepath.Join(backupDir, name)
	if err = os.Link(tempName, final); errors.Is(err, os.ErrExist) {
		oldDigest, readErr := fileDigest(final)
		if readErr != nil || oldDigest != digest {
			return nil, errors.New("existing schema backup does not match")
		}
	} else if err != nil {
		return nil, err
	}
	if err = os.Remove(tempName); err != nil {
		return nil, err
	}
	directory, err := os.Open(backupDir)
	if err != nil {
		return nil, err
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	return &migrationBackup{Filename: name, SHA256: digest}, nil
}

func (s *Store) migratePendingIndex(ctx context.Context, backup *migrationBackup) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == SchemaVersion || version == SourceSchemaVersion || version == ArtifactSchemaVersion || version == RemoteSchemaVersion || version == HTTPBindingSchemaVersion || version == smallBatchSchemaVersion || version == daemonSchemaVersion {
		return nil
	}
	if version != 1 || backup == nil || !validHash(backup.SHA256) {
		return ErrUnsupportedSchema
	}
	manifest, err := json.Marshal(map[string]any{"fromVersion": 1, "toVersion": SchemaVersion, "backup": backup.Filename, "backupSHA256": backup.SHA256, "engineActivated": false, "change": "partial pending-entry operation index; descriptors unchanged"})
	if err != nil {
		return err
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if version != 1 {
			return ErrStaleGeneration
		}
		if _, err := tx.ExecContext(ctx, pendingIndexDDL); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", SchemaVersion)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", SchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(manifest))
		return err
	})
}
