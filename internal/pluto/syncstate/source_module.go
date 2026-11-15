package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const sourceSchema = `
CREATE TABLE source_sets(set_id TEXT PRIMARY KEY,config_digest TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),owner_id TEXT NOT NULL DEFAULT '',owner_sequence INTEGER NOT NULL DEFAULT 0,gap_generation INTEGER NOT NULL DEFAULT 0,attached_root_id TEXT UNIQUE REFERENCES roots(root_id));
CREATE TABLE source_bindings(set_id TEXT NOT NULL REFERENCES source_sets(set_id),source_id TEXT NOT NULL,revision INTEGER NOT NULL,active INTEGER NOT NULL CHECK(active IN(0,1)),descriptor_json TEXT NOT NULL,PRIMARY KEY(set_id,source_id));
CREATE INDEX source_bindings_active ON source_bindings(set_id,source_id) WHERE active=1;
CREATE TABLE source_prefixes(set_id TEXT NOT NULL,source_id TEXT NOT NULL,destination TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(set_id,source_id,destination),FOREIGN KEY(set_id,source_id) REFERENCES source_bindings(set_id,source_id));
CREATE INDEX source_prefix_destination ON source_prefixes(set_id,destination,source_id);
CREATE TABLE source_prefix_work(set_id TEXT NOT NULL,source_id TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(set_id,source_id),FOREIGN KEY(set_id,source_id) REFERENCES source_bindings(set_id,source_id));
CREATE TABLE source_entries(set_id TEXT NOT NULL REFERENCES source_sets(set_id),destination TEXT NOT NULL,generation INTEGER NOT NULL,verification_request INTEGER NOT NULL,ambiguous INTEGER NOT NULL CHECK(ambiguous IN(0,1)),descriptor_json TEXT NOT NULL,PRIMARY KEY(set_id,destination));
CREATE TABLE source_membership(set_id TEXT NOT NULL,source_id TEXT NOT NULL,destination TEXT NOT NULL,seen_scan_id TEXT NOT NULL,PRIMARY KEY(set_id,source_id,destination),FOREIGN KEY(set_id,source_id) REFERENCES source_bindings(set_id,source_id),FOREIGN KEY(set_id,destination) REFERENCES source_entries(set_id,destination));
CREATE INDEX source_membership_entry ON source_membership(set_id,destination,source_id);
CREATE TABLE source_scans(scan_id TEXT PRIMARY KEY,set_id TEXT NOT NULL,source_id TEXT NOT NULL,revision INTEGER NOT NULL,owner_id TEXT NOT NULL,owner_sequence INTEGER NOT NULL,gap_generation INTEGER NOT NULL,status TEXT NOT NULL CHECK(status IN('DISCOVERING','COMPLETE','INCOMPLETE')),reason TEXT NOT NULL DEFAULT '',pages INTEGER NOT NULL DEFAULT 0,FOREIGN KEY(set_id,source_id) REFERENCES source_bindings(set_id,source_id));
CREATE INDEX source_scan_scope ON source_scans(set_id,source_id,status,scan_id);
CREATE INDEX source_scans_open ON source_scans(set_id,scan_id) WHERE status='DISCOVERING';
CREATE TABLE source_frontier(scan_id TEXT NOT NULL REFERENCES source_scans(scan_id),work_id INTEGER NOT NULL,physical_path TEXT NOT NULL,destination TEXT NOT NULL,depth INTEGER NOT NULL CHECK(depth BETWEEN 0 AND 128),claim_token TEXT NOT NULL DEFAULT '',page INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(scan_id,work_id),UNIQUE(scan_id,destination));
CREATE INDEX source_frontier_pending ON source_frontier(scan_id,work_id) WHERE claim_token='';
CREATE TABLE source_verification(set_id TEXT NOT NULL,destination TEXT NOT NULL,request INTEGER NOT NULL,PRIMARY KEY(set_id,destination),FOREIGN KEY(set_id,destination) REFERENCES source_entries(set_id,destination));
CREATE TABLE source_evidence(set_id TEXT NOT NULL,destination TEXT NOT NULL,evidence_json TEXT NOT NULL,PRIMARY KEY(set_id,destination),FOREIGN KEY(set_id,destination) REFERENCES source_entries(set_id,destination));
CREATE TABLE source_gaps(set_id TEXT NOT NULL REFERENCES source_sets(set_id),generation INTEGER NOT NULL,reason TEXT NOT NULL,owner_id TEXT NOT NULL,PRIMARY KEY(set_id,generation));
`

type Sources struct {
	store  *Store
	mu     sync.Mutex
	limits SourceLimits
	owners map[string]SourceWitness
}
type SourceDiskUsage struct{ Database, WAL, SHM, Backup, PageSize, PageCount, Free int64 }

// EnableSources is opt-in. Open(base) does not create/activate this module.
func (s *Store) EnableSources(ctx context.Context, limits SourceLimits) (*Sources, error) {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if limits.DatabaseBytes < 16<<20 || limits.WALBytes < 1<<20 || limits.WALBytes > limits.DatabaseBytes/2 || limits.BackupBytes < 16<<20 || limits.FreeDiskBytes < 0 {
		return nil, ErrSourceQuota
	}
	if s.sources != nil {
		if s.sources.limits != limits {
			return nil, ErrIdentityConflict
		}
		return s.sources, nil
	}
	sources := &Sources{store: s, limits: limits, owners: make(map[string]SourceWitness)}
	if err := sources.admit(ctx, MaxSourcePageBytes); err != nil {
		return nil, err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version == SchemaVersion {
		usage, err := sources.DiskUsage(ctx)
		if err != nil {
			return nil, err
		}
		// The SQLite backup includes all committed WAL pages, not just the main
		// physical file. Admit its full page_count size before creating any artifact.
		projected := usage.PageCount * usage.PageSize
		if usage.Backup+projected > limits.BackupBytes || usage.Free-projected < limits.FreeDiskBytes {
			return nil, ErrSourceQuota
		}
		backup, err := backupVersion(ctx, filepath.Dir(s.filename), s.filename, SchemaVersion)
		if err != nil {
			return nil, err
		}
		if backup == nil {
			return nil, ErrUnsupportedSchema
		}
		if err = sources.admit(ctx, MaxSourcePageBytes); err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(map[string]any{"fromVersion": SchemaVersion, "toVersion": SourceSchemaVersion, "backup": backup.Filename, "backupSHA256": backup.SHA256, "engineActivated": false, "module": "local-sources/v1", "remoteAttachment": "optional; no guessed identity"})
		if err = s.transaction(ctx, func(tx *sql.Tx) error {
			var now int
			if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&now); err != nil {
				return err
			}
			if now != SchemaVersion {
				return ErrStaleGeneration
			}
			if _, err := tx.ExecContext(ctx, sourceSchema); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", SourceSchemaVersion)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", SourceSchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(raw))
			return err
		}); err != nil {
			return nil, err
		}
	} else if version != SourceSchemaVersion && version != ArtifactSchemaVersion && version != RemoteSchemaVersion && version != HTTPBindingSchemaVersion && version != smallBatchSchemaVersion && version != daemonSchemaVersion {
		return nil, ErrUnsupportedSchema
	}
	s.sources = sources
	return sources, nil
}
func (s *Sources) DiskUsage(ctx context.Context) (SourceDiskUsage, error) {
	var u SourceDiskUsage
	// Each PRAGMA result is read separately; an earlier scalar is not page_size.
	if err := s.store.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&u.PageSize); err != nil {
		return u, err
	}
	if err := s.store.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&u.PageCount); err != nil {
		return u, err
	}
	if u.PageSize < 512 || u.PageSize > 65536 || u.PageSize&(u.PageSize-1) != 0 || u.PageCount < 1 {
		return u, errors.New("invalid SQLite physical accounting")
	}
	for suffix, target := range map[string]*int64{"": &u.Database, "-wal": &u.WAL, "-shm": &u.SHM} {
		info, err := os.Lstat(s.store.filename + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return u, err
		}
		if !info.Mode().IsRegular() {
			return u, ErrSourceQuota
		}
		*target = info.Size()
	}
	backupDir := filepath.Join(filepath.Dir(s.store.filename), "sync-state-backups")
	d, err := os.Open(backupDir)
	if err == nil {
		defer d.Close()
		for {
			entries, e := d.Readdir(128)
			for _, entry := range entries {
				if !entry.Mode().IsRegular() {
					return u, ErrSourceQuota
				}
				u.Backup += entry.Size()
			}
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				return u, e
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return u, err
	}
	var fs syscall.Statfs_t
	if err = syscall.Statfs(filepath.Dir(s.store.filename), &fs); err != nil {
		return u, err
	}
	u.Free = int64(fs.Bavail) * int64(fs.Bsize)
	return u, nil
}
func (s *Sources) admit(ctx context.Context, reserve int64) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	u, err := s.DiskUsage(ctx)
	if err != nil {
		return err
	}
	if u.WAL+reserve > s.limits.WALBytes {
		var busy, log, checkpointed int
		if err = s.store.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed); err != nil {
			return err
		}
		u, err = s.DiskUsage(ctx)
		if err != nil {
			return err
		}
		if busy != 0 || u.WAL+reserve > s.limits.WALBytes {
			return ErrSourceQuota
		}
	}
	if reserve < 0 || u.Database+u.WAL+u.SHM+reserve > s.limits.DatabaseBytes || u.Backup > s.limits.BackupBytes || u.Free-reserve < s.limits.FreeDiskBytes {
		return ErrSourceQuota
	}
	// SQLite enforces an independent hard main-file growth bound. Reserve WAL,
	// SHM and one bounded page transaction separately from the main page count.
	maxPages := (s.limits.DatabaseBytes - s.limits.WALBytes - (1 << 20)) / u.PageSize
	if maxPages < u.PageCount {
		return ErrSourceQuota
	}
	var actual int64
	if err = s.store.db.QueryRowContext(ctx, fmt.Sprintf("PRAGMA max_page_count=%d", maxPages)).Scan(&actual); err != nil {
		return err
	}
	if actual != maxPages {
		return ErrSourceQuota
	}
	return nil
}
func (s *Sources) change(ctx context.Context, reserve int64, fn func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.admit(ctx, reserve); err != nil {
		return err
	}
	return s.store.transaction(ctx, fn)
}
