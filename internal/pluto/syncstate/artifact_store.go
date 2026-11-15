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

	"golang.org/x/sys/unix"
)

const artifactSchema = `
CREATE TABLE artifact_scope(singleton INTEGER PRIMARY KEY CHECK(singleton=1),scope_id TEXT NOT NULL UNIQUE,directory_identity TEXT NOT NULL,owner_id TEXT NOT NULL,owner_sequence INTEGER NOT NULL CHECK(owner_sequence>0));
CREATE TABLE local_artifacts(artifact_id TEXT PRIMARY KEY,filename TEXT NOT NULL UNIQUE,phase TEXT NOT NULL CHECK(phase IN('RESERVED','CAPTURING','SEALED','DISPOSING','GONE')),expected_bytes INTEGER NOT NULL CHECK(expected_bytes BETWEEN 0 AND 268435456),size_bytes INTEGER NOT NULL DEFAULT 0 CHECK(size_bytes BETWEEN 0 AND 268435456),file_identity TEXT NOT NULL DEFAULT '',sha256 TEXT NOT NULL DEFAULT '',snapshot_id TEXT NOT NULL DEFAULT '',operation_id TEXT UNIQUE REFERENCES operations(operation_id),capture_json TEXT NOT NULL DEFAULT '');
CREATE INDEX retained_artifacts ON local_artifacts(artifact_id) WHERE phase<>'GONE';
CREATE INDEX gone_artifacts ON local_artifacts(artifact_id) WHERE phase='GONE';
CREATE INDEX artifact_operation_snapshot ON operations(snapshot_id,operation_id) WHERE snapshot_id<>'';
`

type Artifacts struct {
	store                        *Store
	sources                      *Sources
	mu                           sync.Mutex
	directory                    *os.File
	path, scope, owner, identity string
	sequence                     int64
	directoryGeneration          int64
	limits                       ArtifactLimits
	ready, closed                bool
	live                         map[string]*ArtifactReservation // At most two active captures/read users.
	reader                       func(context.Context) (func(), error)
	quarantinedEmpty             int64
	crashPoint                   func(string) // Internal fixture hook, nil in every product caller.
}

type ArtifactReservation struct {
	registry *Artifacts
	id       string
	writable *os.File
	users    int
	closed   bool
	disposed bool // Successful disposal remains idempotent after GONE-row pruning.
}

// promoteCapturedProof is called with the snapshot/registry locks and the source
// transaction. It changes only an unbound sealed capture's observed generation;
// captured bytes, IDs, guards and immutable network operations remain unchanged.
func (a *Artifacts) promoteCapturedProof(ctx context.Context, tx *sql.Tx, v *VerifiedSnapshot, next SnapshotEvidence, root string) error {
	if err := a.validate(ctx, tx); err != nil {
		return err
	}
	row, err := readArtifact(ctx, tx, v.evidence.SnapshotID)
	if err != nil {
		return err
	}
	var raw string
	if err = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(capture_json)<=16384 THEN capture_json ELSE '' END FROM local_artifacts WHERE artifact_id=?", row.ID).Scan(&raw); err != nil {
		return err
	}
	var before artifactCapture
	if json.Unmarshal([]byte(raw), &before) != nil || before.SnapshotEvidence != v.evidence || before.SourceFileIdentity != v.sourceIdentity || row.Phase != ArtifactSealed || row.SnapshotID != v.evidence.SnapshotID || row.SHA256 != v.evidence.SHA256 || row.SizeBytes != v.evidence.SizeBytes || row.FileIdentity != artifactIdentity(v.sealed) || v.filename != filepath.Join(a.path, row.Name) {
		return ErrIdentityConflict
	}
	if next == v.evidence {
		return nil
	}
	comparison := next
	comparison.EntryGeneration = v.evidence.EntryGeneration
	if comparison != v.evidence || next.EntryGeneration != v.evidence.EntryGeneration+1 || row.OperationID != "" {
		return ErrStaleGeneration
	}
	if _, err = artifactOperation(ctx, tx, row); !errors.Is(err, sql.ErrNoRows) {
		if err != nil {
			return err
		}
		return ErrArtifactRetained
	}
	if root != "" {
		var pending string
		// Before captured-entry projection exists, a local entry ID is not the
		// source destination. Conservatively refuse while any root intent is
		// pending; the partial index makes this a bounded lookup.
		err = tx.QueryRowContext(ctx, "SELECT operation_id FROM operations WHERE root_id=? AND stage<>'CLIENT_ACKED' LIMIT 1", root).Scan(&pending)
		if err == nil {
			return ErrArtifactRetained
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	updated, err := json.Marshal(artifactCapture{next, v.sourceIdentity})
	if err != nil || len(updated) > 16384 {
		return errors.Join(ErrSourceQuota, err)
	}
	result, err := tx.ExecContext(ctx, "UPDATE local_artifacts SET capture_json=? WHERE artifact_id=? AND phase=? AND operation_id IS NULL AND capture_json=?", string(updated), row.ID, ArtifactSealed, raw)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrStaleGeneration
	}
	return nil
}

func (s *Store) EnableArtifacts(ctx context.Context, limits ArtifactLimits) (*Artifacts, error) {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	if limits.Records < 1 || limits.Records > MaxArtifactRecords || limits.PlaintextBytes < 0 || limits.PlaintextBytes > MaxFileBytes {
		return nil, ErrSourceQuota
	}
	if s.artifacts != nil {
		if s.artifacts.limits != limits || s.artifacts.closed {
			return nil, ErrIdentityConflict
		}
		return s.artifacts, nil
	}
	if s.sources == nil {
		return nil, errors.New("enable local sources explicitly before artifact registry")
	}
	// Capabilities start at the actual configured state directory. A final
	// symlink, foreign owner, writable public directory or linked database is
	// refused before optional schema mutation or artifact creation.
	stateFD, err := unix.Open(filepath.Dir(s.filename), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	stateDirectory := os.NewFile(uintptr(stateFD), filepath.Dir(s.filename))
	defer stateDirectory.Close()
	stateInfo, err := stateDirectory.Stat()
	if err != nil {
		return nil, err
	}
	stateStat, ok := stateInfo.Sys().(*syscall.Stat_t)
	dbInfo, err := os.Lstat(s.filename)
	if err != nil {
		return nil, err
	}
	dbStat, dbOK := dbInfo.Sys().(*syscall.Stat_t)
	if !ok || !dbOK || stateStat.Uid != uint32(os.Geteuid()) || stateInfo.Mode().Perm()&0022 != 0 || dbStat.Uid != uint32(os.Geteuid()) || dbStat.Nlink != 1 || !dbInfo.Mode().IsRegular() || dbInfo.Mode().Perm()&0077 != 0 {
		return nil, ErrIdentityConflict
	}
	if err := s.sources.admit(ctx, MaxSourcePageBytes); err != nil {
		return nil, err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version == SourceSchemaVersion {
		// A populated unregistered namespace is not ours to migrate/adopt.
		if fd, e := unix.Openat(int(stateDirectory.Fd()), ArtifactDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); e == nil {
			check := os.NewFile(uintptr(fd), ArtifactDirectoryName)
			entries, readErr := check.ReadDir(1)
			closeErr := check.Close()
			if len(entries) != 0 {
				return nil, ErrArtifactUnreconciled
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return nil, readErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		u, err := s.sources.DiskUsage(ctx)
		if err != nil {
			return nil, err
		}
		projected := u.PageCount * u.PageSize
		if u.Backup+projected > s.sources.limits.BackupBytes || u.Free-projected < s.sources.limits.FreeDiskBytes {
			return nil, ErrSourceQuota
		}
		backup, err := backupVersion(ctx, filepath.Dir(s.filename), s.filename, SourceSchemaVersion)
		if err != nil {
			return nil, err
		}
		if backup == nil {
			return nil, ErrUnsupportedSchema
		}
		manifest, _ := json.Marshal(map[string]any{"fromVersion": SourceSchemaVersion, "toVersion": ArtifactSchemaVersion, "backup": backup.Filename, "backupSHA256": backup.SHA256, "module": "local-artifacts/v1", "engineActivated": false})
		if err = s.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
			var current int
			if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
				return err
			}
			if current != SourceSchemaVersion {
				return ErrStaleGeneration
			}
			if _, err := tx.ExecContext(ctx, artifactSchema); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", ArtifactSchemaVersion)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at,manifest_json) VALUES(?,?,?)", ArtifactSchemaVersion, time.Now().UTC().Format(time.RFC3339Nano), string(manifest))
			return err
		}); err != nil {
			return nil, err
		}
	} else if version != ArtifactSchemaVersion && version != RemoteSchemaVersion && version != HTTPBindingSchemaVersion && version != smallBatchSchemaVersion && version != daemonSchemaVersion {
		return nil, ErrUnsupportedSchema
	}
	path := filepath.Join(filepath.Dir(s.filename), ArtifactDirectoryName)
	if err := unix.Mkdirat(int(stateDirectory.Fd()), ArtifactDirectoryName, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	fd, err := unix.Openat(int(stateDirectory.Fd()), ArtifactDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	keep := false
	defer func() {
		if !keep {
			dir.Close()
		}
	}()
	info, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
		return nil, ErrIdentityConflict
	}
	a := &Artifacts{store: s, sources: s.sources, directory: dir, path: path, identity: statIdentity(info), limits: limits, live: make(map[string]*ArtifactReservation)}
	a.owner, err = NewOperationID()
	if err != nil {
		return nil, err
	}
	err = s.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT scope_id,directory_identity,owner_sequence FROM artifact_scope WHERE singleton=1").Scan(&a.scope, &a.identity, &a.sequence)
		if errors.Is(err, sql.ErrNoRows) {
			entries, e := dir.ReadDir(1)
			if e != nil && !errors.Is(e, io.EOF) {
				return e
			}
			if len(entries) != 0 {
				return ErrArtifactUnreconciled
			}
			a.scope, err = NewOperationID()
			if err != nil {
				return err
			}
			a.sequence = 1
			a.identity = statIdentity(info)
			_, err = tx.ExecContext(ctx, "INSERT INTO artifact_scope VALUES(1,?,?,?,?)", a.scope, a.identity, a.owner, a.sequence)
			return err
		}
		if err != nil {
			return err
		}
		if a.identity != statIdentity(info) {
			return ErrIdentityConflict
		}
		a.sequence++
		_, err = tx.ExecContext(ctx, "UPDATE artifact_scope SET owner_id=?,owner_sequence=? WHERE singleton=1", a.owner, a.sequence)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = dir.Sync(); err != nil {
		return nil, err
	}
	err = stateDirectory.Sync()
	if err != nil {
		return nil, err
	}
	s.artifacts = a
	keep = true
	return a, nil
}

func (a *Artifacts) Directory() string { return a.path }
func (a *Artifacts) Scope() string     { return a.scope + ":" + a.owner }

// ProfileScope is durable across writer sessions. Scope still identifies the
// current owner so a detached handle cannot release a later session's budget.
func (a *Artifacts) ProfileScope() string { return a.scope }
func (a *Artifacts) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if len(a.live) != 0 {
		return ErrArtifactInUse
	}
	a.closed = true
	a.ready = false
	return a.directory.Close()
}
func (a *Artifacts) validate(ctx context.Context, q queryer) error {
	if a.closed || ctx.Err() != nil {
		return errors.Join(ErrStaleGeneration, ctx.Err())
	}
	var owner, identity string
	var sequence int64
	if err := q.QueryRowContext(ctx, "SELECT owner_id,owner_sequence,directory_identity FROM artifact_scope WHERE singleton=1").Scan(&owner, &sequence, &identity); err != nil {
		return err
	}
	if owner != a.owner || sequence != a.sequence || identity != a.identity {
		return ErrStaleGeneration
	}
	info, err := a.directory.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(a.path)
	if err != nil || !os.SameFile(info, current) || statIdentity(info) != identity || current.Mode().Perm() != 0700 {
		return errors.Join(ErrIdentityConflict, err)
	}
	if a.ready && a.directoryGeneration != statCTime(info) {
		a.ready = false
		return ErrArtifactUnreconciled
	}
	return nil
}
func readArtifact(ctx context.Context, q queryer, id string) (r ArtifactRecord, err error) {
	err = q.QueryRowContext(ctx, "SELECT CASE WHEN length(artifact_id)=36 THEN artifact_id ELSE '' END,CASE WHEN length(filename)<=64 THEN filename ELSE '' END,phase,expected_bytes,size_bytes,CASE WHEN length(file_identity)<=128 THEN file_identity ELSE '' END,CASE WHEN length(sha256)<=64 THEN sha256 ELSE '' END,CASE WHEN length(snapshot_id)<=36 THEN snapshot_id ELSE '' END,CASE WHEN length(operation_id)<=128 THEN operation_id ELSE '' END FROM local_artifacts WHERE artifact_id=?", id).Scan(&r.ID, &r.Name, &r.Phase, &r.ExpectedBytes, &r.SizeBytes, &r.FileIdentity, &r.SHA256, &r.SnapshotID, &r.OperationID)
	return
}
func (a *Artifacts) Record(ctx context.Context, id string) (ArtifactRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(ctx, a.store.db); err != nil {
		return ArtifactRecord{}, err
	}
	return readArtifact(ctx, a.store.db, id)
}
func (a *Artifacts) aggregate(ctx context.Context, q queryer) (count, charge int64, err error) {
	err = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN phase='GONE' THEN 0 ELSE expected_bytes END),0) FROM (SELECT phase,expected_bytes FROM local_artifacts ORDER BY artifact_id LIMIT ?)", a.limits.Records+1).Scan(&count, &charge)
	if err == nil {
		var packets int64
		packets, err = smallBatchReservedBytes(ctx, q)
		charge += packets
	}
	return
}
func (a *Artifacts) Reserve(ctx context.Context, size int64) (*ArtifactReservation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.ready || len(a.live) >= 2 {
		return nil, ErrArtifactUnreconciled
	}
	if size < 0 || size > MaxFileBytes {
		return nil, ErrSourceQuota
	}
	if err := a.validate(ctx, a.store.db); err != nil {
		return nil, err
	}
	id, err := NewOperationID()
	if err != nil {
		return nil, err
	}
	err = a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if err := a.validate(ctx, tx); err != nil {
			return err
		}
		count, charge, err := a.aggregate(ctx, tx)
		if err != nil {
			return err
		}
		if count >= int64(a.limits.Records) || size > a.limits.PlaintextBytes-charge {
			return ErrSourceQuota
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO local_artifacts(artifact_id,filename,phase,expected_bytes) VALUES(?,?,?,?)", id, id+".snapshot", ArtifactReserved, size)
		return err
	})
	if err != nil {
		return nil, err
	}
	if a.crashPoint != nil {
		a.crashPoint("reserved")
	}
	r := &ArtifactReservation{registry: a, id: id}
	a.live[id] = r
	return r, nil
}
func (r *ArtifactReservation) ID() string { return r.id }
func (r *ArtifactReservation) Create(ctx context.Context) (*os.File, error) {
	a := r.registry
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.closed || a.live[r.id] != r || r.writable != nil {
		return nil, ErrStaleGeneration
	}
	if err := a.validate(ctx, a.store.db); err != nil {
		return nil, err
	}
	record, err := readArtifact(ctx, a.store.db, r.id)
	if err != nil {
		return nil, err
	}
	if record.Phase != ArtifactReserved {
		return nil, ErrIdentityConflict
	}
	fd, err := unix.Openat(int(a.directory.Fd()), record.Name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(a.path, record.Name))
	r.writable = f
	if a.crashPoint != nil {
		a.crashPoint("created")
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err = a.directory.Sync(); err != nil {
		return nil, err
	}
	current, err := a.directory.Stat()
	if err != nil {
		return nil, err
	}
	a.directoryGeneration = statCTime(current)
	// Once the file exists, cancellation must not strand an unregistered inode.
	// Finish only its durable identity checkpoint on a bounded cleanup context;
	// the canceled capture still stops before consuming source bytes. Namespace,
	// owner and reservation guards remain mandatory on this joined writer.
	registration, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err = a.sources.change(registration, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if err := a.validate(registration, tx); err != nil {
			return err
		}
		_, err := tx.ExecContext(registration, "UPDATE local_artifacts SET phase=?,file_identity=? WHERE artifact_id=? AND phase=?", ArtifactCapturing, artifactIdentity(info), r.id, ArtifactReserved)
		return err
	})
	if err == nil && a.crashPoint != nil {
		a.crashPoint("registered")
	}
	if err == nil {
		err = a.checkNamespace(registration)
		if err != nil {
			a.ready = false
		}
	}
	if err == nil {
		err = context.Cause(ctx)
	}
	return f, err // On failure the row/file/charge remain for reconciliation.
}
