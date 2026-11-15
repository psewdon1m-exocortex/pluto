package syncstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type ArtifactDirectoryRestore struct {
	Schema                    string `json:"schema"`
	BackupSHA256              string `json:"backupSha256"`
	ScopeID                   string `json:"scopeId"`
	PreviousDirectoryIdentity string `json:"previousDirectoryIdentity"`
	DirectoryIdentity         string `json:"directoryIdentity"`
	Changed                   bool   `json:"changed"`
}

// RestoreArtifactDirectory transfers custody of a drained v8 profile to its
// restored directory. Normal opens still require the recorded inode. Keep the
// reviewed backup separate from the destination before running this command.
func RestoreArtifactDirectory(ctx context.Context, directory, backupSHA string, binding RootBinding) (out ArtifactDirectoryRestore, err error) {
	if digest, e := hex.DecodeString(backupSHA); e != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != backupSHA {
		return out, errors.New("the restored database requires its exact lowercase SHA-256")
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return out, err
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return out, err
	}
	if resolved != directory {
		return out, ErrIdentityConflict
	}
	state, err := openRestoreDirectory(directory)
	if err != nil {
		return out, err
	}
	defer state.Close()
	lock, err := lockStateWriter(directory)
	if err != nil {
		return out, err
	}
	defer lock.Close()

	filename := filepath.Join(directory, "sync-state.sqlite")
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, e := os.Lstat(filename + suffix)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return out, e
		}
		if !info.Mode().IsRegular() || info.Size() != 0 {
			return out, errors.New("restore requires a standalone checkpointed SQLite backup")
		}
	}
	if err = verifyRestoredDatabase(filename, backupSHA); err != nil {
		return out, err
	}
	if err = preflight(ctx, filename); err != nil {
		return out, err
	}
	// Preserve the backup's journal mode, including when admission refuses it.
	db, err := openStateDB(filename, false, false)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return out, err
	}
	if version != daemonSchemaVersion {
		return out, ErrUnsupportedSchema
	}
	var actual RootBinding
	if err = tx.QueryRowContext(ctx, "SELECT root_id,mapping_id,server_identity,remote_root_id,device_id,source_identity FROM roots WHERE root_id=?", binding.RootID).
		Scan(&actual.RootID, &actual.MappingID, &actual.ServerIdentity, &actual.RemoteRootID, &actual.DeviceID, &actual.SourceIdentity); err != nil {
		return out, err
	}
	if actual != binding {
		return out, ErrIdentityConflict
	}
	var outstanding bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM local_artifacts WHERE phase<>'GONE')
		OR EXISTS(SELECT 1 FROM small_batch_groups WHERE phase<>'GONE')
		OR EXISTS(SELECT 1 FROM operations WHERE stage<>'CLIENT_ACKED')
		OR EXISTS(SELECT 1 FROM profile_rebinding WHERE phase<>'COMPLETE')`).Scan(&outstanding)
	if err != nil {
		return out, err
	}
	if outstanding {
		return out, ErrArtifactRetained
	}
	for _, spool := range []string{filepath.Join(directory, "spool"), filepath.Join(filepath.Dir(directory), "spool")} {
		d, e := openRestoreDirectory(spool)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return out, e
		}
		e = requireEmptyRestoreDirectory(d)
		d.Close()
		if e != nil {
			return out, e
		}
	}
	var scope, previous string
	if err = tx.QueryRowContext(ctx, "SELECT scope_id,directory_identity FROM artifact_scope WHERE singleton=1").Scan(&scope, &previous); err != nil {
		return out, err
	}
	if err = unix.Mkdirat(int(state.Fd()), ArtifactDirectoryName, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return out, err
	}
	artifactDir, err := openRestoreDirectory(filepath.Join(directory, ArtifactDirectoryName))
	if err != nil {
		return out, err
	}
	defer artifactDir.Close()
	if err = requireEmptyRestoreDirectory(artifactDir); err != nil {
		return out, err
	}
	info, err := artifactDir.Stat()
	if err != nil {
		return out, err
	}
	current := statIdentity(info)
	if current == "" || previous == "" || scope == "" {
		return out, ErrIdentityConflict
	}
	if current != previous {
		if err = artifactDir.Sync(); err != nil {
			return out, err
		}
		if err = state.Sync(); err != nil {
			return out, err
		}
		update, e := tx.ExecContext(ctx, "UPDATE artifact_scope SET directory_identity=? WHERE singleton=1 AND scope_id=? AND directory_identity=?", current, scope, previous)
		if e != nil {
			return out, e
		}
		if count, e := update.RowsAffected(); e != nil || count != 1 {
			return out, errors.Join(ErrIdentityConflict, e)
		}
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return ArtifactDirectoryRestore{"pluto.artifact-directory-restore.v1", backupSHA, scope, previous, current, current != previous}, nil
}

func openRestoreDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
		f.Close()
		return nil, ErrIdentityConflict
	}
	return f, nil
}

func requireEmptyRestoreDirectory(dir *os.File) error {
	names, err := dir.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) != 0 {
		return ErrArtifactRetained
	}
	return nil
}

func verifyRestoredDatabase(path, expected string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Size() <= 0 || info.Size() > DefaultSourceLimits().DatabaseBytes {
		return ErrIdentityConflict
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(f, info.Size()+1))
	if err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, after) || after.Size() != info.Size() || statCTime(after) != statCTime(info) || count != info.Size() ||
		hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("restored SQLite backup SHA-256 or file identity changed")
	}
	return nil
}
