package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"pluto/internal/syncproto"
	"syscall"
)

// An expired initial read UUID is not a publication ID. Retire it only before
// any remote candidate, staged import or original operation exists. Keep the
// original file as evidence; an ambiguous/lost HTTP response never enters here.
// The caller holds the session mutex and Store's exclusive writer ownership.
func (s *IsolatedHTTPSession) retireExpiredInitialSnapshot(ctx context.Context) error {
	if _, err := s.r.Candidate(ctx, s.root); !errors.Is(err, sql.ErrNoRows) {
		return ErrRemoteUnqualified
	}
	root, err := s.r.store.Root(ctx, s.root)
	if err != nil {
		return err
	}
	if root.ActiveRemoteGeneration != 1 {
		return ErrRemoteUnqualified
	}
	var debt int
	err = s.r.store.db.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM remote_preparations WHERE root_id=?)+(SELECT COUNT(*) FROM operations WHERE root_id=?)+(SELECT COUNT(*) FROM remote_seen_bindings WHERE root_id=?)", s.root, s.root, s.root).Scan(&debt)
	if err != nil {
		return err
	}
	if debt != 0 {
		return ErrRemoteIncomplete
	}
	id, err := s.r.pendingHTTPSnapshot(s.binding)
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.r.store.filename)
	filename := filepath.Join(directory, "http-snapshot-binding-"+fingerprint(s.binding)+".json")
	if _, err = os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		filename = filepath.Join(directory, "http-snapshot-"+hashBytes([]byte(s.binding.RootID))+".json")
	} else if err != nil {
		return err
	}
	archive := filename + ".expired-" + id
	if err = os.Link(filename, archive); errors.Is(err, os.ErrExist) {
		a, ea := os.Lstat(filename)
		b, eb := os.Lstat(archive)
		if ea != nil || eb != nil || !os.SameFile(a, b) {
			return ErrIdentityConflict
		}
	} else if err != nil {
		return err
	}
	if err = os.Remove(filename); err != nil {
		return err
	}
	dir, err := os.OpenFile(directory, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Only a pending snapshot start UUID; original file operations stay exclusively
// in operations. The Store's writer lock serializes admission and restart.
func (r *RemoteImport) pendingHTTPSnapshot(binding RemoteBinding) (string, error) {
	filename := filepath.Join(filepath.Dir(r.store.filename), "http-snapshot-"+hashBytes([]byte(binding.RootID))+".json")
	scoped := filepath.Join(filepath.Dir(r.store.filename), "http-snapshot-binding-"+fingerprint(binding)+".json")
	if _, err := os.Lstat(scoped); err == nil {
		return r.pendingHTTPSnapshotFile(binding, scoped, false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return r.pendingHTTPSnapshotFile(binding, filename, true)
}

func (r *RemoteImport) pendingHTTPSnapshotFile(binding RemoteBinding, filename string, allowReviewedTransition bool) (string, error) {
	f, e := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e == nil {
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 16384 {
			return "", ErrIdentityConflict
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) {
			return "", ErrIdentityConflict
		}
		raw, e := io.ReadAll(io.LimitReader(f, 16385))
		if e != nil {
			return "", e
		}
		v, e := syncproto.Parse(raw)
		if e != nil {
			return "", e
		}
		m, e := strictHTTPObject(v, "schema", "root_id", "snapshot_id", "binding")
		if e != nil || m["schema"] != "pluto.http-snapshot-start.v1" || m["root_id"] != r.rootForHTTP(binding) {
			return "", ErrIdentityConflict
		}
		bm, ok := m["binding"].(map[string]any)
		if !ok {
			return "", ErrIdentityConflict
		}
		b, e := syncproto.ReadBinding(bm)
		if e != nil {
			return "", ErrIdentityConflict
		}
		id, e := httpText(m, "snapshot_id")
		if e != nil || !httpUUID(id) {
			return "", ErrIdentityConflict
		}
		if b != binding {
			// Keep the old snapshot identity as recovery evidence. Only the
			// reviewed offline transition may allocate a separate new binding's
			// start UUID; ordinary restart cannot silently replace it.
			var version, authorized int
			if !allowReviewedTransition || r.store.db.QueryRow("PRAGMA user_version").Scan(&version) != nil || version != daemonSchemaVersion {
				return "", ErrIdentityConflict
			}
			e = r.store.db.QueryRow("SELECT COUNT(*) FROM profile_rebinding p JOIN roots r ON r.root_id=p.root_id WHERE r.remote_root_id=? AND r.server_identity=? AND p.new_binding=? AND p.phase IN ('AUTHORIZED','RECONCILING','COMPLETE')", binding.RootID, binding.ServerIdentity, string(mustJSON(binding))).Scan(&authorized)
			if e != nil || authorized != 1 {
				return "", ErrIdentityConflict
			}
			scoped := filepath.Join(filepath.Dir(filename), "http-snapshot-binding-"+fingerprint(binding)+".json")
			return r.pendingHTTPSnapshotFile(binding, scoped, false)
		}
		return id, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	id, e := NewOperationID()
	if e != nil {
		return "", e
	}
	raw, e := httpJSON(map[string]any{"schema": "pluto.http-snapshot-start.v1", "root_id": r.rootForHTTP(binding), "snapshot_id": id, "binding": bindingHTTP(binding)})
	if e != nil {
		return "", e
	}
	temp, e := os.CreateTemp(filepath.Dir(filename), ".http-snapshot-*")
	if e != nil {
		return "", e
	}
	defer os.Remove(temp.Name())
	closed := false
	defer func() {
		if !closed {
			temp.Close()
		}
	}()
	if _, e = temp.Write(raw); e != nil {
		return "", e
	}
	if e = temp.Sync(); e != nil {
		return "", e
	}
	if e = temp.Close(); e != nil {
		return "", e
	}
	closed = true
	if e = os.Rename(temp.Name(), filename); e != nil {
		return "", e
	}
	dir, e := os.OpenFile(filepath.Dir(filename), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return "", e
	}
	defer dir.Close()
	if e = dir.Sync(); e != nil {
		return "", e
	}
	return id, nil
}

func (r *RemoteImport) rootForHTTP(b RemoteBinding) string { return b.ServerIdentity + ":" + b.RootID }
