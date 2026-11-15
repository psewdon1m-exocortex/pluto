package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"pluto/internal/syncproto"
	"strings"
)

// ProjectSourcePath creates bounded, exact legacy namespace prefixes. Virtual
// ancestors describe the configured destination, not observed disk continuity.
// Existing captured mappings keep their independent local identity/generation.
func (r *RemoteImport) ProjectSourcePath(ctx context.Context, w SourceWitness, rootID string, source SourceEntry) (entryID string, err error) {
	if !validDestination(source.Destination) || source.Kind != "file" && source.Kind != "folder" || source.Ambiguous {
		return "", ErrSourceAmbiguous
	}
	err = r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		set, e := r.sources.checkWitness(ctx, tx, w)
		if e != nil {
			return e
		}
		root, e := readRoot(ctx, tx, rootID)
		if e != nil {
			return e
		}
		if set.AttachedRootID != rootID || root.SourceIdentity != w.SetID || root.NameCodec != "legacy" && root.NameCodec != "portable_v1" {
			return ErrIdentityConflict
		}
		current, e := readSourceEntry(ctx, tx, w.SetID, source.Destination)
		if e != nil {
			return e
		}
		if current != source || current.Presence != "PRESENT" {
			return ErrStaleGeneration
		}
		e = tx.QueryRowContext(ctx, "SELECT entry_id FROM captured_local_entries WHERE set_id=? AND destination=? AND root_id=?", w.SetID, source.Destination, rootID).Scan(&entryID)
		if e == nil {
			l, e := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", rootID, entryID)
			if e != nil {
				return e
			}
			_, path, e := localPath(ctx, tx, l)
			if e != nil {
				return e
			}
			if path != source.Destination || l.Kind != source.Kind {
				return ErrIdentityConflict
			}
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		parent := ""
		prefix := ""
		parts := strings.Split(source.Destination, "/")
		for i, name := range parts {
			key := name
			if root.NameCodec == "portable_v1" {
				var e error
				key, e = syncproto.NameKey(name, root.NameCodec)
				if e != nil {
					return e
				}
			}
			if prefix != "" {
				prefix += "/"
			}
			prefix += name
			id := "path-" + fingerprint(struct{ Domain, Root, Set, Path string }{"pluto.local-prefix/v1", rootID, w.SetID, prefix})
			kind := "folder"
			identity := "virtual-" + id
			size := int64(0)
			if i == len(parts)-1 && source.Kind == "file" {
				kind = "file"
				identity = source.FileIdentity
				size = source.SizeBytes
			}
			l, e := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", rootID, id)
			if e == nil {
				if l.ParentID != parent || l.Name != name || l.NameKey != key || l.Kind != kind || l.Presence != "PRESENT" {
					return ErrIdentityConflict
				}
			} else if errors.Is(e, sql.ErrNoRows) {
				if root.NameCodec == "portable_v1" {
					var exists bool
					if e = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM local_entries WHERE root_id=? AND COALESCE(parent_id,'')=? AND name_key=? AND json_extract(descriptor_json,'$.Presence')='PRESENT')", rootID, parent, key).Scan(&exists); e != nil {
						return e
					}
					if exists {
						return ErrIdentityConflict
					}
				}
				l = Observation{RootID: rootID, EntryID: id, ParentID: parent, Name: name, NameKey: key, Kind: kind, FileIdentity: identity, Presence: "PRESENT", Generation: 1, SizeBytes: size}
				if e = checkObservation(l); e != nil {
					return e
				}
				if _, e = tx.ExecContext(ctx, "INSERT INTO local_entries(root_id,entry_id,parent_id,name_key,generation,descriptor_json) VALUES(?,?,?,?,?,?)", rootID, id, localParentArgument(parent), key, 1, string(mustJSON(l))); e != nil {
					return e
				}
				if e = addDirty(ctx, tx, rootID, id, 1, 0, "local"); e != nil {
					return e
				}
			} else {
				return e
			}
			parent = id
			entryID = id
		}
		return nil
	})
	return entryID, err
}

func localParentArgument(parent string) any {
	if parent == "" {
		return nil
	}
	return parent
}
