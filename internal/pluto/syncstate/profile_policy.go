package syncstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"pluto/internal/syncproto"
)

type PolicyPreview struct {
	Schema                                                                            string `json:"schema"`
	Digest                                                                            string `json:"digest"`
	FromCodec, ToCodec                                                                string
	Entries, InvalidNames, Collisions, NewlyExcluded, NewlyIncluded, PendingOriginals int64
	CopiesRetained                                                                    bool
}

func compatibleNameKey(key, name string) bool {
	if key == name {
		return true
	}
	portable, err := syncproto.NameKey(name, "portable_v1")
	return err == nil && key == portable
}

// Read-only, bounded keyset pages. Persistent expression indexes make collision
// probes per-parent lookups, without enumerating siblings into process memory.
func (s *Store) PreviewPolicy(ctx context.Context, rootID, codec, digest string, before, after func(string) bool) (PolicyPreview, error) {
	p := PolicyPreview{Schema: "pluto.policy-plan.v1", ToCodec: codec, CopiesRetained: true}
	root, err := s.Root(ctx, rootID)
	if err != nil {
		return p, err
	}
	p.FromCodec = root.NameCodec
	if codec != "legacy" && codec != "portable_v1" || !validHash(digest) {
		return p, ErrIdentityConflict
	}
	h := sha256.New()
	h.Write(mustJSON(root))
	h.Write([]byte(digest))
	if err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations WHERE root_id=? AND stage<>'CLIENT_ACKED'", rootID).Scan(&p.PendingOriginals); err != nil {
		return p, err
	}
	for _, remote := range []bool{false, true} {
		cursor := ""
		for {
			statement := "SELECT entry_id,descriptor_json FROM local_entries WHERE root_id=? AND entry_id>? ORDER BY entry_id LIMIT 128"
			args := []any{rootID, cursor}
			if remote {
				statement = "SELECT node_id,descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id>? ORDER BY node_id LIMIT 128"
				args = []any{rootID, root.ActiveRemoteGeneration, cursor}
			}
			rows, e := s.db.QueryContext(ctx, statement, args...)
			if e != nil {
				return p, e
			}
			type item struct{ id, raw string }
			page := []item{}
			for rows.Next() {
				var v item
				if e = rows.Scan(&v.id, &v.raw); e != nil {
					rows.Close()
					return p, e
				}
				page = append(page, v)
			}
			e = errors.Join(rows.Err(), rows.Close())
			if e != nil {
				return p, e
			}
			if len(page) == 0 {
				break
			}
			for _, v := range page {
				cursor = v.id
				h.Write([]byte(v.raw))
				p.Entries++
				var name, parent, presence string
				if remote {
					var r RemoteEntry
					if json.Unmarshal([]byte(v.raw), &r) != nil {
						return p, ErrIdentityConflict
					}
					name, parent, presence = r.Name, r.ParentID, r.Presence
					if r.NodeID == root.RemoteRootID {
						continue
					}
				} else {
					var l Observation
					if json.Unmarshal([]byte(v.raw), &l) != nil {
						return p, ErrIdentityConflict
					}
					name, parent, presence = l.Name, l.ParentID, l.Presence
				}
				if presence != "PRESENT" {
					continue
				}
				key, e := syncproto.NameKey(name, codec)
				if e != nil {
					p.InvalidNames++
					continue
				}
				if codec == "portable_v1" {
					var count int64
					q := "SELECT COUNT(*) FROM local_entries WHERE root_id=? AND COALESCE(parent_id,'')=? AND lower(json_extract(descriptor_json,'$.Name'))=? AND json_extract(descriptor_json,'$.Presence')='PRESENT'"
					a := []any{rootID, parent, key}
					if remote {
						q = "SELECT COUNT(*) FROM remote_entries WHERE root_id=? AND generation=? AND json_extract(descriptor_json,'$.ParentID')=? AND lower(json_extract(descriptor_json,'$.Name'))=? AND json_extract(descriptor_json,'$.Presence')='PRESENT'"
						a = []any{rootID, root.ActiveRemoteGeneration, parent, key}
					}
					if e = s.db.QueryRowContext(ctx, q, a...).Scan(&count); e != nil {
						return p, e
					}
					if count > 1 {
						p.Collisions++
					}
				}
			}
		}
	}
	if before != nil && after != nil {
		cursor := ""
		for {
			rows, e := s.db.QueryContext(ctx, "SELECT destination FROM source_entries WHERE set_id=? AND destination>? ORDER BY destination LIMIT 128", root.SourceIdentity, cursor)
			if e != nil {
				return p, e
			}
			page := []string{}
			for rows.Next() {
				var path string
				if e = rows.Scan(&path); e != nil {
					rows.Close()
					return p, e
				}
				page = append(page, path)
			}
			e = errors.Join(rows.Err(), rows.Close())
			if e != nil {
				return p, e
			}
			if len(page) == 0 {
				break
			}
			for _, path := range page {
				cursor = path
				if before(path) && !after(path) {
					p.NewlyExcluded++
				}
				if !before(path) && after(path) {
					p.NewlyIncluded++
				}
			}
		}
	}
	h.Write(mustJSON(p))
	p.Digest = hex.EncodeToString(h.Sum(nil))
	return p, nil
}

// Called only by offline apply after exact preview acceptance and a WAL-aware
// backup. Historical original JSON/receipts are deliberately not rewritten.
func (s *Store) ApplyPolicy(ctx context.Context, root, codec, digest string, revision int64, raw []byte) error {
	if revision < 1 || !validHash(digest) || len(raw) > 65536 {
		return ErrIdentityConflict
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var pending int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations WHERE root_id=? AND stage<>'CLIENT_ACKED'", root).Scan(&pending); e != nil {
			return e
		}
		if pending != 0 {
			return ErrArtifactRetained
		}
		current, e := readRoot(ctx, tx, root)
		if e != nil {
			return e
		}
		var prior int64
		e = tx.QueryRowContext(ctx, "SELECT revision FROM profile_policy WHERE root_id=?", root).Scan(&prior)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if prior > revision {
			return ErrStaleGeneration
		}
		if prior == revision {
			var saved string
			if e = tx.QueryRowContext(ctx, "SELECT digest FROM profile_policy WHERE root_id=?", root).Scan(&saved); e != nil {
				return e
			}
			if saved != digest {
				return ErrIdentityConflict
			}
			return nil
		}
		if current.NameCodec != codec {
			// Name spelling and IDs stay exact. Only collision keys change.
			if codec != "portable_v1" && codec != "legacy" {
				return ErrIdentityConflict
			}
			expression := "json_extract(descriptor_json,'$.Name')"
			if codec == "portable_v1" {
				expression = "lower(" + expression + ")"
			}
			if _, e = tx.ExecContext(ctx, "UPDATE local_entries SET name_key="+expression+",descriptor_json=json_set(descriptor_json,'$.NameKey',"+expression+") WHERE root_id=?", root); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE baselines SET descriptor_json=json_set(descriptor_json,'$.NameKey',"+expression+") WHERE root_id=?", root); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE roots SET name_codec=? WHERE root_id=?", codec, root); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM parent_cache WHERE root_id=?", root); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO profile_policy(root_id,revision,digest,codec,policy_json) VALUES(?,?,?,?,?) ON CONFLICT(root_id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,codec=excluded.codec,policy_json=excluded.policy_json", root, revision, digest, codec, string(raw))
		return e
	})
}

func (s *Store) CheckPolicy(ctx context.Context, root, codec, digest string, revision int64, raw []byte) error {
	var old string
	err := s.db.QueryRowContext(ctx, "SELECT digest FROM profile_policy WHERE root_id=?", root).Scan(&old)
	if errors.Is(err, sql.ErrNoRows) && codec == "portable_v1" {
		var entries, operations int
		if e := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM local_entries WHERE root_id=?", root).Scan(&entries); e != nil {
			return e
		}
		if e := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM operations WHERE root_id=?", root).Scan(&operations); e != nil {
			return e
		}
		if entries != 0 || operations != 0 {
			return ErrIdentityConflict
		}
		return s.ApplyPolicy(ctx, root, codec, digest, revision, raw)
	}
	if errors.Is(err, sql.ErrNoRows) && codec == "legacy" {
		return s.transaction(ctx, func(tx *sql.Tx) error {
			current, e := readRoot(ctx, tx, root)
			if e != nil {
				return e
			}
			if current.NameCodec != "legacy" || revision < 1 || !validHash(digest) || len(raw) > 65536 {
				return ErrIdentityConflict
			}
			_, e = tx.ExecContext(ctx, "INSERT INTO profile_policy(root_id,revision,digest,codec,policy_json) VALUES(?,?,?,?,?)", root, revision, digest, codec, string(raw))
			return e
		})
	}
	if err != nil {
		return err
	}
	if old != digest {
		return ErrIdentityConflict
	}
	return nil
}
