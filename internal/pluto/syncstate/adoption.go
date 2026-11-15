package syncstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// This snapshot is an adoption fence, never permission to publish. It exposes
// counts and bindings, while hashing originals without printing their payloads.
type AdoptionState struct {
	SchemaVersion                                            int            `json:"schemaVersion"`
	Digest                                                   string         `json:"digest"`
	Root                                                     Root           `json:"root"`
	Remote                                                   *RemoteBinding `json:"remote,omitempty"`
	Pending, Acknowledged, Unresolved, IncompatibleOriginals int64
	Compatible                                               bool `json:"compatible"`
	RequiresRebind                                           bool `json:"requiresRebind"`
}

func (s *Store) PreviewAdoption(ctx context.Context, expected RootBinding, binding RemoteBinding, identity CapturedHTTPIdentity, codec string, allowRebind bool) (AdoptionState, error) {
	var out AdoptionState
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&out.SchemaVersion); err != nil {
		return out, err
	}
	out.Root, err = readRoot(ctx, tx, expected.RootID)
	if err != nil {
		return out, err
	}
	out.Compatible = out.Root.RootBinding == expected && out.Root.NameCodec == codec && !out.Root.AllowsDelete && out.Root.MaxFileBytes == MaxFileBytes && out.Root.MaxActiveVersions == MaxActiveVersions
	hash := sha256.New()
	hash.Write(mustJSON(out.Root))
	if out.SchemaVersion >= RemoteSchemaVersion {
		remote, e := readCandidate(ctx, tx, expected.RootID)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return out, e
		}
		if e == nil {
			out.Remote = &remote.Binding
			hash.Write(mustJSON(remote))
			out.RequiresRebind = remote.Binding != binding
			if out.RequiresRebind && !allowRebind || remote.HTTPRebootstrap != nil {
				out.Compatible = false
			}
		}
	}
	after := ""
	for {
		rows, e := tx.QueryContext(ctx, "SELECT operation_id,intent_json,intent_fingerprint,sealed_fingerprint,stage,receipt_json FROM operations WHERE root_id=? AND operation_id>? ORDER BY operation_id LIMIT 128", expected.RootID, after)
		if e != nil {
			return out, e
		}
		count, bytes := 0, 0
		for rows.Next() {
			var id, raw, fingerprint, stage string
			var seal, receipt sql.NullString
			if e = rows.Scan(&id, &raw, &fingerprint, &seal, &stage, &receipt); e != nil {
				rows.Close()
				return out, e
			}
			bytes += len(raw) + len(receipt.String)
			if bytes > MaxSourcePageBytes {
				rows.Close()
				return out, ErrSourceQuota
			}
			count++
			after = id
			hash.Write(mustJSON([]any{id, raw, fingerprint, seal.String, stage, receipt.String}))
			if stage == "CLIENT_ACKED" {
				out.Acknowledged++
				continue
			}
			out.Pending++
			// All unresolved originals require status reconciliation; absence of an ACK
			// is never converted into an inferred remote failure or a new operation ID.
			out.Unresolved++
			var intent Intent
			if json.Unmarshal([]byte(raw), &intent) != nil {
				rows.Close()
				return out, ErrIdentityConflict
			}
			var original *CapturedHTTPIdentity
			if intent.Captured != nil {
				original = intent.Captured.Transport
			}
			if intent.FolderHTTP != nil {
				original = &intent.FolderHTTP.Identity
			}
			compatible := true
			if original != nil {
				v := *original
				b := v.InputBinding
				v.InputBinding = RemoteBinding{}
				v.RequestPath = ""
				compatible = v == identity && b == binding
			} else if intent.Stream != nil {
				compatible = intent.Stream.Remote.Binding == binding
			} else {
				compatible = false
			}
			if !compatible {
				out.IncompatibleOriginals++
				out.Compatible = false
			}
		}
		e = errors.Join(rows.Err(), rows.Close())
		if e != nil {
			return out, e
		}
		if count < 128 {
			break
		}
	}
	if out.RequiresRebind && out.Pending > 0 {
		out.Compatible = false
	}
	hash.Write(mustJSON(out))
	out.Digest = hex.EncodeToString(hash.Sum(nil))
	return out, tx.Commit()
}
