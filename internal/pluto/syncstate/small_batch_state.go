package syncstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// Transport references carry no separate upload stage, receipt or baseline.
// Original operation rows remain the only authority for each item's identity.
type smallBatchRecord struct {
	ID, Root, Scope, Phase, Name, DirectoryIdentity, FileIdentity, SHA256 string
	Revision, ExpectedBytes                                               int64
	Plan                                                                  *smallBatchPlan
}

func smallBatchOriginal(ctx context.Context, q queryer, id string, retained *int) (Operation, error) {
	var size int
	if err := q.QueryRowContext(ctx, "SELECT length(CAST(intent_json AS BLOB)) FROM operations WHERE operation_id=?", id).Scan(&size); err != nil {
		return Operation{}, err
	}
	if size < 1 || size > HTTPMetadataBytes || *retained > smallBatchMaximumMetadataBytes-size {
		return Operation{}, ErrSourceQuota
	}
	op, err := readOperation(ctx, q, id)
	if err != nil {
		return op, err
	}
	raw, err := json.Marshal(op)
	if err != nil {
		return op, err
	}
	if len(raw) > HTTPMetadataBytes || *retained > smallBatchMaximumMetadataBytes-len(raw) {
		return Operation{}, ErrSourceQuota
	}
	*retained += len(raw)
	return op, nil
}

type smallBatchQuery interface {
	queryer
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readSmallBatchRecord(ctx context.Context, q smallBatchQuery, id string, caches ...*smallJobProofCache) (record smallBatchRecord, err error) {
	if !smallBatchToken(id) {
		return record, ErrIdentityConflict
	}
	var manifest []byte
	var digest string
	err = q.QueryRowContext(ctx, "SELECT root_id,artifact_scope,phase,revision,manifest,manifest_sha256,expected_bytes,filename,directory_identity,file_identity,aggregate_sha256 FROM small_batch_groups WHERE batch_id=? AND length(manifest)<=4194304", id).Scan(&record.Root, &record.Scope, &record.Phase, &record.Revision, &manifest, &digest, &record.ExpectedBytes, &record.Name, &record.DirectoryIdentity, &record.FileIdentity, &record.SHA256)
	if err != nil {
		return
	}
	record.ID = id
	if !validHash(digest) || hashBytes(manifest) != digest || len(record.Name) != 42 || record.Name[36:] != ".batch" || !artifactUUID(record.Name[:36]) || record.Revision < 1 || record.Revision == math.MaxInt64 || record.ExpectedBytes < 0 || record.ExpectedBytes > smallBatchMaximumDataBytes {
		return record, ErrIdentityConflict
	}
	switch record.Phase {
	case "RESERVED":
		if record.FileIdentity != "" || record.DirectoryIdentity != "" || record.SHA256 != "" {
			return record, ErrIdentityConflict
		}
	case "BUILDING":
		if record.FileIdentity == "" || record.DirectoryIdentity == "" || record.SHA256 != "" {
			return record, ErrIdentityConflict
		}
	case "READY", "ATTEMPTED":
		if record.FileIdentity == "" || record.DirectoryIdentity == "" || !validHash(record.SHA256) {
			return record, ErrIdentityConflict
		}
	case "DISPOSING", "GONE":
		// A never-created reservation or interrupted owned build may retire
		// only after native cleanup proves absence/identity and retains originals.
		if (record.FileIdentity == "") != (record.DirectoryIdentity == "") || record.SHA256 != "" && (!validHash(record.SHA256) || record.FileIdentity == "") {
			return record, ErrIdentityConflict
		}
	default:
		return record, ErrIdentityConflict
	}
	var version int
	if err = q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return
	}
	if version != smallBatchSchemaVersion && version != daemonSchemaVersion {
		return record, ErrUnsupportedSchema
	}
	// One bounded join reads the current originals in this same transaction.
	// The SQL length guards prevent an oversized damaged row from being loaded.
	rows, err := q.QueryContext(ctx, `SELECT m.ordinal,m.operation_id,m.source_generation,m.source_identity,m.offset_bytes,m.size_bytes,m.active,
 length(CAST(o.intent_json AS BLOB)),CASE WHEN length(CAST(o.intent_json AS BLOB))<=40960 THEN o.intent_json END,
 o.stage,o.sha256,o.snapshot_id,o.intent_fingerprint,o.sealed_fingerprint,
 length(CAST(o.http_binding_json AS BLOB)),CASE WHEN length(CAST(o.http_binding_json AS BLOB))<=40960 THEN o.http_binding_json END
 FROM small_batch_members m LEFT JOIN operations o ON o.operation_id=m.operation_id
 WHERE m.batch_id=? ORDER BY m.ordinal LIMIT 501`, id)
	if err != nil {
		return record, err
	}
	defer rows.Close()
	originals := make([]Operation, 0, 16)
	proofHash := sha256.New()
	proofHash.Write([]byte(digest))
	var offset int64
	retained := 0
	for rows.Next() {
		if len(originals) == smallBatchMaximumItems {
			return record, ErrIdentityConflict
		}
		var operation, identity string
		var generation, start, size int64
		var ordinal, active int
		var intentSize, bindingSize sql.NullInt64
		var raw, binding, stage, sha, snapshot, intentHash, sealedHash sql.NullString
		if err = rows.Scan(&ordinal, &operation, &generation, &identity, &start, &size, &active,
			&intentSize, &raw, &stage, &sha, &snapshot, &intentHash, &sealedHash, &bindingSize, &binding); err != nil {
			return record, err
		}
		if ordinal != len(originals) || !intentSize.Valid || !stage.Valid {
			return record, ErrIdentityConflict
		}
		if !raw.Valid || intentSize.Int64 < 1 || intentSize.Int64 > HTTPMetadataBytes || bindingSize.Int64 > HTTPMetadataBytes {
			return record, ErrSourceQuota
		}
		op := Operation{Stage: stage.String, SHA256: sha.String, SnapshotID: snapshot.String, IntentFingerprint: intentHash.String, SealedFingerprint: sealedHash.String}
		if err = json.Unmarshal([]byte(raw.String), &op.Intent); err != nil {
			return record, err
		}
		if binding.Valid {
			if op.HTTPBinding, err = decodeHTTPUploadBinding(binding.String, op); err != nil {
				return record, err
			}
		}
		encoded, e := json.Marshal(op)
		if e != nil || len(encoded) > HTTPMetadataBytes || retained > smallBatchMaximumMetadataBytes-len(encoded) {
			return record, errors.Join(ErrSourceQuota, e)
		}
		retained += len(encoded)
		originalHash := sha256.Sum256(encoded)
		proofHash.Write(originalHash[:])
		if op.OperationID != operation || op.RootID != record.Root || op.LocalGeneration != generation || op.SizeBytes != size || op.Captured == nil || fingerprint(op.Captured) != identity || start != offset || active != 1 && record.Phase != "GONE" || active != 0 && record.Phase == "GONE" {
			return record, ErrIdentityConflict
		}
		offset += size
		originals = append(originals, op)
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return record, err
	}
	if len(originals) == 0 || offset != record.ExpectedBytes {
		return record, ErrIdentityConflict
	}
	var cache *smallJobProofCache
	if len(caches) == 1 {
		cache = caches[0]
	}
	key := fmt.Sprintf("%x", proofHash.Sum(nil))
	var cached bool
	record.Plan, cached, err = cache.get(id, key, originals)
	if err != nil {
		return record, err
	}
	if !cached {
		record.Plan, err = restoreSmallBatchPlan(manifest, originals)
	}
	if err == nil && (record.Plan.id != id || record.Plan.dataBytes != record.ExpectedBytes) {
		err = ErrIdentityConflict
	}
	if err == nil && !cached {
		cache.put(key, record.Plan)
	}
	return
}

func (s *smallBatchStore) read(ctx context.Context, id string) (record smallBatchRecord, err error) {
	err = s.remote.store.transaction(ctx, func(tx *sql.Tx) error {
		var e error
		record, e = readSmallBatchRecord(ctx, tx, id, &s.proofs)
		return e
	})
	return
}

func (s *smallBatchStore) reserve(ctx context.Context, plan *smallBatchPlan) (record smallBatchRecord, err error) {
	if plan == nil || len(plan.entries) < 1 {
		return record, ErrIdentityConflict
	}
	r := s.remote
	a := r.store.artifacts
	if a == nil {
		return record, ErrArtifactUnreconciled
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.ready {
		return record, ErrArtifactUnreconciled
	}
	if err = a.validate(ctx, r.store.db); err != nil {
		return
	}
	fileID, e := NewOperationID()
	if e != nil {
		return record, e
	}
	// Account for manifest, member rows, indexes and WAL, never a root-sized list.
	persisted := plan.persistedBytes()
	reserve := int64(2*len(persisted) + len(plan.entries)*1024 + 64*1024)
	err = r.sources.change(ctx, reserve, func(tx *sql.Tx) error {
		if e := a.validate(ctx, tx); e != nil {
			return e
		}
		var version int
		if e := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
			return e
		}
		if version != smallBatchSchemaVersion && version != daemonSchemaVersion {
			return ErrUnsupportedSchema
		}
		old, e := readSmallBatchRecord(ctx, tx, plan.id, &s.proofs)
		if e == nil {
			if old.Scope != a.scope || !bytes.Equal(old.Plan.persistedBytes(), persisted) {
				return ErrIdentityConflict
			}
			record = old
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		// A missing member must not make an existing damaged row look absent.
		var existing int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM small_batch_groups WHERE batch_id=?", plan.id).Scan(&existing); e != nil {
			return e
		}
		if existing != 0 {
			return ErrIdentityConflict
		}
		var rows, live int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN phase='GONE' THEN 0 ELSE 1 END),0) FROM (SELECT phase FROM small_batch_groups LIMIT 65)").Scan(&rows, &live); e != nil {
			return e
		}
		_, charge, e := a.aggregate(ctx, tx)
		if e != nil {
			return e
		}
		if rows >= 64 || live >= 4 || plan.dataBytes > a.limits.PlaintextBytes-charge {
			return ErrSourceQuota
		}
		originals := make([]Operation, 0, len(plan.entries))
		root := plan.entries[0].original.RootID
		retained := 0
		for _, entry := range plan.entries {
			op, e := smallBatchOriginal(ctx, tx, entry.original.OperationID, &retained)
			if e != nil {
				return e
			}
			if op.RootID != root || op.Stage != "SUBMITTED" || op.IntentFingerprint != entry.original.IntentFingerprint || op.SealedFingerprint != entry.original.SealedFingerprint {
				return ErrIdentityConflict
			}
			artifact, e := readArtifact(ctx, tx, op.SnapshotID)
			if e != nil {
				return e
			}
			bound, e := artifactOperation(ctx, tx, artifact)
			if e != nil || artifact.Phase != ArtifactSealed || bound.OperationID != op.OperationID {
				return errors.Join(ErrIdentityConflict, e)
			}
			var active int
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM small_batch_members WHERE operation_id=? AND active=1", op.OperationID).Scan(&active); e != nil {
				return e
			}
			if active != 0 {
				return ErrArtifactInUse
			}
			originals = append(originals, op)
		}
		actual, e := restoreSmallBatchPlan(persisted, originals)
		if e != nil {
			return e
		}
		if actual.id != plan.id || actual.rules != plan.rules || actual.dataBytes != plan.dataBytes || actual.binding != plan.binding || actual.executionJob != plan.executionJob || !bytes.Equal(actual.manifest, plan.manifest) {
			return ErrIdentityConflict
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO small_batch_groups(batch_id,root_id,artifact_scope,phase,revision,manifest,manifest_sha256,expected_bytes,filename) VALUES(?,?,?,'RESERVED',1,?,?,?,?)", plan.id, root, a.scope, persisted, hashBytes(persisted), plan.dataBytes, fileID+".batch"); e != nil {
			return e
		}
		var offset int64
		for n, entry := range actual.entries {
			op := entry.original
			if _, e = tx.ExecContext(ctx, "INSERT INTO small_batch_members(batch_id,ordinal,operation_id,source_generation,source_identity,offset_bytes,size_bytes,active) VALUES(?,?,?,?,?,?,?,1)", plan.id, n, op.OperationID, op.LocalGeneration, entry.sourceIdentity, offset, op.SizeBytes); e != nil {
				return e
			}
			offset += op.SizeBytes
		}
		if e = r.point("small_batch.reserve.before_commit"); e != nil {
			return e
		}
		// All inserted members came from this transaction's verified originals.
		// No operation or manifest was changed by the two inserts above. Return
		// their exact checked values instead of decoding the new rows again.
		record = smallBatchRecord{ID: plan.id, Root: root, Scope: a.scope, Phase: "RESERVED", Revision: 1,
			ExpectedBytes: plan.dataBytes, Name: fileID + ".batch", Plan: actual}
		return nil
	})
	if err == nil {
		err = r.point("small_batch.reserve.after_commit")
	}
	return
}
