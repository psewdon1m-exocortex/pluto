package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

func readOperation(ctx context.Context, q queryer, id string) (Operation, error) {
	var value Operation
	var raw string
	err := q.QueryRowContext(ctx, `SELECT intent_json,stage,sha256,snapshot_id,intent_fingerprint,sealed_fingerprint FROM operations WHERE operation_id=?`, id).Scan(&raw, &value.Stage, &value.SHA256, &value.SnapshotID, &value.IntentFingerprint, &value.SealedFingerprint)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &value.Intent)
	}
	if err == nil {
		var version int
		err = q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
		if err == nil && (version == HTTPBindingSchemaVersion || (version == smallBatchSchemaVersion || version == daemonSchemaVersion)) {
			var binding sql.NullString
			err = q.QueryRowContext(ctx, "SELECT http_binding_json FROM operations WHERE operation_id=?", id).Scan(&binding)
			if err == nil && binding.Valid {
				value.HTTPBinding, err = decodeHTTPUploadBinding(binding.String, value)
			}
		}
	}
	return value, err
}

func (s *Store) Operation(ctx context.Context, id string) (Operation, error) {
	return readOperation(ctx, s.db, id)
}

func moduleFiveOperations(ctx context.Context, tx *sql.Tx) (bool, error) {
	var version int
	err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	return version == RemoteSchemaVersion || version == HTTPBindingSchemaVersion || (version == smallBatchSchemaVersion || version == daemonSchemaVersion), err
}

// A retained B is evidence, not permission to overwrite. Authorization requires
// the current trust generation and an authoritative R with a contiguous cursor.
func validateBaselineRemote(ctx context.Context, tx *sql.Tx, root Root, base Baseline) error {
	if base.RemoteBinding != nil {
		// Module5 candidate imports do not establish server authority for this
		// legacy operation path. Future Send must use the qualified adapter.
		return ErrRemoteUnqualified
	}
	if base.TrustGeneration != root.TrustGeneration {
		return ErrStaleGeneration
	}
	cursor, err := readCursor(ctx, tx, root.RootID, "remote")
	if err != nil {
		return err
	}
	if !cursor.Valid || cursor.Epoch != base.Epoch {
		return errors.New("remote baseline requires reconciliation")
	}
	remote, err := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", root.RootID, root.ActiveRemoteGeneration, base.NodeID)
	if err != nil {
		return errors.New("remote baseline requires authoritative observation")
	}
	if remote.Generation != root.ActiveRemoteGeneration || remote.Epoch != base.Epoch || remote.LastSeq > cursor.Position || remote.LastSeq < base.LastSeq || remote.Version != base.Version || remote.Kind != base.Kind || remote.Presence != base.Presence || remote.SizeBytes != base.SizeBytes || remote.SHA256 != base.SHA256 || remote.Name != base.Name {
		return errors.New("remote changed since baseline; reconciliation required")
	}
	return nil
}

func validateCurrentLocal(ctx context.Context, tx *sql.Tx, op Operation) (Observation, error) {
	entry, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
	if err != nil {
		return entry, err
	}
	if entry.Generation != op.LocalGeneration {
		return entry, ErrStaleGeneration
	}
	if entry.Presence != "PRESENT" || entry.ParentID != op.ParentID || entry.Name != op.Name || entry.NameKey != op.NameKey || entry.FileIdentity != op.FileIdentity || entry.SizeBytes != op.SizeBytes {
		return entry, ErrStaleGeneration
	}
	if entry.SHA256 != "" && entry.HashGeneration == entry.Generation && op.SHA256 != "" && entry.SHA256 != op.SHA256 {
		return entry, ErrIdentityConflict
	}
	return entry, nil
}

func validateCurrentBase(ctx context.Context, tx *sql.Tx, root Root, op Operation) error {
	base, err := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
	if errors.Is(err, sql.ErrNoRows) {
		if !op.ExpectedAbsent {
			return ErrStaleGeneration
		}
		return nil
	}
	if err != nil {
		return err
	}
	if op.ExpectedAbsent || op.ExpectedVersion != base.Version || op.ExpectedEpoch != base.Epoch || op.ExpectedNodeID != base.NodeID {
		return ErrStaleGeneration
	}
	return validateBaselineRemote(ctx, tx, root, base)
}

// Plan fixes the operation ID and immutable intent before any network I/O.
// Expected versions come from B, never from the latest R. Unknown B permits
// only create-only planning; differing existing data needs later adoption.
func (s *Store) Plan(ctx context.Context, intent Intent) error {
	// Captured proof may only be minted by the exact private-capture transaction.
	if intent.Captured != nil || intent.FolderHTTP != nil {
		return ErrRemoteUnqualified
	}
	if !validID(intent.OperationID) || !validID(intent.RootID) || !validID(intent.EntryID) || intent.LocalGeneration < 1 || intent.TrustGeneration < 1 || intent.SizeBytes < 0 || intent.SizeBytes > MaxFileBytes || (intent.Kind != "PUT" && intent.Kind != "ENSURE_DIRECTORY") {
		return errors.New("operation intent violates Pluto backup bounds/policy")
	}
	if err := checkBatch(len(intent.Dependencies)); err != nil {
		return err
	}
	intent.Dependencies = append([]string{}, intent.Dependencies...)
	slices.Sort(intent.Dependencies)
	for i, id := range intent.Dependencies {
		if !validID(id) || id == intent.OperationID || (i > 0 && id == intent.Dependencies[i-1]) {
			return errors.New("operation dependency invalid")
		}
	}
	intentHash := fingerprint(intent)
	return s.transaction(ctx, func(tx *sql.Tx) error {
		old, err := readOperation(ctx, tx, intent.OperationID)
		if err == nil {
			if old.IntentFingerprint != intentHash {
				return ErrIdentityConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if enabled, err := moduleFiveOperations(ctx, tx); err != nil {
			return err
		} else if enabled {
			return ErrRemoteUnqualified
		}
		root, err := readRoot(ctx, tx, intent.RootID)
		if err != nil {
			return err
		}
		if root.TrustGeneration != intent.TrustGeneration {
			return ErrStaleGeneration
		}
		entry, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", intent.RootID, intent.EntryID)
		if err != nil {
			return err
		}
		if entry.Generation != intent.LocalGeneration {
			return ErrStaleGeneration
		}
		if entry.Presence != "PRESENT" || entry.SizeBytes != intent.SizeBytes || entry.ParentID != intent.ParentID || entry.Name != intent.Name || entry.NameKey != intent.NameKey || entry.FileIdentity != intent.FileIdentity || (intent.Kind == "PUT" && entry.Kind != "file") || (intent.Kind == "ENSURE_DIRECTORY" && (entry.Kind != "folder" || intent.SizeBytes != 0)) {
			return errors.New("operation does not describe a present observed object")
		}
		base, err := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", intent.RootID, intent.EntryID)
		if errors.Is(err, sql.ErrNoRows) {
			if !intent.ExpectedAbsent || intent.ExpectedVersion != "" || intent.ExpectedEpoch != "" || intent.ExpectedNodeID != "" {
				return errors.New("unknown baseline allows only create-only intent")
			}
		} else if err != nil {
			return err
		} else {
			if intent.ExpectedAbsent || intent.ExpectedVersion != base.Version || intent.ExpectedEpoch != base.Epoch || intent.ExpectedNodeID != base.NodeID {
				return errors.New("operation expected version must come from the baseline")
			}
			if err = validateBaselineRemote(ctx, tx, root, base); err != nil {
				return err
			}
		}
		for _, id := range intent.Dependencies {
			dependency, err := readOperation(ctx, tx, id)
			if err != nil || dependency.RootID != intent.RootID {
				return errors.New("dependency must be a prior operation in this root")
			}
		}
		var existing string
		err = tx.QueryRowContext(ctx, "SELECT operation_id FROM operations WHERE root_id=? AND entry_id=? AND local_generation=? AND kind=?", intent.RootID, intent.EntryID, intent.LocalGeneration, intent.Kind).Scan(&existing)
		if err == nil {
			return ErrIdentityConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		raw, _ := json.Marshal(intent)
		if _, err = tx.ExecContext(ctx, `INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,?,?,?,?,?,?,'PLANNED')`, intent.OperationID, intent.RootID, intent.EntryID, intent.LocalGeneration, intent.Kind, string(raw), intentHash); err != nil {
			return err
		}
		for _, id := range intent.Dependencies {
			if _, err = tx.ExecContext(ctx, "INSERT INTO operation_dependencies(operation_id,dependency_id) VALUES(?,?)", intent.OperationID, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) Seal(ctx context.Context, id, sha, snapshot string) error {
	if !validID(id) || !validID(snapshot) {
		return errors.New("sealed snapshot identity invalid")
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return err
		}
		if (op.Kind == "PUT" && !validHash(sha)) || (op.Kind == "ENSURE_DIRECTORY" && sha != "") {
			return errors.New("sealed content checksum invalid")
		}
		sealedHash := fingerprint(struct{ IntentFingerprint, SHA256 string }{op.IntentFingerprint, sha})
		if op.Stage != "PLANNED" {
			if op.SealedFingerprint != sealedHash || op.SnapshotID != snapshot {
				return ErrIdentityConflict
			}
			return nil
		}
		entry, err := validateCurrentLocal(ctx, tx, op)
		if err != nil {
			return err
		}
		if entry.SHA256 != "" && entry.HashGeneration == entry.Generation && entry.SHA256 != sha {
			return ErrIdentityConflict
		}
		_, err = tx.ExecContext(ctx, "UPDATE operations SET stage='SEALED',sha256=?,snapshot_id=?,sealed_fingerprint=? WHERE operation_id=?", sha, snapshot, sealedHash, id)
		return err
	})
}

// Submitted is durable before the executor attempts transport. It does not
// authorize activating an engine, bypassing scopes, or trusting metadata skips.
func (s *Store) Submitted(ctx context.Context, id string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return err
		}
		if op.FolderHTTP != nil {
			return ErrRemoteUnqualified
		}
		root, err := readRoot(ctx, tx, op.RootID)
		if err != nil {
			return err
		}
		if root.TrustGeneration != op.TrustGeneration {
			return ErrStaleGeneration
		}
		if _, err = validateCurrentLocal(ctx, tx, op); err != nil {
			return err
		}
		if op.Stage == "CLIENT_ACKED" {
			return nil
		}
		if enabled, err := moduleFiveOperations(ctx, tx); err != nil {
			return err
		} else if enabled {
			return ErrRemoteUnqualified
		}
		if err = validateCurrentBase(ctx, tx, root, op); err != nil {
			return err
		}
		if op.Stage == "SUBMITTED" {
			return nil
		}
		if op.Stage != "SEALED" {
			return errors.New("operation must be sealed before transport")
		}
		var pending int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_dependencies d JOIN operations p ON p.operation_id=d.dependency_id WHERE d.operation_id=? AND p.stage<>'CLIENT_ACKED'`, id).Scan(&pending); err != nil {
			return err
		}
		if pending != 0 {
			return errors.New("operation parent dependencies are not acknowledged")
		}
		_, err = tx.ExecContext(ctx, "UPDATE operations SET stage='SUBMITTED' WHERE operation_id=?", id)
		return err
	})
}

// Ack is the receipt-based baseline-changing path. The receipt must confirm publication
// of the sealed bytes for this exact operation and observed generation.
func (s *Store) Ack(ctx context.Context, receipt Receipt) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		op, err := readOperation(ctx, tx, receipt.OperationID)
		if err != nil {
			return err
		}
		if op.Captured != nil || op.FolderHTTP != nil || receipt.CapturedResult != nil {
			return ErrRemoteUnqualified
		}
		if !receipt.Published || (op.Kind == "PUT" && !receipt.ContentVerified) || receipt.RootID != op.RootID || receipt.EntryID != op.EntryID || receipt.LocalGeneration != op.LocalGeneration || receipt.SizeBytes != op.SizeBytes || receipt.SHA256 != op.SHA256 || receipt.SealedFingerprint != op.SealedFingerprint || !validID(receipt.NodeID) || !validID(receipt.Version) || !validID(receipt.Epoch) || receipt.Seq < 1 {
			return ErrInvalidReceipt
		}
		if !op.ExpectedAbsent && (receipt.NodeID != op.ExpectedNodeID || receipt.Epoch != op.ExpectedEpoch) {
			return ErrInvalidReceipt
		}
		rawReceipt, _ := json.Marshal(receipt)
		if op.Stage == "CLIENT_ACKED" {
			var existing string
			if err = tx.QueryRowContext(ctx, "SELECT receipt_json FROM operations WHERE operation_id=?", op.OperationID).Scan(&existing); err != nil {
				return err
			}
			if existing != string(rawReceipt) {
				return ErrInvalidReceipt
			}
			return nil
		}
		if op.Stage != "SUBMITTED" {
			return ErrInvalidReceipt
		}
		old, err := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
		if err == nil && old.LocalGeneration >= op.LocalGeneration {
			return ErrInvalidReceipt
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		kind := "file"
		if op.Kind == "ENSURE_DIRECTORY" {
			kind = "folder"
		}
		base := Baseline{RootID: op.RootID, EntryID: op.EntryID, NodeID: receipt.NodeID, Epoch: receipt.Epoch, Version: receipt.Version, SHA256: receipt.SHA256, Kind: kind, Presence: "PRESENT", OperationID: op.OperationID, LocalGeneration: op.LocalGeneration, TrustGeneration: op.TrustGeneration, SizeBytes: op.SizeBytes, LastSeq: receipt.Seq, ParentID: op.ParentID, Name: op.Name, NameKey: op.NameKey, FileIdentity: op.FileIdentity}
		raw, _ := json.Marshal(base)
		if _, err = tx.ExecContext(ctx, `INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?) ON CONFLICT(root_id,entry_id) DO UPDATE SET node_id=excluded.node_id,descriptor_json=excluded.descriptor_json`, op.RootID, op.EntryID, receipt.NodeID, string(raw)); err != nil {
			return err
		}
		root, err := readRoot(ctx, tx, op.RootID)
		if err != nil {
			return err
		}
		remote, remoteErr := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", op.RootID, root.ActiveRemoteGeneration, receipt.NodeID)
		if remoteErr != nil && !errors.Is(remoteErr, sql.ErrNoRows) {
			return remoteErr
		}
		if remoteErr == nil && remote.LastSeq > receipt.Seq {
			entry, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
			if err != nil {
				return err
			}
			if err = addDirty(ctx, tx, op.RootID, op.EntryID, entry.Generation, remote.LastSeq, "remote"); err != nil {
				return err
			}
		}
		candidateModule, err := moduleFiveOperations(ctx, tx)
		if err != nil {
			return err
		}
		if root.TrustGeneration == op.TrustGeneration && !candidateModule {
			if _, err = tx.ExecContext(ctx, `DELETE FROM dirty_entries WHERE root_id=? AND entry_id=? AND observed_generation<=? AND remote_seq<=?`, op.RootID, op.EntryID, op.LocalGeneration, receipt.Seq); err != nil {
				return err
			}
		} else {
			entry, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
			if err != nil {
				return err
			}
			if err = addDirty(ctx, tx, op.RootID, op.EntryID, entry.Generation, receipt.Seq, "local"); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE operations SET stage='CLIENT_ACKED',receipt_json=? WHERE operation_id=?", string(rawReceipt), op.OperationID)
		return err
	})
}

func (s *Store) PendingPage(ctx context.Context, root, after string, limit int) ([]Operation, error) {
	if limit < 1 || limit > MaxBatch {
		return nil, errors.New("operation page limit invalid")
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	bindingColumn := "NULL"
	if version == HTTPBindingSchemaVersion || (version == smallBatchSchemaVersion || version == daemonSchemaVersion) {
		bindingColumn = "http_binding_json"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT intent_json,stage,sha256,snapshot_id,intent_fingerprint,sealed_fingerprint,`+bindingColumn+` FROM operations WHERE root_id=? AND operation_id>? AND stage<>'CLIENT_ACKED' ORDER BY operation_id LIMIT ?`, root, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]Operation, 0, limit)
	pageBytes := 0
	for rows.Next() {
		var value Operation
		var raw string
		var binding sql.NullString
		if err = rows.Scan(&raw, &value.Stage, &value.SHA256, &value.SnapshotID, &value.IntentFingerprint, &value.SealedFingerprint, &binding); err != nil {
			return nil, err
		}
		pageBytes += len(raw) + len(binding.String)
		if pageBytes > MaxSourcePageBytes {
			return nil, ErrSourceQuota
		}
		if err = json.Unmarshal([]byte(raw), &value.Intent); err != nil {
			return nil, err
		}
		if binding.Valid {
			value.HTTPBinding, err = decodeHTTPUploadBinding(binding.String, value)
			if err != nil {
				return nil, err
			}
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
