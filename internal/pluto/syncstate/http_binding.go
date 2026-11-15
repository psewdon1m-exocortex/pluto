package syncstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"pluto/internal/syncproto"
)

const HTTPBindingSchemaVersion = 6
const httpBindingColumn = "http_binding_json TEXT CHECK(http_binding_json IS NULL OR length(CAST(http_binding_json AS BLOB))<=16384)"
const httpBindingIndexDDL = "CREATE UNIQUE INDEX http_server_upload_identity ON operations(json_extract(http_binding_json,'$.ServerUploadID')) WHERE http_binding_json IS NOT NULL"
const currentScanIndexDDL = "CREATE INDEX source_current_scan_entries ON source_membership(seen_scan_id,destination,set_id,source_id)"
const pendingRootIndexDDL = "CREATE INDEX pending_root_operations ON operations(root_id,operation_id) WHERE stage<>'CLIENT_ACKED'"

// Server IDs are acceptance metadata for the original operation. They never
// replace or rewrite its immutable intent, local ID, captured bytes or keys.
type HTTPUploadBinding struct {
	Schema, LocalOperationID, IntentFingerprint, SealedFingerprint string
	HTTPIntentHash, ServerUploadID, ServerOperationID              string
	DeviceID, BackendIdentity, RequestPath                         string
	InputBinding                                                   RemoteBinding
}

func makeHTTPUploadBinding(op Operation, serverID, inputHash string) (HTTPUploadBinding, error) {
	var value HTTPUploadBinding
	input, err := originalCatalogInput(op)
	if op.Mutation != nil && op.Mutation.Schema == "pluto.mutation-binding/v1" && hashBytes(op.Mutation.Input) == op.Mutation.InputSHA256 && serverID == op.OperationID && validHash(inputHash) {
		input.hash = inputHash
	}
	if err != nil || !httpUUID(serverID) || inputHash != input.hash || op.Stage != "SUBMITTED" && op.Stage != "CLIENT_ACKED" || !validHash(op.IntentFingerprint) || !validHash(op.SealedFingerprint) {
		return value, errors.Join(ErrInvalidReceipt, err)
	}
	if fingerprint(op.Intent) != op.IntentFingerprint || fingerprint(struct{ IntentFingerprint, SHA256 string }{op.IntentFingerprint, op.SHA256}) != op.SealedFingerprint || op.Captured.Evidence.SHA256 != op.SHA256 || op.Captured.Evidence.SnapshotID != op.SnapshotID {
		return value, ErrInvalidReceipt
	}
	t := op.Captured.Transport
	schema := "pluto.http-upload-binding/v1"
	if op.Mutation != nil {
		schema = "pluto.http-mutation-binding/v1"
	}
	return HTTPUploadBinding{Schema: schema, LocalOperationID: op.OperationID, IntentFingerprint: op.IntentFingerprint, SealedFingerprint: op.SealedFingerprint, HTTPIntentHash: inputHash, ServerUploadID: serverID, ServerOperationID: serverID, DeviceID: t.DeviceID, BackendIdentity: t.BackendIdentity, RequestPath: t.RequestPath, InputBinding: t.InputBinding}, nil
}

func validHTTPUploadBinding(op Operation, value HTTPUploadBinding) bool {
	wanted, err := makeHTTPUploadBinding(op, value.ServerUploadID, value.HTTPIntentHash)
	return err == nil && wanted == value
}

func decodeHTTPUploadBinding(raw string, op Operation) (*HTTPUploadBinding, error) {
	if len(raw) > 16384 {
		return nil, ErrInvalidReceipt
	}
	if _, err := syncproto.Parse([]byte(raw)); err != nil {
		return nil, errors.Join(ErrInvalidReceipt, err)
	}
	var value HTTPUploadBinding
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || !validHTTPUploadBinding(op, value) {
		return nil, errors.Join(ErrInvalidReceipt, err)
	}
	return &value, nil
}

func validCapturedHTTPReceipt(op Operation, binding *HTTPUploadBinding, description RemoteEntry) bool {
	if op.Captured == nil || op.Captured.Transport == nil {
		return op.HTTPBinding == nil && binding == nil
	}
	return op.HTTPBinding != nil && binding != nil && validHTTPUploadBinding(op, *binding) && *binding == *op.HTTPBinding && description.OperationID == binding.ServerOperationID
}

// BindHTTPUpload records the fully checked first prepare result before any
// append/complete. Same-value retry is idempotent; rebinding is never allowed.
func (r *RemoteImport) BindHTTPUpload(ctx context.Context, expected Operation, serverID, inputHash string) (Operation, error) {
	var result Operation
	err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		return r.bindHTTPUploadTx(ctx, tx, expected, serverID, inputHash, &result)
	})
	if err == nil {
		err = r.point("http_binding.after_commit")
	}
	return result, err
}

func (r *RemoteImport) bindHTTPUploadTx(ctx context.Context, tx *sql.Tx, expected Operation, serverID, inputHash string, result *Operation) error {
	current, err := readOperation(ctx, tx, expected.OperationID)
	if err != nil {
		return err
	}
	if current.IntentFingerprint != expected.IntentFingerprint || current.SealedFingerprint != expected.SealedFingerprint || current.Stage != "SUBMITTED" && current.Stage != "CLIENT_ACKED" {
		return ErrInvalidReceipt
	}
	binding, err := makeHTTPUploadBinding(current, serverID, inputHash)
	if err != nil {
		return err
	}
	if current.HTTPBinding != nil {
		if *current.HTTPBinding != binding {
			return ErrInvalidReceipt
		}
		*result = current
		return nil
	}
	raw, err := json.Marshal(binding)
	if err != nil || len(raw) > 16384 {
		return ErrSourceQuota
	}
	changed, err := tx.ExecContext(ctx, "UPDATE operations SET http_binding_json=? WHERE operation_id=? AND http_binding_json IS NULL", string(raw), current.OperationID)
	if err != nil {
		return err
	}
	if rows, err := changed.RowsAffected(); err != nil || rows != 1 {
		return errors.Join(ErrInvalidReceipt, err)
	}
	if err = r.point("http_binding.before_commit"); err != nil {
		return err
	}
	current.HTTPBinding = &binding
	*result = current
	return nil
}
