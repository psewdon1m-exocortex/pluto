package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"pluto/internal/syncproto"
)

func (s *IsolatedHTTPSession) ackStream(ctx context.Context, op Operation, status StreamStatus) error {
	if status.State != "PUBLISHED" || status.FinalSHA256 == nil || *status.FinalSHA256 != op.SHA256 || op.SHA256 == "" || status.Received != remoteDecimal(op.SizeBytes) {
		return ErrArtifactRetained
	}
	value, err := syncproto.Parse(status.Publication)
	if err != nil {
		return err
	}
	outer, ok := value.(map[string]any)
	if !ok {
		return ErrInvalidReceipt
	}
	result, ok := outer["result"].(map[string]any)
	if !ok {
		return ErrInvalidReceipt
	}
	inputHash, err := streamSealedIntentHash(op)
	if err != nil {
		return err
	}
	session, ok := outer["session"].(map[string]any)
	if !ok || session["intentHash"] != inputHash || session["operationId"] != op.OperationID || session["uploadId"] != op.OperationID || session["rootId"] != op.Stream.Remote.Binding.RootID || session["expectedSizeBytes"] != remoteDecimal(op.SizeBytes) || session["receivedSizeBytes"] != remoteDecimal(op.SizeBytes) || session["transferPending"] != false {
		return ErrInvalidReceipt
	}
	if result["status"] != "PUBLISHED" || result["operationId"] != op.OperationID || result["uploadId"] != op.OperationID || result["rootId"] != op.Stream.Remote.Binding.RootID {
		return ErrInvalidReceipt
	}
	d, err := syncproto.ReadDescriptor(result["publishedDescription"])
	if err != nil {
		return err
	}
	if d.Type != "file" || d.Availability != "AVAILABLE" || d.ParentID == nil || *d.ParentID != op.Stream.RemoteParent || d.Name != op.Name || d.ContentSHA256 == nil || *d.ContentSHA256 != op.SHA256 || d.ContentVersionID == nil || d.SizeBytes != remoteDecimal(op.SizeBytes) || !op.ExpectedAbsent && d.NodeID != op.ExpectedNodeID {
		return ErrInvalidReceipt
	}
	first, err := syncproto.Integer64(result["firstSeq"])
	if err != nil {
		return err
	}
	last, err := syncproto.Integer64(result["lastSeq"])
	if err != nil || first < 1 || last < first {
		return ErrInvalidReceipt
	}
	rc, ok := result["publicationReceipt"].(map[string]any)
	if session["phase"] != "published" || result["schema"] != "saturn.catalog-upload-result.v2" || rc["uploadId"] != op.OperationID || rc["etag"] != fmt.Sprintf("\"sha256-%s\"", op.SHA256) {
		return ErrInvalidReceipt
	}
	stamp, ok := rc["publishedAt"].(string)
	if !ok {
		return ErrInvalidReceipt
	}
	published, parseErr := time.Parse("2006-01-02T15:04:05.000Z", stamp)
	if parseErr != nil || published.Format("2006-01-02T15:04:05.000Z") != stamp {
		return ErrInvalidReceipt
	}
	if result["intentHash"] != inputHash || rc["intentHash"] != inputHash {
		return ErrInvalidReceipt
	}
	if !ok || rc["schema"] != "saturn.upload-publication.v1" || rc["operationId"] != op.OperationID || rc["rootId"] != op.Stream.Remote.Binding.RootID || rc["resourceId"] != d.NodeID || rc["versionId"] != *d.ContentVersionID || rc["sha256"] != op.SHA256 || rc["sizeBytes"] != remoteDecimal(op.SizeBytes) || rc["parentId"] != *d.ParentID || rc["name"] != op.Name {
		return ErrInvalidReceipt
	}
	if err = s.Refresh(ctx); err != nil {
		return err
	}
	err = s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		original, e := readOperation(ctx, tx, op.OperationID)
		if e != nil {
			return e
		}
		if original.IntentFingerprint != op.IntentFingerprint || original.SHA256 != op.SHA256 || original.SealedFingerprint != op.SealedFingerprint {
			return ErrInvalidReceipt
		}
		var verified bool
		if e = tx.QueryRowContext(ctx, "SELECT source_verified FROM stream_progress WHERE operation_id=?", op.OperationID).Scan(&verified); e != nil || !verified {
			return ErrInvalidReceipt
		}
		if original.Stage == "CLIENT_ACKED" {
			return nil
		}
		old, e := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && (old.LocalGeneration > op.LocalGeneration || old.LastSeq >= last) {
			return ErrInvalidReceipt
		}
		binding := op.Stream.Remote.Binding
		b := Baseline{RootID: op.RootID, EntryID: op.EntryID, NodeID: d.NodeID, Epoch: binding.ServerEpoch, Version: d.Version, SHA256: op.SHA256, Kind: "file", Presence: "PRESENT", OperationID: op.OperationID, ParentID: op.ParentID, Name: op.Name, NameKey: op.NameKey, FileIdentity: op.FileIdentity, LocalGeneration: op.LocalGeneration, TrustGeneration: op.TrustGeneration, SizeBytes: op.SizeBytes, LastSeq: last, RemoteBinding: &binding, RemoteParentID: op.Stream.RemoteParent, ContentVersionID: *d.ContentVersionID}
		if _, e = tx.ExecContext(ctx, "INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?) ON CONFLICT(root_id,entry_id) DO UPDATE SET node_id=excluded.node_id,descriptor_json=excluded.descriptor_json", op.RootID, op.EntryID, d.NodeID, string(mustJSON(b))); e != nil {
			return e
		}
		source, e := readSourceEntry(ctx, tx, op.Stream.Source.SetID, op.Stream.Source.Destination)
		if e == nil && source == op.Stream.Source {
			local, e := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
			if e != nil {
				return e
			}
			if local.Generation == op.LocalGeneration {
				local.SHA256 = op.SHA256
				local.HashGeneration = local.Generation
				if _, e = tx.ExecContext(ctx, "UPDATE local_entries SET descriptor_json=? WHERE root_id=? AND entry_id=?", string(mustJSON(local)), op.RootID, op.EntryID); e != nil {
					return e
				}
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM source_verification WHERE set_id=? AND destination=? AND request=?", source.SetID, source.Destination, source.VerificationRequest); e != nil {
				return e
			}
		}
		for _, p := range op.Stream.Parents {
			l := p.Local
			r := p.Remote
			pb := Baseline{RootID: op.RootID, EntryID: l.EntryID, NodeID: r.NodeID, Epoch: r.Epoch, Version: r.Version, Kind: "folder", Presence: "PRESENT", ParentID: l.ParentID, Name: l.Name, NameKey: l.NameKey, FileIdentity: l.FileIdentity, LocalGeneration: l.Generation, TrustGeneration: op.TrustGeneration, LastSeq: r.LastSeq, RemoteBinding: &binding, RemoteParentID: r.ParentID}
			if _, e = tx.ExecContext(ctx, "INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?) ON CONFLICT(root_id,entry_id) DO NOTHING", op.RootID, l.EntryID, r.NodeID, string(mustJSON(pb))); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM operation_retry WHERE operation_id=?", op.OperationID); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, "UPDATE operations SET stage='CLIENT_ACKED',receipt_json=? WHERE operation_id=?", string(mustJSON(status)), op.OperationID)
		return e
	})
	if err != nil {
		return err
	}
	return s.r.afterContentAck(ctx, op.OperationID)
}

func streamSealedIntentHash(op Operation) (string, error) {
	var input struct {
		Prepare struct {
			Intent map[string]any `json:"intent"`
		} `json:"prepare"`
	}
	if op.Stream == nil || hashBytes(op.Stream.Input) != op.Stream.InputSHA256 || json.Unmarshal(op.Stream.Input, &input) != nil {
		return "", ErrIdentityConflict
	}
	i := input.Prepare.Intent
	canonical := []any{i["schema"], i["deviceKind"], i["idempotencyKey"], i["deviceId"], i["rootId"], i["requestPath"], i["parentId"], i["name"], i["targetId"], i["sizeBytes"], op.SHA256, i["ifMatch"], i["ifNoneMatch"], i["requireAbsent"], i["expectedVersionId"]}
	condition, ok := i["condition"].(map[string]any)
	if !ok {
		return "", ErrInvalidReceipt
	}
	canonical = append(canonical, condition["kind"])
	if condition["kind"] == "match" {
		canonical = append(canonical, condition["nodeId"], condition["metadataVersion"])
	} else if condition["kind"] != "absent" {
		return "", ErrInvalidReceipt
	}
	topology, ok := i["parentTopology"].([]any)
	if !ok {
		return "", ErrInvalidReceipt
	}
	triples := make([]any, 0, len(topology))
	for _, value := range topology {
		p, ok := value.(map[string]any)
		if !ok {
			return "", ErrInvalidReceipt
		}
		triples = append(triples, []any{p["nodeId"], p["parentId"], p["name"]})
	}
	canonical = append(canonical, triples)
	raw, err := httpJSON(canonical)
	if err != nil {
		return "", err
	}
	return hashBytes(raw), nil
}
