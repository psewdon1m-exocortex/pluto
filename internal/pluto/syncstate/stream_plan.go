package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"
)

const StreamChunkBytes = 4 << 20

var errStreamSourceProofNeeded = errors.New("stream source requires a fresh whole-file proof")
var errStreamVerifiedNoop = errors.New("stream source agrees with current trusted remote baseline")

func (s *IsolatedHTTPSession) streamFileLimit() int64 {
	if s.features["scale-transfer-v2"] && s.streamFileBytes > 0 {
		return min(s.streamFileBytes, int64(streamV2MaximumFileBytes))
	}
	return MaxFileBytes
}

type StreamBinding struct {
	Schema       string
	Input        json.RawMessage
	InputSHA256  string
	Source       SourceEntry
	Witness      SourceWitness
	Remote       RemoteWitness
	Parents      []CapturedParentBinding
	RemoteParent string
}
type StreamChunk struct {
	Index  int    `json:"index"`
	Offset string `json:"offset"`
	Length string `json:"length"`
	SHA256 string `json:"sha256"`
}
type StreamStatus struct {
	Schema      string          `json:"schema"`
	OperationID string          `json:"operationId"`
	State       string          `json:"state"`
	Received    string          `json:"receivedSizeBytes"`
	Chunks      []StreamChunk   `json:"chunks"`
	Pending     *StreamChunk    `json:"pendingChunk"`
	FinalSHA256 *string         `json:"finalSha256"`
	Publication json.RawMessage `json:"publication"`
}

// Persist immutable identity before reading content. This permits transport,
// never publication: whole SHA and a stable source guard are required to seal.
func (s *IsolatedHTTPSession) planStream(ctx context.Context, w SourceWitness, entry SourceEntry, localID string) (*Operation, error) {
	return s.planStreamWithProof(ctx, w, entry, localID, nil)
}

func (s *IsolatedHTTPSession) planStreamWithProof(ctx context.Context, w SourceWitness, entry SourceEntry, localID string, proof *streamSourceProof) (*Operation, error) {
	if !s.features["stream-upload-v1"] || entry.SizeBytes < 2*StreamChunkBytes {
		return nil, nil
	}
	if entry.SizeBytes > s.streamFileLimit() {
		return nil, ErrSourceQuota
	}
	if entry.Kind != "file" || entry.Presence != "PRESENT" || entry.Ambiguous || entry.SetID != w.SetID {
		return nil, ErrIdentityConflict
	}
	a, err := s.Authority(ctx)
	if err != nil {
		return nil, err
	}
	var out *Operation
	verifiedNoop := false
	err = s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		set, e := s.r.sources.checkWitness(ctx, tx, w)
		if e != nil {
			return e
		}
		current, e := readSourceEntry(ctx, tx, w.SetID, entry.Destination)
		if e != nil {
			return e
		}
		if current != entry {
			return ErrStaleGeneration
		}
		pending, e := pendingCapturedEntry(ctx, tx, s.root, localID)
		if e != nil {
			return e
		}
		if len(pending) > 0 {
			return ErrArtifactRetained
		}
		root, e := readRoot(ctx, tx, s.root)
		if e != nil {
			return e
		}
		if set.AttachedRootID != s.root || root.SourceIdentity != w.SetID {
			return ErrIdentityConflict
		}
		c, e := readCandidate(ctx, tx, s.root)
		if e != nil {
			return e
		}
		if !authorityMatches(a, c.RemoteWitness, time.Now()) || root.TrustGeneration != c.TrustGeneration || root.ActiveRemoteGeneration != c.Generation {
			return ErrRemoteUnqualified
		}
		local, e := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", s.root, localID)
		if e != nil {
			return e
		}
		chain, path, e := localPath(ctx, tx, local)
		if e != nil || path != entry.Destination {
			return ErrIdentityConflict
		}
		anchor, e := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", s.root, c.Generation, c.Binding.RootID)
		if e != nil || !currentRemoteBinding(anchor, c.RemoteWitness) || anchor.Availability != "AVAILABLE" || anchor.Kind != "folder" {
			return ErrRemoteUnqualified
		}
		parent := anchor.NodeID
		parents := []CapturedParentBinding{}
		remoteChain := []RemoteEntry{anchor}
		for i := len(chain) - 1; i > 0; i-- {
			p, e := namespaceCandidate(ctx, tx, c.RemoteWitness, parent, chain[i].Name)
			if e != nil || p == nil || p.Kind != "folder" || p.Availability != "AVAILABLE" || !currentRemoteBinding(*p, c.RemoteWitness) {
				return ErrRemoteUnqualified
			}
			base, be := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", s.root, chain[i].EntryID)
			if be != nil && !errors.Is(be, sql.ErrNoRows) {
				return be
			}
			if be == nil && !sameParentTopologyBaseline(base, *p, c.RemoteWitness) {
				return ErrIdentityConflict
			}
			parents = append(parents, CapturedParentBinding{Local: chain[i], Remote: *p})
			remoteChain = append(remoteChain, *p)
			parent = p.NodeID
		}
		remote, e := namespaceCandidate(ctx, tx, c.RemoteWitness, parent, local.Name)
		if e != nil {
			return e
		}
		if remote != nil && (!currentRemoteBinding(*remote, c.RemoteWitness) || remote.Kind != "file" || remote.Presence != "PRESENT" || remote.Availability != "AVAILABLE") {
			return ErrRemoteUnqualified
		}
		base, be := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", s.root, localID)
		if be != nil && !errors.Is(be, sql.ErrNoRows) {
			return be
		}
		if remote == nil && be == nil || remote != nil && (be != nil || !sameRemoteBaseline(base, *remote, c.RemoteWitness)) {
			return nil
		}
		// Existing equal metadata is not source proof; use guarded capture to decide
		// NOOP/metadata-only instead of creating another stream for a health sweep.
		if be == nil && base.SizeBytes == entry.SizeBytes && local.MTimeNS == entry.MTimeNS && base.FileIdentity == entry.FileIdentity {
			if entry.SizeBytes <= MaxFileBytes {
				return nil
			}
			if proof == nil {
				return errStreamSourceProofNeeded
			}
			if !proof.current(entry) {
				return ErrCaptureChanged
			}
			if proof.sha256 == base.SHA256 && remote != nil && proof.sha256 == remote.SHA256 {
				if local.Kind != "file" || local.Presence != "PRESENT" || base.ParentID != local.ParentID || base.Name != local.Name || base.NameKey != local.NameKey || local.FileIdentity != entry.FileIdentity || local.SizeBytes != entry.SizeBytes || local.Generation < base.LocalGeneration {
					return ErrIdentityConflict
				}
				binding, e := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1", w.SetID, entry.SourceID)
				if e != nil || binding.IncarnationStatus != "LOCAL_OBSERVED" || binding.Incarnation != entry.SourceIncarnation {
					return ErrStaleGeneration
				}
				var request int64
				if e = tx.QueryRowContext(ctx, "SELECT request FROM source_verification WHERE set_id=? AND destination=?", w.SetID, entry.Destination).Scan(&request); e != nil || request != entry.VerificationRequest {
					return ErrStaleGeneration
				}
				// Record only the fresh local digest. This is not a publication and
				// must not invent a receipt, capture artifact or published mtime.
				local.SHA256 = proof.sha256
				local.HashGeneration = local.Generation
				if _, e = tx.ExecContext(ctx, "UPDATE local_entries SET descriptor_json=? WHERE root_id=? AND entry_id=? AND generation=?", string(mustJSON(local)), s.root, localID, local.Generation); e != nil {
					return e
				}
				if _, e = tx.ExecContext(ctx, "DELETE FROM source_verification WHERE set_id=? AND destination=? AND request=?", w.SetID, entry.Destination, entry.VerificationRequest); e != nil {
					return e
				}
				if _, e = tx.ExecContext(ctx, "DELETE FROM dirty_entries WHERE root_id=? AND entry_id=? AND observed_generation<=? AND remote_seq<=?", s.root, localID, local.Generation, c.Position); e != nil {
					return e
				}
				verifiedNoop = true
				return nil
			}
		}
		id, e := NewOperationID()
		if e != nil {
			return e
		}
		var target, content, none any
		condition := map[string]any{"kind": "absent"}
		absent := remote == nil
		if absent {
			none = "*"
		} else {
			target = remote.NodeID
			content = remote.ContentVersionID
			condition = map[string]any{"kind": "match", "nodeId": remote.NodeID, "metadataVersion": remote.Version}
		}
		topology := make([]map[string]any, 0, len(remoteChain))
		for i := len(remoteChain) - 1; i >= 0; i-- {
			p := remoteChain[i]
			var pid any
			if p.ParentID != "" {
				pid = p.ParentID
			}
			topology = append(topology, map[string]any{"nodeId": p.NodeID, "parentId": pid, "name": p.Name})
		}
		b := c.Binding
		intent := map[string]any{"schema": "saturn.upload-intent.v2", "deviceKind": "pluto", "deviceId": s.identity.DeviceID, "rootId": b.RootID, "requestPath": "/" + entry.Destination, "idempotencyKey": "pluto-sync-" + id, "parentId": parent, "name": local.Name, "targetId": target, "sizeBytes": remoteDecimal(entry.SizeBytes), "sha256": nil, "ifMatch": nil, "ifNoneMatch": none, "requireAbsent": absent, "expectedVersionId": content, "condition": condition, "parentTopology": topology}
		input := map[string]any{"schema": "saturn.stream-upload.v1", "operationId": id, "source": map[string]any{"generation": remoteDecimal(entry.Generation), "witnessSha256": fingerprint(entry)}, "chunkBytes": StreamChunkBytes, "prepare": map[string]any{"epoch": b.ServerEpoch, "bindingVersion": b.BindingVersion, "backendIdentity": s.identity.BackendIdentity, "intent": intent}}
		originalSchema := "pluto.stream-original/v1"
		if s.features["scale-transfer-v2"] {
			input["schema"] = "saturn.stream-upload.v2"
			originalSchema = "pluto.stream-original/v2"
		}
		raw, e := httpJSON(input)
		if e != nil || len(raw) > HTTPMetadataBytes {
			return ErrSourceQuota
		}
		before := local.Generation
		if before == math.MaxInt64 {
			return ErrSourceQuota
		}
		local.Generation++
		local.ExpectedGeneration = before
		local.FileIdentity = entry.FileIdentity
		local.SizeBytes = entry.SizeBytes
		local.MTimeNS = entry.MTimeNS
		local.HashGeneration = 0
		local.SHA256 = ""
		if _, e = tx.ExecContext(ctx, "UPDATE local_entries SET generation=?,descriptor_json=? WHERE root_id=? AND entry_id=? AND generation=?", local.Generation, string(mustJSON(local)), s.root, localID, before); e != nil {
			return e
		}
		op := Operation{Intent: Intent{OperationID: id, RootID: s.root, EntryID: localID, Kind: "STREAM_PUT", ExpectedEpoch: b.ServerEpoch, ParentID: local.ParentID, Name: local.Name, NameKey: local.NameKey, FileIdentity: entry.FileIdentity, LocalGeneration: local.Generation, TrustGeneration: root.TrustGeneration, SizeBytes: entry.SizeBytes, ExpectedAbsent: absent, Stream: &StreamBinding{Schema: "pluto.stream-original/v1", Input: raw, InputSHA256: hashBytes(raw), Source: entry, Witness: w, Remote: c.RemoteWitness, Parents: parents, RemoteParent: parent}}, Stage: "SUBMITTED"}
		if remote != nil {
			op.ExpectedNodeID = remote.NodeID
			op.ExpectedVersion = remote.Version
		}
		op.Stream.Schema = originalSchema
		op.IntentFingerprint = fingerprint(op.Intent)
		if _, e = tx.ExecContext(ctx, "INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,?,?,?,?,?,?,'SUBMITTED')", id, s.root, localID, op.LocalGeneration, op.Kind, string(mustJSON(op.Intent)), op.IntentFingerprint); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO stream_progress(operation_id) VALUES(?)", id); e != nil {
			return e
		}
		out = &op
		return nil
	})
	if err == nil && verifiedNoop {
		return nil, errStreamVerifiedNoop
	}
	return out, err
}
