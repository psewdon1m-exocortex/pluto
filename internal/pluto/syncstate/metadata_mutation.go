package syncstate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"pluto/internal/syncproto"
)

type MutationChoice struct {
	Kind       string
	Namespace  map[string]any
	Source     map[string]any
	ModifiedAt string
	MTimeNS    int64
}
type MutationBinding struct {
	Schema      string
	Input       json.RawMessage
	Namespace   json.RawMessage
	InputSHA256 string
	Kind        string `json:",omitempty"`
	MTimeNS     int64  `json:",omitempty"`
}

func makeMutationBinding(op Intent, choice *MutationChoice) (*MutationBinding, error) {
	if op.Captured == nil || op.Captured.Transport == nil || choice == nil {
		return nil, ErrIdentityConflict
	}
	if choice.Kind != "create-empty" && choice.Kind != "clone-content" && choice.Kind != "metadata-patch" {
		return nil, ErrIdentityConflict
	}
	if choice.Kind == "create-empty" && op.SizeBytes != 0 {
		return nil, ErrIdentityConflict
	}
	b := op.Captured.Transport.InputBinding
	topology, err := (Operation{Intent: op}).ParentTopology()
	if err != nil {
		return nil, err
	}
	expected := map[string]any{"kind": "absent"}
	if !op.ExpectedAbsent {
		expected = map[string]any{"kind": "version", "node_id": op.ExpectedNodeID, "version": op.ExpectedVersion}
	}
	input := map[string]any{"schema": "saturn.namespace-mutation.v1", "operationId": op.OperationID, "idempotencyKey": "pluto-mutation-" + op.OperationID, "rootId": b.RootID, "epoch": b.ServerEpoch, "bindingVersion": b.BindingVersion, "expected": expected, "kind": choice.Kind, "parentId": topology[0].NodeID, "name": op.Name}
	if choice.Kind == "metadata-patch" {
		if op.ExpectedAbsent || op.Captured.DecisionKind != "NOOP_CAPTURED" || !httpUUID(op.Captured.ExpectedContentVersionID) {
			return nil, ErrIdentityConflict
		}
		delete(input, "parentId")
		delete(input, "name")
		input["contentVersionId"] = op.Captured.ExpectedContentVersionID
		input["sha256"] = op.Captured.Evidence.SHA256
		input["modifiedAt"] = choice.ModifiedAt
	}
	if choice.Kind == "clone-content" {
		if choice.Source["sizeBytes"] != remoteDecimal(op.SizeBytes) || choice.Source["sha256"] != op.Captured.Evidence.SHA256 {
			return nil, ErrInvalidReceipt
		}
		input["source"] = choice.Source
	}
	raw, err := httpJSON(input)
	if err != nil {
		return nil, err
	}
	ns, err := httpJSON(choice.Namespace)
	if err != nil {
		return nil, err
	}
	return &MutationBinding{Schema: "pluto.mutation-binding/v1", Input: raw, Namespace: ns, InputSHA256: hashBytes(raw), Kind: choice.Kind, MTimeNS: choice.MTimeNS}, nil
}
func (s *IsolatedHTTPSession) chooseMutation(ctx context.Context, d CapturedDecision, v *VerifiedSnapshot) (*MutationChoice, error) {
	if !s.features["namespace-mutations-v1"] || s.namespace == nil {
		return nil, nil
	}
	e := v.Evidence()
	if d.Kind == "NOOP_CAPTURED" {
		source, err := s.r.sources.SourceEntry(ctx, e.SetID, e.Destination)
		if err != nil {
			return nil, err
		}
		base, err := readJSON[Baseline](ctx, s.r.store.db, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", d.Witness.RootID, d.Witness.EntryID)
		if err != nil {
			return nil, err
		}
		if base.PublishedMTimeNS == source.MTimeNS {
			return nil, nil
		}
		return &MutationChoice{Kind: "metadata-patch", Namespace: s.namespace, ModifiedAt: time.Unix(0, source.MTimeNS).UTC().Format(time.RFC3339Nano), MTimeNS: source.MTimeNS}, nil
	}
	if d.Kind == "CREATE" && e.SizeBytes == 0 {
		return &MutationChoice{Kind: "create-empty", Namespace: s.namespace}, nil
	}
	if !s.features["clone-content-v1"] || d.Kind != "CREATE" {
		return nil, nil
	}
	raw, err := s.post(ctx, "content/lookup", map[string]any{"binding": bindingHTTP(s.binding), "sizeBytes": remoteDecimal(e.SizeBytes), "sha256": e.SHA256})
	if err != nil {
		if HTTPStatus(err) == 404 || HTTPStatus(err) == 501 {
			return nil, nil
		}
		return nil, err
	}
	parsed, err := syncproto.Parse(raw)
	if err != nil {
		return nil, err
	}
	object, err := strictHTTPObject(parsed, "reference")
	if err != nil {
		return nil, err
	}
	if object["reference"] == nil {
		return nil, nil
	}
	source, err := strictHTTPObject(object["reference"], "nodeId", "contentVersionId", "metadataVersion", "sizeBytes", "sha256")
	if err != nil {
		return nil, err
	}
	for _, field := range []string{"nodeId", "contentVersionId", "metadataVersion"} {
		v, ok := source[field].(string)
		if !ok || !httpUUID(v) {
			return nil, ErrInvalidReceipt
		}
	}
	if source["sizeBytes"] != remoteDecimal(e.SizeBytes) || source["sha256"] != e.SHA256 {
		return nil, ErrInvalidReceipt
	}
	return &MutationChoice{Kind: "clone-content", Namespace: s.namespace, Source: source}, nil
}
func (s *IsolatedHTTPSession) mutation(ctx context.Context, op Operation, recovery bool) (*CapturedPublication, error) {
	if op.Mutation == nil || op.Mutation.Schema != "pluto.mutation-binding/v1" || hashBytes(op.Mutation.Input) != op.Mutation.InputSHA256 || op.IntentFingerprint != fingerprint(op.Intent) || op.RootID != s.root || op.Captured == nil || op.Captured.Transport == nil || op.Captured.Transport.Origin != s.origin || op.Captured.Transport.InputBinding != s.binding {
		return nil, ErrIdentityConflict
	}
	var input, namespace map[string]any
	if json.Unmarshal(op.Mutation.Input, &input) != nil || json.Unmarshal(op.Mutation.Namespace, &namespace) != nil || input["operationId"] != op.OperationID {
		return nil, ErrIdentityConflict
	}
	command := "execute"
	if recovery {
		command = "status"
	}
	raw, err := s.mutationTransport(ctx, op, command, input, namespace)
	if err != nil {
		var failure *guardedHTTPFailure
		if recovery && op.HTTPBinding == nil && (HTTPStatus(err) == 404 || errors.As(err, &failure) && failure.status == 409 && failure.code == "operation_reused") {
			return s.mutation(ctx, op, false)
		}
		return nil, err
	}
	v, err := syncproto.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok || m["schema"] != "saturn.namespace-mutation-status.v1" || m["operationId"] != op.OperationID {
		return nil, ErrInvalidReceipt
	}
	hash, ok := m["intentHash"].(string)
	if !ok || !validHash(hash) {
		return nil, ErrInvalidReceipt
	}
	bound, err := s.r.BindHTTPUpload(ctx, op, op.OperationID, hash)
	if err != nil {
		return nil, err
	}
	op = bound
	if m["state"] != "PUBLISHED" {
		if recovery && (m["state"] == "QUEUED" || m["state"] == "PREPARED") {
			return s.mutation(ctx, op, false)
		}
		return nil, ErrArtifactRetained
	}
	result, err := strictHTTPObject(m["result"], "description", "firstSeq", "lastSeq", "tombstone")
	if err != nil || result["tombstone"] != false {
		return nil, ErrInvalidReceipt
	}
	desc, err := syncproto.ReadDescriptor(result["description"])
	if err != nil {
		return nil, err
	}
	if op.Mutation.Kind == "metadata-patch" && (desc.ContentVersionID == nil || *desc.ContentVersionID != op.Captured.ExpectedContentVersionID) {
		return nil, ErrInvalidReceipt
	}
	first, err := syncproto.Integer64(result["firstSeq"])
	if err != nil {
		return nil, err
	}
	last, err := syncproto.Integer64(result["lastSeq"])
	if err != nil || first < 1 || last < first {
		return nil, ErrInvalidReceipt
	}
	b := op.Captured.Transport.InputBinding
	pub := CapturedPublication{Binding: b, HTTPBinding: op.HTTPBinding, FirstSeq: first, Description: remoteFromDescriptor(op.RootID, op.Captured.Witness.Remote.Generation, last, b, desc, op.OperationID), Receipt: Receipt{OperationID: op.OperationID, RootID: op.RootID, EntryID: op.EntryID, NodeID: desc.NodeID, Epoch: b.ServerEpoch, Version: desc.Version, SHA256: op.SHA256, SealedFingerprint: op.SealedFingerprint, LocalGeneration: op.LocalGeneration, SizeBytes: op.SizeBytes, Seq: last, Published: true, ContentVerified: true}}
	rc := pub.Receipt
	rc.CapturedResult = &CapturedPublicationEvidence{Binding: b, Description: pub.Description, FirstSeq: first, HTTPBinding: op.HTTPBinding}
	if !validCapturedReceipt(op, rc) {
		return nil, ErrInvalidReceipt
	}
	if err = s.Refresh(ctx); err != nil {
		return nil, err
	}
	return &pub, nil
}

// Metadata commands consume the sealed reader locally so the existing capture
// scope still verifies exact bytes; the HTTP request carries no file payload.
func (s *IsolatedHTTPSession) publishMutation(ctx context.Context, op Operation, reader io.Reader) (CapturedPublication, error) {
	if _, err := io.CopyN(io.Discard, reader, op.SizeBytes); err != nil {
		return CapturedPublication{}, err
	}
	pub, err := s.mutation(ctx, op, false)
	if err != nil {
		return CapturedPublication{}, err
	}
	return *pub, nil
}
