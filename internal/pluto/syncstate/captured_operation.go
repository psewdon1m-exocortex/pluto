package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// CapturedOperationBinding is immutable historical evidence. Source and local
// generations have different domains. This value neither grants Send permission
// nor proves whole-root continuity; PlanCaptured is its only writer.
type CapturedOperationBinding struct {
	Schema                                                              string
	Evidence                                                            SnapshotEvidence
	EntryID, SourceFileIdentity, DecisionKind, ExpectedContentVersionID string
	LocalGeneration                                                     int64
	Witness                                                             CapturedWitness
	RemoteAnchor                                                        RemoteEntry
	Parents                                                             []CapturedParentBinding
	Transport                                                           *CapturedHTTPIdentity `json:",omitempty"`
}
type CapturedParentBinding struct {
	Local  Observation
	Remote RemoteEntry
}

func capturedArtifactMatches(op Operation, c artifactCapture) bool {
	p := op.Captured
	_, topologyErr := op.ParentTopology()
	return topologyErr == nil && p != nil && p.Schema == "pluto.captured-operation/v1" && p.EntryID == op.EntryID && p.LocalGeneration == op.LocalGeneration && p.LocalGeneration > 0 && p.Evidence == c.SnapshotEvidence && p.SourceFileIdentity == c.SourceFileIdentity && p.SourceFileIdentity == op.FileIdentity && p.Witness.RootID == op.RootID && p.Witness.EntryID == op.EntryID && p.Witness.Source == p.Evidence && validHash(p.Witness.StateDigest) && (p.DecisionKind == "CREATE" || p.DecisionKind == "OVERWRITE" || p.DecisionKind == "NOOP_CAPTURED" && op.Mutation != nil && op.Mutation.Kind == "metadata-patch") && len(p.Parents) < MaxSourceDepth && p.Witness.Remote.Binding.ServerEpoch == op.ExpectedEpoch && p.Witness.Remote.TrustGeneration == op.TrustGeneration
}

// PlanCaptured writes the immutable identity, sealed snapshot and historical
// source→local projection in one transaction before any network attempt. The
// registry snapshot UUID closes a crash before the explicit artifact bind.
func (r *RemoteImport) PlanCaptured(ctx context.Context, w SourceWitness, v *VerifiedSnapshot, a *RemoteAuthority, expected CapturedDecision, id string, now time.Time) (result Operation, err error) {
	return r.planCaptured(ctx, w, v, a, expected, id, now, false)
}
func (r *RemoteImport) planCaptured(ctx context.Context, w SourceWitness, v *VerifiedSnapshot, a *RemoteAuthority, expected CapturedDecision, id string, now time.Time, submit bool) (result Operation, err error) {
	return r.planCapturedMutation(ctx, w, v, a, expected, id, now, submit, nil)
}
func (r *RemoteImport) planCapturedMutation(ctx context.Context, w SourceWitness, v *VerifiedSnapshot, a *RemoteAuthority, expected CapturedDecision, id string, now time.Time, submit bool, choice *MutationChoice) (result Operation, err error) {
	if v == nil || !validID(id) {
		return result, ErrIdentityConflict
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err = v.integrity(ctx); err != nil {
		return result, err
	}
	registry := r.store.artifacts
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if !registry.ready {
		return result, ErrArtifactUnreconciled
	}
	err = r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if e := registry.validate(ctx, tx); e != nil {
			return e
		}
		d, state, e := r.decideCaptured(ctx, tx, w, expected.Witness.RootID, expected.Witness.EntryID, v, a, now)
		if e != nil {
			return e
		}
		if (d.Kind != "CREATE" && d.Kind != "OVERWRITE" && !(d.Kind == "NOOP_CAPTURED" && choice != nil && choice.Kind == "metadata-patch" && choice.MTimeNS == state.Source.MTimeNS)) || d.Kind != expected.Kind || d.Witness != expected.Witness {
			return ErrStaleGeneration
		}
		if _, e = readOperation(ctx, tx, id); e == nil {
			return ErrIdentityConflict
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if len(state.Parents) == 0 || len(state.Chain) > MaxSourceDepth {
			return ErrIdentityConflict
		}
		proof := &CapturedOperationBinding{Schema: "pluto.captured-operation/v1", Evidence: state.Evidence, EntryID: state.Local.EntryID, SourceFileIdentity: state.Local.FileIdentity, LocalGeneration: state.Local.Generation, DecisionKind: d.Kind, Witness: d.Witness, RemoteAnchor: state.Parents[0], Parents: make([]CapturedParentBinding, 0, len(state.Chain)-1)}
		if a != nil && a.transport != nil {
			identity := *a.transport
			identity.InputBinding = state.Candidate.Binding
			identity.RequestPath = "/" + state.Evidence.Destination
			proof.Transport = &identity
		}
		for i := len(state.Chain) - 1; i > 0; i-- {
			j := len(state.Chain) - i
			proof.Parents = append(proof.Parents, CapturedParentBinding{Local: state.Chain[i], Remote: state.Parents[j]})
		}
		parent := state.Parents[len(state.Parents)-1].NodeID
		intent := Intent{OperationID: id, RootID: state.Local.RootID, EntryID: state.Local.EntryID, Kind: "PUT", ExpectedEpoch: state.Candidate.Binding.ServerEpoch, ParentID: state.Local.ParentID, Name: state.Local.Name, NameKey: state.Local.NameKey, FileIdentity: state.Local.FileIdentity, LocalGeneration: state.Local.Generation, TrustGeneration: state.Root.TrustGeneration, SizeBytes: state.Evidence.SizeBytes, ExpectedAbsent: d.Kind == "CREATE", Captured: proof}
		if state.Remote != nil {
			intent.ExpectedNodeID = state.Remote.NodeID
			intent.ExpectedVersion = state.Remote.Version
			proof.ExpectedContentVersionID = state.Remote.ContentVersionID
		}
		if choice != nil {
			if choice.Kind == "metadata-patch" {
				intent.Kind = "METADATA_PATCH"
			}
			intent.Mutation, e = makeMutationBinding(intent, choice)
			if e != nil {
				return e
			}
		}
		// Parent identity is sealed in the last exact namespace binding; root-level
		// files bind the qualified remote root instead of an invented local ID.
		if parent == "" {
			return ErrIdentityConflict
		}
		if len(mustJSON(intent)) > MaxSourcePageBytes {
			return ErrSourceQuota
		}
		ih := fingerprint(intent)
		sh := fingerprint(struct{ IntentFingerprint, SHA256 string }{ih, state.Evidence.SHA256})
		result = Operation{Intent: intent, Stage: "SEALED", SHA256: state.Evidence.SHA256, SnapshotID: state.Evidence.SnapshotID, IntentFingerprint: ih, SealedFingerprint: sh}
		if proof.Transport != nil {
			if _, e = originalCatalogInput(result); e != nil {
				return e
			}
		}
		record, e := readArtifact(ctx, tx, result.SnapshotID)
		if e != nil {
			return e
		}
		if record.Phase != ArtifactSealed || record.OperationID != "" || record.SHA256 != result.SHA256 || record.SizeBytes != result.SizeBytes {
			return ErrIdentityConflict
		}
		var raw string
		var c artifactCapture
		if e = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(capture_json)<=16384 THEN capture_json ELSE '' END FROM local_artifacts WHERE artifact_id=?", record.ID).Scan(&raw); e != nil {
			return e
		}
		if json.Unmarshal([]byte(raw), &c) != nil || !capturedArtifactMatches(result, c) {
			return ErrIdentityConflict
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage,sha256,snapshot_id,sealed_fingerprint) VALUES(?,?,?,?,?,?,?,'SEALED',?,?,?)", id, result.RootID, result.EntryID, result.LocalGeneration, result.Kind, string(mustJSON(intent)), ih, result.SHA256, result.SnapshotID, sh)
		if e != nil {
			return e
		}
		if submit {
			if _, e = tx.ExecContext(ctx, "UPDATE local_artifacts SET operation_id=? WHERE artifact_id=? AND operation_id IS NULL", id, record.ID); e != nil {
				return e
			}
			if e = r.point("capture.before_submit"); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE operations SET stage='SUBMITTED' WHERE operation_id=?", id); e != nil {
				return e
			}
			result.Stage = "SUBMITTED"
		}
		return r.point("capture.before_plan")
	})
	return result, err
}

type CapturedParentTopology struct{ NodeID, ParentID, Name string }

// ParentTopology returns the immutable same-cut direct-parent→root chain for
// the forthcoming modern server namespace fence. Stable UUID alone is not
// permission to publish after an ancestor was moved or renamed. No URL/DTO is
// inferred, and historical publication descriptions cannot refresh this chain.
func (op Operation) ParentTopology() ([]CapturedParentTopology, error) {
	p := op.Captured
	if p == nil || p.Schema != "pluto.captured-operation/v1" || len(p.Parents) >= MaxSourceDepth {
		return nil, ErrIdentityConflict
	}
	w := p.Witness.Remote
	a := p.RemoteAnchor
	if a.NodeID != w.Binding.RootID || a.ParentID != "" || a.Kind != "folder" || a.Presence != "PRESENT" || a.Availability != "AVAILABLE" || !currentRemoteBinding(a, w) || !validID(a.Version) {
		return nil, ErrIdentityConflict
	}
	versions := make([]CapturedParentTopology, 0, len(p.Parents)+1)
	seen := make(map[string]bool, len(p.Parents)+1)
	for i := len(p.Parents) - 1; i >= 0; i-- {
		e := p.Parents[i].Remote
		parent := a.NodeID
		if i > 0 {
			parent = p.Parents[i-1].Remote.NodeID
		}
		if e.ParentID != parent || e.Kind != "folder" || e.Presence != "PRESENT" || e.Availability != "AVAILABLE" || !currentRemoteBinding(e, w) || !validID(e.Version) || seen[e.NodeID] {
			return nil, ErrIdentityConflict
		}
		seen[e.NodeID] = true
		versions = append(versions, CapturedParentTopology{e.NodeID, e.ParentID, e.Name})
	}
	if seen[a.NodeID] {
		return nil, ErrIdentityConflict
	}
	return append(versions, CapturedParentTopology{a.NodeID, a.ParentID, a.Name}), nil
}

// SubmittedCaptured rechecks the original exact advisory witness in one write
// transaction, excluding only its own retained intent. Server CAS is still
// necessary; local authority freshness is not a server publication fence.
func (r *RemoteImport) SubmittedCaptured(ctx context.Context, w SourceWitness, v *VerifiedSnapshot, a *RemoteAuthority, id string, now time.Time) error {
	if v == nil {
		return ErrInvalidReceipt
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.integrity(ctx); err != nil {
		return err
	}
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return err
		}
		if op.Captured == nil || op.SnapshotID != v.evidence.SnapshotID || op.Stage != "SEALED" {
			return ErrInvalidReceipt
		}
		d, _, err := r.decideCapturedIgnoring(ctx, tx, w, op.RootID, op.EntryID, v, a, now, id)
		if err != nil {
			return err
		}
		if d.Kind != op.Captured.DecisionKind || d.Witness != op.Captured.Witness {
			return ErrStaleGeneration
		}
		if err = r.point("capture.before_submit"); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE operations SET stage='SUBMITTED' WHERE operation_id=? AND stage='SEALED'", id)
		return err
	})
}

// CapturedPublication is a historical result of this immutable operation. The
// full seven-field binding and content UUID are separate from metadata CAS.
// It is never inserted into current R or used as a feed cut by itself.
type CapturedPublication struct {
	Receipt     Receipt
	Binding     RemoteBinding
	Description RemoteEntry
	FirstSeq    int64
	HTTPBinding *HTTPUploadBinding `json:",omitempty"`
}
type CapturedPublicationEvidence struct {
	Binding     RemoteBinding
	Description RemoteEntry
	FirstSeq    int64
	HTTPBinding *HTTPUploadBinding `json:",omitempty"`
}

func validCapturedReceipt(op Operation, rc Receipt) bool {
	p := op.Captured
	q := rc.CapturedResult
	if p == nil || q == nil || q.Binding != p.Witness.Remote.Binding || q.FirstSeq < 1 || q.FirstSeq > rc.Seq {
		return false
	}
	e := q.Description
	if !validCapturedHTTPReceipt(op, q.HTTPBinding, e) {
		return false
	}
	topology, err := op.ParentTopology()
	if err != nil || len(topology) == 0 {
		return false
	}
	return rc.Published && rc.ContentVerified && rc.OperationID == op.OperationID && rc.RootID == op.RootID && rc.EntryID == op.EntryID && rc.LocalGeneration == op.LocalGeneration && rc.SHA256 == op.SHA256 && rc.SizeBytes == op.SizeBytes && rc.SealedFingerprint == op.SealedFingerprint && rc.Epoch == op.ExpectedEpoch && e.RootID == op.RootID && e.NodeID == rc.NodeID && e.Epoch == rc.Epoch && e.Version == rc.Version && e.Kind == "file" && e.Presence == "PRESENT" && e.Availability == "AVAILABLE" && e.SizeBytes == op.SizeBytes && e.SHA256 == op.SHA256 && validID(e.ContentVersionID) && e.RemoteBinding != nil && *e.RemoteBinding == q.Binding && e.LastSeq == rc.Seq && e.Name == op.Name && e.ParentID == topology[0].NodeID && (op.ExpectedAbsent || e.NodeID == op.ExpectedNodeID)
}

func (r *RemoteImport) AckCaptured(ctx context.Context, pub CapturedPublication) error {
	err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		return r.ackCapturedTx(ctx, tx, pub)
	})
	if err == nil {
		err = r.afterContentAck(ctx, pub.Receipt.OperationID)
	}
	return err
}

func capturedAckStillCurrent(ctx context.Context, tx *sql.Tx, r *RemoteImport, p *CapturedOperationBinding, op Operation, l Observation, c RemoteCandidate) bool {
	anchor, err := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", op.RootID, c.Generation, c.Binding.RootID)
	if err != nil || !currentRemoteBinding(anchor, c.RemoteWitness) || anchor.NodeID != p.RemoteAnchor.NodeID || anchor.ParentID != p.RemoteAnchor.ParentID || anchor.Name != p.RemoteAnchor.Name || anchor.Kind != "folder" || anchor.Presence != "PRESENT" || anchor.Availability != "AVAILABLE" {
		return false
	}
	set, err := r.sources.checkWitness(ctx, tx, p.Evidence.Witness)
	if err != nil || set.AttachedRootID != op.RootID || l.Generation != op.LocalGeneration || l.HashGeneration != l.Generation || l.SHA256 != op.SHA256 {
		return false
	}
	s, err := readSourceEntry(ctx, tx, p.Evidence.SetID, p.Evidence.Destination)
	if err != nil || s.Ambiguous || s.Generation != p.Evidence.EntryGeneration || s.VerificationRequest != p.Evidence.VerificationRequest || s.SourceIncarnation != p.Evidence.SourceIncarnation || s.FileIdentity != op.FileIdentity {
		return false
	}
	for _, parent := range p.Parents {
		local, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", op.RootID, parent.Local.EntryID)
		if err != nil || local != parent.Local {
			return false
		}
		e, err := namespaceCandidate(ctx, tx, c.RemoteWitness, parent.Remote.ParentID, parent.Remote.Name)
		if err != nil || e == nil || !currentRemoteBinding(*e, c.RemoteWitness) || e.NodeID != parent.Remote.NodeID || e.ParentID != parent.Remote.ParentID || e.Name != parent.Remote.Name || e.Kind != "folder" || e.Availability != "AVAILABLE" {
			return false
		}
	}
	return true
}

func (r *RemoteImport) ackCapturedTx(ctx context.Context, tx *sql.Tx, pub CapturedPublication) error {
	rc := pub.Receipt
	op, err := readOperation(ctx, tx, rc.OperationID)
	if err != nil {
		return err
	}
	p := op.Captured
	e := pub.Description
	if !validCapturedHTTPReceipt(op, pub.HTTPBinding, e) {
		return ErrInvalidReceipt
	}
	if p == nil || op.Kind != "PUT" && !(op.Kind == "METADATA_PATCH" && op.Mutation != nil && op.Mutation.Kind == "metadata-patch" && e.ContentVersionID == p.ExpectedContentVersionID) || !rc.Published || !rc.ContentVerified || rc.RootID != op.RootID || rc.EntryID != op.EntryID || rc.LocalGeneration != op.LocalGeneration || rc.SHA256 != op.SHA256 || rc.SizeBytes != op.SizeBytes || rc.SealedFingerprint != op.SealedFingerprint || pub.Binding != p.Witness.Remote.Binding || pub.FirstSeq < 1 || pub.FirstSeq > rc.Seq || e.RootID != op.RootID || e.NodeID != rc.NodeID || e.Epoch != rc.Epoch || e.Version != rc.Version || e.Kind != "file" || e.Presence != "PRESENT" || e.Availability != "AVAILABLE" || e.SizeBytes != op.SizeBytes || e.SHA256 != op.SHA256 || e.ContentVersionID == "" || e.RemoteBinding == nil || *e.RemoteBinding != pub.Binding || e.LastSeq != rc.Seq || e.Name != op.Name || !validID(rc.NodeID) || !validID(rc.Version) || rc.Epoch != op.ExpectedEpoch {
		return ErrInvalidReceipt
	}
	parent := pub.Binding.RootID
	if len(p.Parents) > 0 {
		parent = p.Parents[len(p.Parents)-1].Remote.NodeID
	}
	if e.ParentID != parent || !op.ExpectedAbsent && e.NodeID != op.ExpectedNodeID {
		return ErrInvalidReceipt
	}
	rc.CapturedResult = &CapturedPublicationEvidence{Binding: pub.Binding, Description: e, FirstSeq: pub.FirstSeq, HTTPBinding: pub.HTTPBinding}
	raw := string(mustJSON(rc))
	if len(raw) > 16384 {
		return ErrSourceQuota
	}
	if op.Stage == "CLIENT_ACKED" {
		var old string
		if err = tx.QueryRowContext(ctx, "SELECT receipt_json FROM operations WHERE operation_id=?", op.OperationID).Scan(&old); err != nil {
			return err
		}
		if old != raw {
			return ErrInvalidReceipt
		}
		return nil
	}
	if op.Stage != "SUBMITTED" {
		return ErrInvalidReceipt
	}
	old, err := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && (old.LocalGeneration > op.LocalGeneration || old.LastSeq >= rc.Seq) {
		return ErrInvalidReceipt
	}
	proof := p.Evidence
	binding := pub.Binding
	b := Baseline{RootID: op.RootID, EntryID: op.EntryID, NodeID: e.NodeID, Epoch: e.Epoch, Version: e.Version, SHA256: e.SHA256, Kind: "file", Presence: "PRESENT", OperationID: op.OperationID, ParentID: op.ParentID, Name: op.Name, NameKey: op.NameKey, FileIdentity: op.FileIdentity, LocalGeneration: op.LocalGeneration, TrustGeneration: op.TrustGeneration, SizeBytes: op.SizeBytes, LastSeq: rc.Seq, RemoteBinding: &binding, RemoteParentID: e.ParentID, ContentVersionID: e.ContentVersionID, CaptureProof: &proof}
	if op.Mutation != nil && op.Mutation.Kind == "metadata-patch" {
		b.PublishedMTimeNS = op.Mutation.MTimeNS
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?) ON CONFLICT(root_id,entry_id) DO UPDATE SET node_id=excluded.node_id,descriptor_json=excluded.descriptor_json", op.RootID, op.EntryID, e.NodeID, string(mustJSON(b))); err != nil {
		return err
	}
	// Parents are historical qualified agreement, not invented folder receipts.
	// Never replace an existing parent B, including a newer or conflicted one.
	for _, parent := range p.Parents {
		l := parent.Local
		e := parent.Remote
		pb := Baseline{RootID: l.RootID, EntryID: l.EntryID, NodeID: e.NodeID, Epoch: e.Epoch, Version: e.Version, Kind: "folder", Presence: "PRESENT", ParentID: l.ParentID, Name: l.Name, NameKey: l.NameKey, FileIdentity: l.FileIdentity, LocalGeneration: l.Generation, TrustGeneration: op.TrustGeneration, LastSeq: e.LastSeq, RemoteBinding: &binding, RemoteParentID: e.ParentID}
		if _, err = tx.ExecContext(ctx, "INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?) ON CONFLICT(root_id,entry_id) DO NOTHING", l.RootID, l.EntryID, e.NodeID, string(mustJSON(pb))); err != nil {
			return err
		}
	}
	root, err := readRoot(ctx, tx, op.RootID)
	if err != nil {
		return err
	}
	c, ce := readCandidate(ctx, tx, op.RootID)
	l, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
	if err != nil {
		return err
	}
	// Clear only when current authoritative imported R confirms this receipt.
	// ACK after local/source gap or new R/trust stores history but retains work.
	current, ee := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", op.RootID, root.ActiveRemoteGeneration, e.NodeID)
	if ce == nil && ee == nil && capturedAckStillCurrent(ctx, tx, r, p, op, l, c) && root.TrustGeneration == op.TrustGeneration && c.Binding == pub.Binding && currentRemoteBinding(current, c.RemoteWitness) && sameRemoteBaseline(b, current, c.RemoteWitness) {
		_, err = tx.ExecContext(ctx, "DELETE FROM dirty_entries WHERE root_id=? AND entry_id=? AND observed_generation<=? AND remote_seq<=?", op.RootID, op.EntryID, op.LocalGeneration, rc.Seq)
	} else {
		err = addDirty(ctx, tx, op.RootID, op.EntryID, l.Generation, rc.Seq, "local")
	}
	if err != nil {
		return err
	}
	if err = r.point("capture.before_ack"); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE operations SET stage='CLIENT_ACKED',receipt_json=? WHERE operation_id=?", raw, op.OperationID)
	return err
}
