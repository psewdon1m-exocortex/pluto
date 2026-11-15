package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"pluto/internal/syncproto"
	"strings"
	"time"
)

func pendingCapturedEntry(ctx context.Context, tx *sql.Tx, root, entry string) ([]Operation, error) {
	rows, err := tx.QueryContext(ctx, "SELECT operation_id FROM operations WHERE root_id=? AND entry_id=? AND stage<>'CLIENT_ACKED' ORDER BY local_generation,kind LIMIT 2", root, entry)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, 2)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := make([]Operation, 0, len(ids))
	for _, id := range ids {
		op, err := readOperation(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, nil
}

func (r *RemoteImport) capturedSource(ctx context.Context, tx *sql.Tx, w SourceWitness, v *VerifiedSnapshot, root Root) (SourceEntry, error) {
	var entry SourceEntry
	if v == nil || v.closed || v.evidence.Witness != w {
		return entry, ErrInvalidReceipt
	}
	set, err := r.sources.checkWitness(ctx, tx, w)
	if err != nil {
		return entry, err
	}
	if set.AttachedRootID != root.RootID || root.SourceIdentity != set.ID || root.NameCodec != "legacy" && root.NameCodec != "portable_v1" {
		return entry, ErrIdentityConflict
	}
	e := v.evidence
	entry, err = readSourceEntry(ctx, tx, w.SetID, e.Destination)
	if err != nil {
		return entry, err
	}
	if entry.Ambiguous || entry.Presence != "PRESENT" || entry.Kind != "file" || entry.Generation != e.EntryGeneration || entry.VerificationRequest != e.VerificationRequest || entry.SourceID != e.SourceID || entry.SourceIncarnation != e.SourceIncarnation || entry.SizeBytes != e.SizeBytes || entry.FileIdentity != v.sourceIdentity || entry.PhysicalPath != v.physicalPath {
		return entry, ErrStaleGeneration
	}
	durable, err := readJSON[SnapshotEvidence](ctx, tx, "SELECT evidence_json FROM source_evidence WHERE set_id=? AND destination=?", w.SetID, e.Destination)
	if err != nil {
		return entry, err
	}
	if durable != e {
		return entry, ErrStaleGeneration
	}
	binding, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1", w.SetID, e.SourceID)
	if err != nil {
		return entry, err
	}
	if binding.IncarnationStatus != "LOCAL_OBSERVED" || binding.Incarnation != e.SourceIncarnation {
		return entry, ErrStaleGeneration
	}
	var member int
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM source_membership WHERE set_id=? AND source_id=? AND destination=?)", w.SetID, e.SourceID, e.Destination).Scan(&member); err != nil {
		return entry, err
	}
	if member != 1 {
		return entry, ErrSourceAmbiguous
	}
	return entry, nil
}

// localPath reads at most128 exact parent bindings. No inode-only or source
// alias normalization is applied; the path must equal legacy remoteRelativePath.
func localPath(ctx context.Context, tx *sql.Tx, l Observation) ([]Observation, string, error) {
	root, rootErr := readRoot(ctx, tx, l.RootID)
	if rootErr != nil {
		return nil, "", rootErr
	}
	chain := make([]Observation, 0, 8)
	seen := make(map[string]bool, 8)
	bytes := 0
	for {
		key := l.Name
		if root.NameCodec == "portable_v1" {
			var e error
			key, e = syncproto.NameKey(l.Name, root.NameCodec)
			if e != nil {
				return nil, "", e
			}
		}
		if len(chain) >= MaxSourceDepth || seen[l.EntryID] || l.NameKey != key || l.Presence != "PRESENT" || len(l.Name) == 0 {
			return nil, "", ErrSourceIncomplete
		}
		seen[l.EntryID] = true
		chain = append(chain, l)
		bytes += len(l.Name) + 1
		if bytes > 4096 {
			return nil, "", ErrSourceQuota
		}
		if l.ParentID == "" {
			break
		}
		parent, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", l.RootID, l.ParentID)
		if err != nil {
			return nil, "", err
		}
		if parent.Kind != "folder" {
			return nil, "", ErrIdentityConflict
		}
		l = parent
	}
	parts := make([]string, len(chain))
	for i := range chain {
		parts[len(chain)-1-i] = chain[i].Name
	}
	return chain, strings.Join(parts, "/"), nil
}

// ProjectCapturedEntry binds exact sealed evidence to one existing local path.
// It does not invent a local journal cut, discover parents, infer absence, or
// clear dirty work. A source and local generation are deliberately independent.
func (r *RemoteImport) ProjectCapturedEntry(ctx context.Context, w SourceWitness, rootID, entryID string, v *VerifiedSnapshot) error {
	if v == nil {
		return ErrInvalidReceipt
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.integrity(ctx); err != nil {
		return err
	}
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		root, err := readRoot(ctx, tx, rootID)
		if err != nil {
			return err
		}
		source, err := r.capturedSource(ctx, tx, w, v, root)
		if err != nil {
			return err
		}
		l, err := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", rootID, entryID)
		if err != nil {
			return err
		}
		_, path, err := localPath(ctx, tx, l)
		if err != nil {
			return err
		}
		if path != source.Destination || l.Kind != "file" {
			return ErrIdentityConflict
		}
		changed := l.SHA256 != v.evidence.SHA256 || l.HashGeneration != l.Generation || l.FileIdentity != source.FileIdentity || l.SizeBytes != source.SizeBytes || l.MTimeNS != source.MTimeNS
		if changed {
			pending, err := pendingCapturedEntry(ctx, tx, rootID, entryID)
			if err != nil {
				return err
			}
			if len(pending) > 0 {
				return ErrArtifactRetained
			}
			if l.Generation == math.MaxInt64 {
				return ErrStaleGeneration
			}
			before := l.Generation
			l.ExpectedGeneration = before
			l.Generation++
			l.HashGeneration = l.Generation
			l.SHA256 = v.evidence.SHA256
			l.FileIdentity = source.FileIdentity
			l.SizeBytes = source.SizeBytes
			l.MTimeNS = source.MTimeNS
			raw, _ := json.Marshal(l)
			result, err := tx.ExecContext(ctx, "UPDATE local_entries SET generation=?,descriptor_json=? WHERE root_id=? AND entry_id=? AND generation=?", l.Generation, string(raw), rootID, entryID, before)
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrStaleGeneration
			}
		}
		raw, _ := json.Marshal(v.evidence)
		if _, err = tx.ExecContext(ctx, "INSERT INTO captured_local_entries(root_id,entry_id,set_id,destination,local_generation,evidence_json) VALUES(?,?,?,?,?,?) ON CONFLICT(root_id,entry_id) DO UPDATE SET set_id=excluded.set_id,destination=excluded.destination,local_generation=excluded.local_generation,evidence_json=excluded.evidence_json", rootID, entryID, w.SetID, source.Destination, l.Generation, string(raw)); err != nil {
			return err
		}
		return addDirty(ctx, tx, rootID, entryID, l.Generation, 0, "local")
	})
}

func namespaceCandidate(ctx context.Context, tx *sql.Tx, w RemoteWitness, parent, name string) (*RemoteEntry, error) {
	root, err := readRoot(ctx, tx, w.RootID)
	if err != nil {
		return nil, err
	}
	if cached, found, e := cachedParent(ctx, tx, w, root.NameCodec, parent, name); e != nil {
		return nil, e
	} else if found {
		return cached, nil
	}
	expr := "json_extract(descriptor_json,'$.Name')"
	key := name
	if root.NameCodec == "portable_v1" {
		key, err = syncproto.NameKey(name, root.NameCodec)
		if err != nil {
			return nil, err
		}
		expr = "lower(" + expr + ")"
	}
	rows, err := tx.QueryContext(ctx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND json_extract(descriptor_json,'$.ParentID')=? AND "+expr+"=? AND json_extract(descriptor_json,'$.Presence')='PRESENT' ORDER BY node_id LIMIT 2", w.RootID, w.Generation, parent, key)
	if err != nil {
		return nil, err
	}
	var result *RemoteEntry
	count := 0
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var value RemoteEntry
		if err = json.Unmarshal([]byte(raw), &value); err != nil {
			rows.Close()
			return nil, err
		}
		count++
		result = &value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count > 1 {
		return nil, ErrIdentityConflict
	}
	if result != nil && result.Name != name {
		return nil, ErrIdentityConflict
	} // Case-only rename needs a server namespace plan; Pluto never moves a copy.
	return result, nil
}

func currentRemoteBinding(e RemoteEntry, w RemoteWitness) bool {
	return e.RemoteBinding != nil && *e.RemoteBinding == w.Binding && e.Generation == w.Generation && e.Epoch == w.Binding.ServerEpoch && e.LastSeq <= w.Position
}
func sameRemoteBaseline(b Baseline, e RemoteEntry, w RemoteWitness) bool {
	// Receipt B can cover ancestor events after the file's own event. Require
	// the qualified candidate to cover that entire publication, while matching
	// the exact current file version/content/topology. Comparing with e.LastSeq
	// would reject an unchanged file whenever publication also updated parents.
	return b.RemoteBinding != nil && *b.RemoteBinding == w.Binding && b.TrustGeneration == w.TrustGeneration && b.NodeID == e.NodeID && b.Epoch == e.Epoch && b.Version == e.Version && b.RemoteParentID == e.ParentID && b.Name == e.Name && compatibleNameKey(b.NameKey, e.Name) && b.Kind == e.Kind && b.Presence == e.Presence && b.SizeBytes == e.SizeBytes && b.SHA256 == e.SHA256 && b.ContentVersionID == e.ContentVersionID && b.LastSeq <= w.Position
}

// Folder aggregate size/metadata version can change for an unrelated sibling.
// Parent permission binds namespace topology, never folder aggregate content.
// Target file B still uses the full metadata/content comparison above.
func sameParentTopologyBaseline(b Baseline, e RemoteEntry, w RemoteWitness) bool {
	return b.RemoteBinding != nil && *b.RemoteBinding == w.Binding && b.TrustGeneration == w.TrustGeneration && b.NodeID == e.NodeID && b.Epoch == e.Epoch && b.RemoteParentID == e.ParentID && b.Name == e.Name && compatibleNameKey(b.NameKey, e.Name) && b.Kind == "folder" && e.Kind == "folder" && b.Presence == "PRESENT" && e.Presence == "PRESENT"
}

func authorityMatches(a *RemoteAuthority, w RemoteWitness, now time.Time) bool {
	return a != nil && a.witness == w && w.Valid && a.qualifiedAtMS >= 0 && a.expiresMS > a.qualifiedAtMS && a.expiresMS-a.qualifiedAtMS <= 30000 && now.UnixMilli() >= a.qualifiedAtMS && now.UnixMilli() < a.expiresMS
}

type capturedState struct {
	Root        Root
	Local       Observation
	Base        *Baseline
	Dirty       *Dirty
	Source      SourceEntry
	Evidence    SnapshotEvidence
	Candidate   RemoteCandidate
	Chain       []Observation
	Parents     []RemoteEntry
	ParentBases []*Baseline
	Pending     []Operation
	Remote      *RemoteEntry
}

func (r *RemoteImport) decideCaptured(ctx context.Context, tx *sql.Tx, w SourceWitness, rootID, entryID string, v *VerifiedSnapshot, a *RemoteAuthority, now time.Time) (CapturedDecision, capturedState, error) {
	return r.decideCapturedIgnoring(ctx, tx, w, rootID, entryID, v, a, now, "")
}

// Only a previously sealed exact intent may be excluded by the Send recheck.
// Other retained operations always route to original-ID recovery.
func (r *RemoteImport) decideCapturedIgnoring(ctx context.Context, tx *sql.Tx, w SourceWitness, rootID, entryID string, v *VerifiedSnapshot, a *RemoteAuthority, now time.Time, ignore string) (CapturedDecision, capturedState, error) {
	d := CapturedDecision{Kind: "RECONCILE"}
	var state capturedState
	var err error
	state.Root, err = readRoot(ctx, tx, rootID)
	if err != nil {
		return d, state, err
	}
	state.Local, err = readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", rootID, entryID)
	if err != nil {
		return d, state, err
	}
	state.Pending, err = pendingCapturedEntry(ctx, tx, rootID, entryID)
	if err != nil {
		return d, state, err
	}
	if ignore != "" {
		kept := make([]Operation, 0, len(state.Pending))
		for _, op := range state.Pending {
			if op.OperationID != ignore {
				kept = append(kept, op)
			}
		}
		state.Pending = kept
	}
	if b, e := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", rootID, entryID); e == nil {
		state.Base = &b
	} else if !errors.Is(e, sql.ErrNoRows) {
		return d, state, e
	}
	var dirty Dirty
	err = tx.QueryRowContext(ctx, "SELECT root_id,entry_id,observed_generation,remote_seq,reasons FROM dirty_entries WHERE root_id=? AND entry_id=?", rootID, entryID).Scan(&dirty.RootID, &dirty.EntryID, &dirty.ObservedGeneration, &dirty.RemoteSeq, &dirty.Reasons)
	if err == nil {
		state.Dirty = &dirty
	} else if !errors.Is(err, sql.ErrNoRows) {
		return d, state, err
	}
	state.Candidate, err = readCandidate(ctx, tx, rootID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return d, state, err
	}
	finish := func(kind, reason string) (CapturedDecision, capturedState, error) {
		d.Kind = kind
		d.Reason = reason
		d.Remote = state.Remote
		d.Witness = CapturedWitness{RootID: rootID, EntryID: entryID, Source: state.Evidence, Remote: state.Candidate.RemoteWitness, StateDigest: fingerprint(struct {
			Domain string
			State  capturedState
		}{"pluto.captured-witness/v1", state})}
		return d, state, nil
	}
	if len(state.Pending) > 0 {
		if len(state.Pending) > 1 {
			return finish("RECOVER", "multiple retained intents require original-ID reconciliation")
		}
		d.OperationID = state.Pending[0].OperationID
		return finish("RECOVER", "retained immutable operation; no replacement ID")
	}
	if state.Local.Presence == "ABSENT" {
		return finish("KEEP_REMOTE", "Pluto never deletes server data for local absence")
	}
	if v == nil {
		return finish("VERIFY", "exact sealed content evidence required")
	}
	state.Source, err = r.capturedSource(ctx, tx, w, v, state.Root)
	if err != nil {
		return finish("RECONCILE", "source witness/generation/incarnation is not current")
	}
	state.Evidence = v.evidence
	var gen int64
	var raw string
	if err = tx.QueryRowContext(ctx, "SELECT local_generation,evidence_json FROM captured_local_entries WHERE root_id=? AND entry_id=?", rootID, entryID).Scan(&gen, &raw); err != nil {
		return finish("VERIFY", "captured bytes have not been projected to this local entry")
	}
	if gen != state.Local.Generation || raw != string(mustJSON(state.Evidence)) || state.Local.SHA256 != state.Evidence.SHA256 || state.Local.HashGeneration != state.Local.Generation || state.Local.SizeBytes != state.Evidence.SizeBytes {
		return finish("RECONCILE", "local/captured generation changed")
	}
	state.Chain, _, err = localPath(ctx, tx, state.Local)
	if err != nil {
		return finish("RECONCILE", "local ancestry is incomplete or exceeds bounds")
	}
	parts := make([]string, len(state.Chain))
	for i := range state.Chain {
		parts[len(parts)-1-i] = state.Chain[i].Name
	}
	if strings.Join(parts, "/") != state.Source.Destination {
		return finish("RECONCILE", "local namespace differs from the original source mapping")
	}
	if state.Candidate.RootID == "" {
		return finish("RECONCILE", "remote candidate is not complete")
	}
	c := state.Candidate
	cw := c.RemoteWitness
	if !authorityMatches(a, cw, now) || state.Root.TrustGeneration != cw.TrustGeneration || state.Root.ActiveRemoteGeneration != cw.Generation {
		return finish("RECONCILE", "actual qualified server cut is unavailable or expired")
	}
	// Root is an explicit anchor. A missing root descriptor is not proof that
	// its children are absent, even if a page happened to have has_more=false.
	anchor, err := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", rootID, cw.Generation, cw.Binding.RootID)
	if err != nil || !currentRemoteBinding(anchor, cw) || anchor.Presence != "PRESENT" || anchor.Kind != "folder" || anchor.Availability != "AVAILABLE" {
		return finish("RECONCILE", "remote root anchor is unknown")
	}
	state.Parents = append(state.Parents, anchor)
	parent := cw.Binding.RootID
	for i := len(state.Chain) - 1; i > 0; i-- {
		l := state.Chain[i]
		remote, err := namespaceCandidate(ctx, tx, cw, parent, l.Name)
		if err != nil || remote == nil || !currentRemoteBinding(*remote, cw) || remote.Availability != "AVAILABLE" || remote.Kind != "folder" {
			return finish("RECONCILE", "parent namespace unavailable, ambiguous or absent")
		}
		state.Parents = append(state.Parents, *remote)
		b, be := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", rootID, l.EntryID)
		if be == nil {
			state.ParentBases = append(state.ParentBases, &b)
			if !sameParentTopologyBaseline(b, *remote, cw) || b.ParentID != l.ParentID || b.Name != l.Name || b.Kind != l.Kind {
				return finish("CONFLICT", "parent binding renamed/moved or changed since B")
			}
		} else if !errors.Is(be, sql.ErrNoRows) {
			return d, state, be
		} else {
			state.ParentBases = append(state.ParentBases, nil)
			if state.Base != nil {
				return finish("RECONCILE", "retained file B needs explicit current parent B")
			}
		}
		parent = remote.NodeID
	}
	state.Remote, err = namespaceCandidate(ctx, tx, cw, parent, state.Local.Name)
	if err != nil {
		return finish("RECONCILE", "remote namespace is ambiguous")
	}
	if state.Remote == nil {
		if state.Base != nil {
			return finish("CONFLICT", "prior remote namespace no longer exists")
		}
		return finish("CREATE", "authoritative candidate cut proves exact namespace absence; Send still needs server CAS")
	}
	e := *state.Remote
	if !currentRemoteBinding(e, cw) || e.Availability != "AVAILABLE" || e.Kind != "file" || !validHash(e.SHA256) || e.ContentVersionID == "" {
		return finish("RECONCILE", "metadata/content availability is unknown")
	}
	if state.Base != nil {
		if !sameRemoteBaseline(*state.Base, e, cw) {
			return finish("CONFLICT", "remote metadata/content/namespace changed since B")
		}
		if e.SHA256 == state.Evidence.SHA256 && e.SizeBytes == state.Evidence.SizeBytes {
			return finish("NOOP_CAPTURED", "fresh captured bytes and current R agree with trusted B")
		}
		return finish("OVERWRITE", "current R equals expected B; immutable intent must use B version")
	}
	if e.SHA256 == state.Evidence.SHA256 && e.SizeBytes == state.Evidence.SizeBytes {
		return finish("ADOPT_EQUAL", "exact captured bytes and qualified namespace agree")
	}
	return finish("CONFLICT", "unknown B with different existing remote data")
}
func mustJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }

// DecideCaptured is advisory and read-only. Outside this package no authority
// evidence can currently be created, so public imports remain RECONCILE.
func (r *RemoteImport) DecideCaptured(ctx context.Context, w SourceWitness, root, entry string, v *VerifiedSnapshot, a *RemoteAuthority, now time.Time) (CapturedDecision, error) {
	if v != nil {
		v.mu.Lock()
		defer v.mu.Unlock()
		if err := v.integrity(ctx); err != nil {
			return CapturedDecision{}, err
		}
	}
	r.sources.mu.Lock()
	defer r.sources.mu.Unlock()
	var d CapturedDecision
	err := r.store.transaction(ctx, func(tx *sql.Tx) error {
		var e error
		d, _, e = r.decideCaptured(ctx, tx, w, root, entry, v, a, now)
		return e
	})
	return d, err
}

// RevalidateCapturedDecision repeats the exact-entry snapshot semantics. It does
// not upgrade a prior RECONCILE result into Send permission or regenerate proofs.
func (r *RemoteImport) RevalidateCapturedDecision(ctx context.Context, w SourceWitness, v *VerifiedSnapshot, a *RemoteAuthority, expected CapturedDecision, now time.Time) error {
	current, err := r.DecideCaptured(ctx, w, expected.Witness.RootID, expected.Witness.EntryID, v, a, now)
	if err != nil {
		return err
	}
	if current.Kind != expected.Kind || current.OperationID != expected.OperationID || current.Witness != expected.Witness {
		return ErrStaleGeneration
	}
	return nil
}

// AdoptCaptured conditionally stores historical agreement from an exact private
// capture. It does not fabricate a publication receipt or clear newer dirty work.
// Actual activation is impossible until a qualified server adapter exists.
func (r *RemoteImport) AdoptCaptured(ctx context.Context, w SourceWitness, v *VerifiedSnapshot, a *RemoteAuthority, expected CapturedDecision, now time.Time) error {
	return r.adoptCaptured(ctx, w, v, a, expected, now, false)
}

// The opt-in executor records missing parent agreement in the same transaction
// as first file adoption. Public foundation adoption retains its original
// explicit-parent-qualification behavior. Existing parent B is never replaced.
func (r *RemoteImport) adoptCaptured(ctx context.Context, w SourceWitness, v *VerifiedSnapshot, a *RemoteAuthority, expected CapturedDecision, now time.Time, parents bool) error {
	if v == nil {
		return ErrInvalidReceipt
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.integrity(ctx); err != nil {
		return err
	}
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		d, state, err := r.decideCaptured(ctx, tx, w, expected.Witness.RootID, expected.Witness.EntryID, v, a, now)
		if err != nil {
			return err
		}
		if d.Kind != "ADOPT_EQUAL" && d.Kind != "NOOP_CAPTURED" {
			return ErrRemoteUnqualified
		}
		if d.Kind != expected.Kind || d.Witness != expected.Witness {
			return ErrStaleGeneration
		}
		e := *state.Remote
		l := state.Local
		proof := state.Evidence
		binding := state.Candidate.Binding
		base := Baseline{RootID: l.RootID, EntryID: l.EntryID, NodeID: e.NodeID, Epoch: e.Epoch, Version: e.Version, SHA256: e.SHA256, Kind: e.Kind, Presence: e.Presence, ParentID: l.ParentID, Name: l.Name, NameKey: l.NameKey, FileIdentity: l.FileIdentity, LocalGeneration: l.Generation, TrustGeneration: state.Root.TrustGeneration, SizeBytes: e.SizeBytes, LastSeq: e.LastSeq, RemoteBinding: &binding, RemoteParentID: e.ParentID, ContentVersionID: e.ContentVersionID, CaptureProof: &proof}
		if state.Base != nil {
			base.OperationID = state.Base.OperationID
			base.PublishedMTimeNS = state.Base.PublishedMTimeNS
		}
		raw, _ := json.Marshal(base)
		if _, err = tx.ExecContext(ctx, "INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?) ON CONFLICT(root_id,entry_id) DO UPDATE SET node_id=excluded.node_id,descriptor_json=excluded.descriptor_json", l.RootID, l.EntryID, e.NodeID, string(raw)); err != nil {
			return err
		}
		if parents {
			for i := len(state.Chain) - 1; i > 0; i-- {
				local := state.Chain[i]
				remote := state.Parents[len(state.Chain)-i]
				pb := Baseline{RootID: local.RootID, EntryID: local.EntryID, NodeID: remote.NodeID, Epoch: remote.Epoch, Version: remote.Version, Kind: "folder", Presence: "PRESENT", ParentID: local.ParentID, Name: local.Name, NameKey: local.NameKey, FileIdentity: local.FileIdentity, LocalGeneration: local.Generation, TrustGeneration: state.Root.TrustGeneration, SizeBytes: remote.SizeBytes, LastSeq: remote.LastSeq, RemoteBinding: &binding, RemoteParentID: remote.ParentID}
				if _, err = tx.ExecContext(ctx, "INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?) ON CONFLICT(root_id,entry_id) DO NOTHING", local.RootID, local.EntryID, remote.NodeID, string(mustJSON(pb))); err != nil {
					return err
				}
			}
		}
		if err = r.point("capture.before_adopt"); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM dirty_entries WHERE root_id=? AND entry_id=? AND observed_generation<=? AND remote_seq<=?", l.RootID, l.EntryID, l.Generation, state.Candidate.Position)
		return err
	})
}
