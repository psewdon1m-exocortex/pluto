package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// LocalProofKind identifies the evidence an adapter must actually qualify.
// These values do not assert that a production adapter already exists.
type LocalProofKind string

const (
	ContinuousJournal LocalProofKind = "CONTINUOUS_JOURNAL_FROM_VERIFIED_ANCHOR"
	ReconciledRoot    LocalProofKind = "COMPLETE_ROOT_RECONCILIATION_AT_CUT"
)

// LocalCutProof is an adapter certificate, not a timer or a metadata-equality
// flag. Source/device identity, trust, anchor and applied cursor are mandatory.
// EvidenceSHA256 identifies the real adapter evidence that must be retained.
type LocalCutProof struct {
	Kind                                                              LocalProofKind
	RootID, SourceIdentity, DeviceID, AnchorReceiptID, EvidenceSHA256 string
	TrustGeneration, AnchorPosition                                   int64
	Applied                                                           Cursor
}

// RemoteCutProof attests a complete snapshot followed by contiguous committed
// feed replay through this exact current cut. A per-file HEAD is not this proof.
type RemoteCutProof struct {
	RootID, ServerIdentity, RemoteRootID, SnapshotReceiptID, CutReceiptID, EvidenceSHA256 string
	TrustGeneration, ActiveGeneration, SnapshotCut, CommittedThrough                      int64
	Applied                                                                               Cursor
}

type NamespaceEvidenceKind string

const (
	NamespaceAbsentAtCut  NamespaceEvidenceKind = "AUTHORITATIVE_NAMESPACE_ABSENT_AT_CUT"
	NamespacePresentAtCut NamespaceEvidenceKind = "AUTHORITATIVE_NAMESPACE_PRESENT_AT_CUT"
	MetadataNotFound      NamespaceEvidenceKind = "METADATA_NOT_FOUND"
)

// NamespaceProof supplies bounded destination membership evidence for UNKNOWN B.
// Absence must be established at the authoritative cut, not inferred from a
// missing metadata row or an unfinished index. A present node must also be in R.
type NamespaceProof struct {
	Kind                                                                                                           NamespaceEvidenceKind
	RootID, ServerIdentity, RemoteRootID, EntryID, ParentNodeID, NameKey, NodeID, Epoch, ReceiptID, EvidenceSHA256 string
	TrustGeneration, Generation, Cut                                                                               int64
}

// ProofWindow bounds reuse after an adapter has actually revalidated both cuts.
// This is a freshness bound, never a server lock, CAS or durable publication fence.
type ProofWindow struct {
	ValidatedAt, ValidUntil time.Time
}

const (
	MaxProofAge               = 30 * time.Second
	MaxParentDepth            = 128
	MaxAncestorRecordsPerPage = 4096
	MaxAncestorBytesPerPage   = 8 * 1024 * 1024
)

type PlanningProofs struct {
	Window    ProofWindow
	Local     LocalCutProof
	Remote    RemoteCutProof
	Namespace []NamespaceProof // at most MaxBatch entries for this page
}

type DecisionKind string

const (
	DecisionVerifyLocal   DecisionKind = "VERIFY_LOCAL"
	DecisionReconcile     DecisionKind = "RECONCILE"
	DecisionNoop          DecisionKind = "NOOP"
	DecisionAdoptEqual    DecisionKind = "ADOPT_EQUAL_CONDITIONALLY"
	DecisionCreateOnly    DecisionKind = "CREATE_ONLY"
	DecisionOverwrite     DecisionKind = "OVERWRITE_EXPECTED_BASELINE"
	DecisionConflict      DecisionKind = "CONFLICT_KEEP_BOTH"
	DecisionKeepRemote    DecisionKind = "KEEP_REMOTE_NO_DELETE"
	DecisionRecover       DecisionKind = "RECOVER_IMMUTABLE_OPERATION"
	DecisionBlockedPolicy DecisionKind = "BLOCKED_BACKUP_POLICY"
)

type ExpectedRemote struct {
	Absent                 bool
	NodeID, Epoch, Version string
}

// StateWitness seals the advisory decision and the exact read-snapshot inputs.
// Future execution must revalidate it immediately before Send, then still use
// server CAS/durable operation fencing. Revalidation is not a network fence.
type StateWitness struct {
	Domain                                                  string
	StateFingerprint, ProofFingerprint, DecisionFingerprint string
}

const PlannerWitnessDomain = "pluto-dirty-plan/v1"
const parentWitnessDomain = "pluto-ancestor-binding/v1"

type AncestorOutcome string

const (
	AncestorBoundRoot  AncestorOutcome = "BOUND_ROOT_REACHED"
	AncestorMissing    AncestorOutcome = "MISSING_BINDING"
	AncestorUnknown    AncestorOutcome = "UNKNOWN_BINDING"
	AncestorPending    AncestorOutcome = "PENDING_OUTCOME"
	AncestorCycle      AncestorOutcome = "CYCLE"
	AncestorDepthLimit AncestorOutcome = "DEPTH_LIMIT"
	AncestorPageBudget AncestorOutcome = "PAGE_BUDGET"
)

type PlanDecision struct {
	RootID, EntryID string
	Kind            DecisionKind
	Reason          string
	LocalGeneration int64
	Expected        *ExpectedRemote
	Recovery        *Operation
	Witness         StateWitness
}

type PlanPage struct {
	Decisions                      []PlanDecision
	AfterEntryID                   string
	Queries, RowsRead              int
	AncestorRecords, AncestorBytes int
	AncestorBudgetExhausted        bool
}

type planningRow struct {
	State                  EntryState
	Parents                []parentBinding // immediate parent first; bounded by MaxParentDepth
	ParentDepthExceeded    bool
	AncestorBudgetExceeded bool
	AncestorOutcome        AncestorOutcome
	Pending                []Operation
}

type parentBinding struct {
	Local       *Observation
	Base        *Baseline
	Remote      *RemoteEntry
	Pending     []Operation
	Fingerprint string // immutable for the lifetime of this read-snapshot cache
}

const dirtyPlanningQuery = `SELECT d.root_id,d.entry_id,d.observed_generation,d.remote_seq,d.reasons,
l.descriptor_json,b.descriptor_json,r.descriptor_json
FROM dirty_entries d
JOIN local_entries l ON l.root_id=d.root_id AND l.entry_id=d.entry_id
LEFT JOIN baselines b ON b.root_id=d.root_id AND b.entry_id=d.entry_id
LEFT JOIN remote_entries r ON r.root_id=d.root_id AND r.generation=? AND r.node_id=b.node_id
WHERE d.root_id=? AND d.entry_id>? ORDER BY d.entry_id LIMIT ?`

const pendingPlanningQuery = `SELECT intent_json,stage,sha256,snapshot_id,intent_fingerprint,sealed_fingerprint
FROM operations INDEXED BY pending_entry_operations WHERE root_id=? AND entry_id=? AND stage<>'CLIENT_ACKED'
ORDER BY local_generation,kind LIMIT 2`

func decodeOptional[T any](raw sql.NullString) (*T, error) {
	if !raw.Valid {
		return nil, nil
	}
	var value T
	if err := json.Unmarshal([]byte(raw.String), &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func scanPlanningRows(ctx context.Context, tx *sql.Tx, root Root, after string, limit int) ([]planningRow, error) {
	rows, err := tx.QueryContext(ctx, dirtyPlanningQuery, root.ActiveRemoteGeneration, root.RootID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]planningRow, 0, limit)
	for rows.Next() {
		var row planningRow
		var dirty Dirty
		var local string
		var base, remote sql.NullString
		if err = rows.Scan(&dirty.RootID, &dirty.EntryID, &dirty.ObservedGeneration, &dirty.RemoteSeq, &dirty.Reasons, &local, &base, &remote); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(local), &row.State.Local); err != nil {
			return nil, err
		}
		row.State.Dirty = &dirty
		if row.State.Base, err = decodeOptional[Baseline](base); err != nil {
			return nil, err
		}
		if row.State.Remote, err = decodeOptional[RemoteEntry](remote); err != nil {
			return nil, err
		}
		values = append(values, row)
	}
	return values, rows.Err()
}

func pendingForEntry(ctx context.Context, tx *sql.Tx, root, entry string) ([]Operation, error) {
	records, err := pendingRecords(ctx, tx, root, entry)
	if err != nil {
		return nil, err
	}
	return decodePending(records)
}

type pendingRecord struct {
	Raw       string
	Operation Operation
}

func pendingRecords(ctx context.Context, tx *sql.Tx, root, entry string) ([]pendingRecord, error) {
	rows, err := tx.QueryContext(ctx, pendingPlanningQuery, root, entry)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]pendingRecord, 0, 2)
	for rows.Next() {
		var record pendingRecord
		op := &record.Operation
		if err = rows.Scan(&record.Raw, &op.Stage, &op.SHA256, &op.SnapshotID, &op.IntentFingerprint, &op.SealedFingerprint); err != nil {
			return nil, err
		}
		values = append(values, record)
	}
	return values, rows.Err()
}

func decodePending(records []pendingRecord) ([]Operation, error) {
	values := make([]Operation, 0, len(records))
	for _, record := range records {
		op := record.Operation
		if err := json.Unmarshal([]byte(record.Raw), &op.Intent); err != nil {
			return nil, err
		}
		values = append(values, op)
	}
	return values, nil
}

type ancestorBudget struct {
	Cached            map[string]parentBinding
	Records, Bytes    int
	Queries, RowsRead int
	Exhausted         bool
}

func newAncestorBudget() *ancestorBudget {
	return &ancestorBudget{Cached: make(map[string]parentBinding)}
}

func qualifyCuts(root Root, local, remote Cursor, proof PlanningProofs, at time.Time) error {
	window := proof.Window
	if window.ValidatedAt.IsZero() || window.ValidUntil.IsZero() || window.ValidatedAt.After(at) || !window.ValidUntil.After(at) || !window.ValidUntil.After(window.ValidatedAt) || window.ValidUntil.Sub(window.ValidatedAt) > MaxProofAge {
		return errors.New("adapter cut validation window is missing, expired or unbounded")
	}
	l := proof.Local
	r := proof.Remote
	if (l.Kind != ContinuousJournal && l.Kind != ReconciledRoot) || l.RootID != root.RootID || l.SourceIdentity != root.SourceIdentity || l.DeviceID != root.DeviceID || l.TrustGeneration != root.TrustGeneration || !validID(l.AnchorReceiptID) || !validHash(l.EvidenceSHA256) || l.AnchorPosition < 0 || l.AnchorPosition > local.Position || l.Applied != local || !local.Valid || local.Stream != "local" || !validID(local.Epoch) {
		return errors.New("local continuity/reconciliation evidence is unknown or stale")
	}
	if r.RootID != root.RootID || r.ServerIdentity != root.ServerIdentity || r.RemoteRootID != root.RemoteRootID || r.TrustGeneration != root.TrustGeneration || r.ActiveGeneration != root.ActiveRemoteGeneration || !validID(r.SnapshotReceiptID) || !validID(r.CutReceiptID) || !validHash(r.EvidenceSHA256) || r.SnapshotCut < 0 || r.SnapshotCut > r.CommittedThrough || r.CommittedThrough != remote.Position || r.Applied != remote || !remote.Valid || remote.Stream != "remote" || !validID(remote.Epoch) {
		return errors.New("authoritative snapshot/feed cut is unknown or stale")
	}
	return nil
}

func currentContent(local Observation) bool {
	return local.Kind == "file" && local.Presence == "PRESENT" && validHash(local.SHA256) && local.HashGeneration == local.Generation
}

func localEqualsBaseline(local Observation, b Baseline) bool {
	return local.Presence == b.Presence && local.Kind == b.Kind && local.ParentID == b.ParentID && local.Name == b.Name && local.NameKey == b.NameKey && local.FileIdentity == b.FileIdentity && local.SizeBytes == b.SizeBytes && local.SHA256 == b.SHA256
}

func remoteEqualsBaseline(remote RemoteEntry, b Baseline) bool {
	return remote.NodeID == b.NodeID && remote.Epoch == b.Epoch && remote.Version == b.Version && remote.Name == b.Name && remote.Kind == b.Kind && remote.Presence == b.Presence && remote.SizeBytes == b.SizeBytes && remote.SHA256 == b.SHA256 && remote.LastSeq >= b.LastSeq
}

func expectedBase(b Baseline) *ExpectedRemote {
	return &ExpectedRemote{NodeID: b.NodeID, Epoch: b.Epoch, Version: b.Version}
}
func expectedObserved(r RemoteEntry) *ExpectedRemote {
	return &ExpectedRemote{NodeID: r.NodeID, Epoch: r.Epoch, Version: r.Version}
}

const parentPlanningQuery = `SELECT l.descriptor_json,b.descriptor_json,r.descriptor_json
FROM local_entries l
LEFT JOIN baselines b ON b.root_id=l.root_id AND b.entry_id=l.entry_id
LEFT JOIN remote_entries r ON r.root_id=l.root_id AND r.generation=? AND r.node_id=b.node_id
WHERE l.root_id=? AND l.entry_id=?`

func loadParents(ctx context.Context, tx *sql.Tx, root Root, row *planningRow, budget *ancestorBudget) error {
	id := row.State.Local.ParentID
	row.AncestorOutcome = AncestorBoundRoot
	seen := make(map[string]bool)
	for id != "" {
		if seen[id] {
			row.ParentDepthExceeded = true
			row.AncestorOutcome = AncestorCycle
			break
		}
		if len(row.Parents) >= MaxParentDepth {
			row.ParentDepthExceeded = true
			row.AncestorOutcome = AncestorDepthLimit
			break
		}
		seen[id] = true
		if cached, ok := budget.Cached[id]; ok {
			row.Parents = append(row.Parents, cached)
			if cached.Local == nil || cached.Base == nil || cached.Remote == nil || len(cached.Pending) != 0 {
				row.AncestorOutcome = incompleteParentOutcome(cached)
				break
			}
			id = cached.Local.ParentID
			continue
		}
		if budget.Exhausted || len(budget.Cached) >= MaxAncestorRecordsPerPage {
			budget.Exhausted = true
			row.AncestorBudgetExceeded = true
			row.AncestorOutcome = AncestorPageBudget
			break
		}
		var local string
		var base, remote sql.NullString
		budget.Queries++
		err := tx.QueryRowContext(ctx, parentPlanningQuery, root.ActiveRemoteGeneration, root.RootID, id).Scan(&local, &base, &remote)
		if errors.Is(err, sql.ErrNoRows) {
			budget.Cached[id] = parentBinding{}
			row.Parents = append(row.Parents, parentBinding{})
			row.AncestorOutcome = AncestorMissing
			break
		}
		if err != nil {
			return err
		}
		budget.RowsRead++
		budget.Queries++
		pending, err := pendingRecords(ctx, tx, root.RootID, id)
		if err != nil {
			return err
		}
		budget.RowsRead += len(pending)
		count, bytes := 1+len(pending), len(local)
		if base.Valid {
			count++
			bytes += len(base.String)
		}
		if remote.Valid {
			count++
			bytes += len(remote.String)
		}
		for _, record := range pending {
			op := record.Operation
			bytes += len(record.Raw) + len(op.Stage) + len(op.SHA256) + len(op.SnapshotID) + len(op.IntentFingerprint) + len(op.SealedFingerprint)
		}
		if budget.Records+count > MaxAncestorRecordsPerPage || budget.Bytes+bytes > MaxAncestorBytesPerPage {
			budget.Exhausted = true
			row.AncestorBudgetExceeded = true
			row.AncestorOutcome = AncestorPageBudget
			break
		}
		budget.Records += count
		budget.Bytes += bytes
		var parent parentBinding
		var observation Observation
		if err = json.Unmarshal([]byte(local), &observation); err != nil {
			return err
		}
		parent.Local = &observation
		if parent.Base, err = decodeOptional[Baseline](base); err != nil {
			return err
		}
		if parent.Remote, err = decodeOptional[RemoteEntry](remote); err != nil {
			return err
		}
		if parent.Pending, err = decodePending(pending); err != nil {
			return err
		}
		parent.Fingerprint = parentFingerprint(parent)
		budget.Cached[id] = parent
		row.Parents = append(row.Parents, parent)
		if parent.Base == nil || parent.Remote == nil || len(parent.Pending) != 0 {
			row.AncestorOutcome = incompleteParentOutcome(parent)
			break
		}
		id = observation.ParentID
	}
	return nil
}

func incompleteParentOutcome(parent parentBinding) AncestorOutcome {
	if parent.Local == nil {
		return AncestorMissing
	}
	if len(parent.Pending) != 0 {
		return AncestorPending
	}
	return AncestorUnknown
}

func parentFingerprint(parent parentBinding) string {
	return fingerprint(struct {
		Domain  string
		Local   *Observation
		Base    *Baseline
		Remote  *RemoteEntry
		Pending []Operation
	}{parentWitnessDomain, parent.Local, parent.Base, parent.Remote, parent.Pending})
}

type parentWitness struct{ EntryID, NodeID, BindingSHA256 string }

func qualifyParents(root Root, remoteCut Cursor, child Observation, row planningRow) (string, string) {
	if row.AncestorBudgetExceeded {
		return "", "destination ancestry exceeded the snapshot page record/byte budget; new planning is required"
	}
	if row.ParentDepthExceeded || len(row.Parents) == 0 {
		return "", "destination ancestry is unknown, cyclic or exceeds the bounded depth"
	}
	id := child.ParentID
	destination := ""
	for i, parent := range row.Parents {
		l, b, r := parent.Local, parent.Base, parent.Remote
		if len(parent.Pending) != 0 {
			return "", "destination ancestor has an unresolved immutable operation; recover it before publishing descendants"
		}
		if l == nil || b == nil || r == nil || l.RootID != root.RootID || l.EntryID != id || b.RootID != root.RootID || b.EntryID != id || r.RootID != root.RootID || l.Kind != "folder" || b.Kind != "folder" || r.Kind != "folder" || l.Presence != "PRESENT" || b.Presence != "PRESENT" || r.Presence != "PRESENT" || b.TrustGeneration != root.TrustGeneration || b.Epoch != remoteCut.Epoch || b.LocalGeneration > l.Generation || !validID(b.NodeID) || !validID(b.Version) || r.Generation != root.ActiveRemoteGeneration || r.Epoch != remoteCut.Epoch || r.LastSeq > remoteCut.Position || r.LastSeq < b.LastSeq || !localEqualsBaseline(*l, *b) || !remoteEqualsBaseline(*r, *b) {
			return "", "destination ancestor L/B/R namespace, version or current trust requires reconciliation"
		}
		if i == 0 {
			destination = b.NodeID
		}
		expectedParent := root.RemoteRootID
		if l.ParentID != "" {
			if i+1 >= len(row.Parents) || row.Parents[i+1].Base == nil || row.Parents[i+1].Base.EntryID != l.ParentID {
				return "", "destination ancestor relation is unqualified"
			}
			expectedParent = row.Parents[i+1].Base.NodeID
		} else if i+1 != len(row.Parents) {
			return "", "destination ancestry does not terminate at the bound root"
		}
		if r.ParentID != expectedParent {
			return "", "destination ancestor moved; stable node identity does not authorize the new namespace"
		}
		id = l.ParentID
	}
	if id != "" {
		return "", "destination ancestry does not reach the bound root"
	}
	return destination, ""
}

func decideRow(root Root, localCut, remoteCut Cursor, row planningRow, proof PlanningProofs, namespace *NamespaceProof) PlanDecision {
	return decideRowAt(root, localCut, remoteCut, row, proof, namespace, time.Now())
}

func decideRowAt(root Root, localCut, remoteCut Cursor, row planningRow, proof PlanningProofs, namespace *NamespaceProof, at time.Time) PlanDecision {
	l := row.State.Local
	b := row.State.Base
	r := row.State.Remote
	d := row.State.Dirty
	decision := PlanDecision{RootID: root.RootID, EntryID: l.EntryID, LocalGeneration: l.Generation, Kind: DecisionReconcile}
	if l.RootID != root.RootID || !validID(l.EntryID) || l.Generation < 1 || (d != nil && (d.RootID != root.RootID || d.EntryID != l.EntryID)) || (b != nil && (b.RootID != root.RootID || b.EntryID != l.EntryID)) {
		decision.Reason = "indexed entry identities are inconsistent"
		return decision
	}
	if len(row.Pending) != 0 {
		op := row.Pending[0]
		decision.Kind = DecisionRecover
		decision.Recovery = &op
		decision.Reason = "pending outcome must recover the existing operation ID; no cancellation fence permits a new ID"
		return decision
	}
	if l.Presence == "ABSENT" {
		decision.Kind = DecisionKeepRemote
		decision.Reason = "Pluto local absence never schedules remote deletion"
		return decision
	}
	if l.Presence != "PRESENT" {
		decision.Reason = "unknown local observation does not prove absence"
		return decision
	}
	if root.NameCodec != "legacy" || root.AllowsDelete || root.MaxFileBytes != MaxFileBytes || root.MaxActiveVersions != MaxActiveVersions || l.SizeBytes > MaxFileBytes {
		decision.Kind = DecisionBlockedPolicy
		decision.Reason = "backup bounds, namespace or no-delete policy are not satisfied"
		return decision
	}
	if d == nil || d.ObservedGeneration != l.Generation {
		decision.Reason = "dirty generation does not cover the current local observation"
		return decision
	}
	if err := qualifyCuts(root, localCut, remoteCut, proof, at); err != nil {
		decision.Reason = err.Error()
		return decision
	}
	if d.RemoteSeq > remoteCut.Position {
		decision.Reason = "authoritative cut is older than applied dirty work"
		return decision
	}
	if l.Kind == "file" && !currentContent(l) {
		decision.Kind = DecisionVerifyLocal
		decision.Reason = "current local generation has no verified content hash"
		return decision
	}
	if b != nil && (b.TrustGeneration != root.TrustGeneration || b.Epoch != remoteCut.Epoch || b.LocalGeneration > l.Generation) {
		decision.Reason = "retained baseline belongs to an invalidated trust/epoch/generation"
		return decision
	}
	parent := root.RemoteRootID
	if l.ParentID != "" {
		var reason string
		parent, reason = qualifyParents(root, remoteCut, l, row)
		if reason != "" {
			decision.Reason = reason
			return decision
		}
	}
	if b == nil {
		if namespace == nil || namespace.Kind == MetadataNotFound {
			decision.Reason = "unknown baseline needs authoritative destination membership; metadata not_found is not absence"
			return decision
		}
		if namespace.RootID != root.RootID || namespace.ServerIdentity != root.ServerIdentity || namespace.RemoteRootID != root.RemoteRootID || namespace.TrustGeneration != root.TrustGeneration || namespace.EntryID != l.EntryID || namespace.ParentNodeID != parent || namespace.NameKey != l.NameKey || namespace.Epoch != remoteCut.Epoch || namespace.Generation != root.ActiveRemoteGeneration || namespace.Cut != remoteCut.Position || !validID(namespace.ReceiptID) || !validHash(namespace.EvidenceSHA256) {
			decision.Reason = "namespace membership proof is stale or belongs to another destination"
			return decision
		}
		if namespace.Kind == NamespaceAbsentAtCut {
			if namespace.NodeID != "" {
				decision.Reason = "absence proof carries an existing node identity"
				return decision
			}
			decision.Kind = DecisionCreateOnly
			decision.Expected = &ExpectedRemote{Absent: true, Epoch: remoteCut.Epoch}
			decision.Reason = "destination absence is qualified at the authoritative cut"
			return decision
		}
		if namespace.Kind != NamespacePresentAtCut || r == nil || r.NodeID != namespace.NodeID || r.RootID != root.RootID || r.ParentID != parent || r.Name != l.Name || r.Generation != root.ActiveRemoteGeneration || r.Epoch != remoteCut.Epoch || r.LastSeq > remoteCut.Position || r.Presence != "PRESENT" {
			decision.Reason = "present destination lacks the authoritative indexed descriptor"
			return decision
		}
		if r.Kind == l.Kind && r.SizeBytes == l.SizeBytes && (l.Kind == "folder" || (validHash(r.SHA256) && r.SHA256 == l.SHA256)) {
			decision.Kind = DecisionAdoptEqual
			decision.Expected = expectedObserved(*r)
			decision.Reason = "unknown baseline matches verified content or directory identity/type/root; conditional adoption required"
			return decision
		}
		decision.Kind = DecisionConflict
		decision.Reason = "unknown baseline destination differs; preserve both"
		return decision
	}
	if r == nil || r.RootID != root.RootID || r.Generation != root.ActiveRemoteGeneration || r.Epoch != remoteCut.Epoch || r.LastSeq > remoteCut.Position || r.LastSeq < d.RemoteSeq {
		decision.Reason = "baseline node lacks authoritative R at a cut covering dirty work"
		return decision
	}
	if r.Presence == "PRESENT" && r.ParentID != parent {
		decision.Kind = DecisionConflict
		decision.Reason = "remote namespace parent diverged; content equality does not adopt a move"
		return decision
	}
	localEqual := localEqualsBaseline(l, *b)
	remoteEqual := remoteEqualsBaseline(*r, *b)
	if l.Kind == "folder" {
		decision.Reason = "directory reconciliation/adoption requires namespace identity evidence; no content-hash NOOP is manufactured"
		return decision
	}
	if localEqual && remoteEqual {
		decision.Kind = DecisionNoop
		decision.Reason = "qualified current content/namespace and R both equal the current-trust baseline"
		return decision
	}
	if r.Presence == "PRESENT" && r.Kind == l.Kind && r.Name == l.Name && r.SizeBytes == l.SizeBytes && validHash(r.SHA256) && r.SHA256 == l.SHA256 && l.ParentID == b.ParentID && l.NameKey == b.NameKey {
		decision.Kind = DecisionAdoptEqual
		decision.Expected = expectedObserved(*r)
		decision.Reason = "current verified local content equals authoritative R; adopt under current R version"
		return decision
	}
	if !localEqual && remoteEqual && l.ParentID == b.ParentID && l.Name == b.Name && l.NameKey == b.NameKey && l.Kind == b.Kind {
		decision.Kind = DecisionOverwrite
		decision.Expected = expectedBase(*b)
		decision.Reason = "local content changed while authoritative R remains exactly B"
		return decision
	}
	decision.Kind = DecisionConflict
	if localEqual {
		decision.Reason = "R diverged from B; Pluto preserves the remote change"
	} else {
		decision.Reason = "both sides or namespace diverged; preserve both and reconcile"
	}
	return decision
}

func sealDecision(root Root, local, remote Cursor, row planningRow, proof PlanningProofs, namespace *NamespaceProof, decision PlanDecision) PlanDecision {
	// Each cached parent descriptor is hashed once under this same read snapshot.
	// Seal ordered hashes rather than repeatedly serializing long ancestor names.
	parents := make([]parentWitness, 0, len(row.Parents))
	for _, parent := range row.Parents {
		value := parentWitness{BindingSHA256: parent.Fingerprint}
		if parent.Local != nil {
			value.EntryID = parent.Local.EntryID
		}
		if parent.Base != nil {
			value.NodeID = parent.Base.NodeID
		}
		if value.BindingSHA256 == "" {
			value.BindingSHA256 = parentFingerprint(parent)
		}
		parents = append(parents, value)
	}
	decision.Witness = StateWitness{Domain: PlannerWitnessDomain, StateFingerprint: fingerprint(struct {
		Domain                                      string
		Root                                        Root
		TerminalRoot                                RootBinding
		Local, Remote                               Cursor
		State                                       EntryState
		Pending                                     []Operation
		Parents                                     []parentWitness
		ParentDepthExceeded, AncestorBudgetExceeded bool
		AncestorOutcome                             AncestorOutcome
	}{"pluto-plan-state/v1", root, root.RootBinding, local, remote, row.State, row.Pending, parents, row.ParentDepthExceeded, row.AncestorBudgetExceeded, row.AncestorOutcome}), ProofFingerprint: fingerprint(struct {
		Domain    string
		Local     LocalCutProof
		Remote    RemoteCutProof
		Window    ProofWindow
		Namespace *NamespaceProof
	}{"pluto-plan-proof/v1", proof.Local, proof.Remote, proof.Window, namespace})}
	decision.Witness.DecisionFingerprint = decisionFingerprint(decision)
	return decision
}

func decisionFingerprint(decision PlanDecision) string {
	decision.Witness = StateWitness{}
	return fingerprint(struct {
		Domain   string
		Decision PlanDecision
	}{"pluto-plan-decision/v1", decision})
}

func namespaceMap(proof PlanningProofs) (map[string]*NamespaceProof, error) {
	if err := checkBatch(len(proof.Namespace)); err != nil {
		return nil, err
	}
	values := make(map[string]*NamespaceProof, len(proof.Namespace))
	for i := range proof.Namespace {
		entry := &proof.Namespace[i]
		if !validID(entry.EntryID) || values[entry.EntryID] != nil {
			return nil, errors.New("namespace evidence must have unique bounded entry identities")
		}
		values[entry.EntryID] = entry
	}
	return values, nil
}

func loadNamespaceRemote(ctx context.Context, tx *sql.Tx, root Root, row *planningRow, proof *NamespaceProof) (int, error) {
	if row.State.Base != nil || proof == nil || proof.Kind != NamespacePresentAtCut {
		return 0, nil
	}
	if !validID(proof.NodeID) {
		return 0, nil
	}
	remote, err := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", root.RootID, root.ActiveRemoteGeneration, proof.NodeID)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, nil
	}
	if err != nil {
		return 1, err
	}
	row.State.Remote = &remote
	return 1, nil
}

// PlanDirtyPage reads a bounded indexed page under one deferred read snapshot.
// It writes no state, reads no source content, and performs no network requests.
func (s *Store) PlanDirtyPage(ctx context.Context, rootID, after string, limit int, proof PlanningProofs) (PlanPage, error) {
	page := PlanPage{AfterEntryID: after}
	if !validID(rootID) || (after != "" && !validID(after)) || limit < 1 || limit > MaxBatch {
		return page, errors.New("planner keyset/page bounds invalid")
	}
	namespaces, err := namespaceMap(proof)
	if err != nil {
		return page, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	root, err := readRoot(ctx, tx, rootID)
	if err != nil {
		return page, err
	}
	page.Queries++
	local, err := readCursor(ctx, tx, rootID, "local")
	if err != nil {
		return page, err
	}
	page.Queries++
	remote, err := readCursor(ctx, tx, rootID, "remote")
	if err != nil {
		return page, err
	}
	page.Queries++
	rows, err := scanPlanningRows(ctx, tx, root, after, limit)
	if err != nil {
		return page, err
	}
	page.Queries++
	page.Decisions = make([]PlanDecision, 0, len(rows))
	page.RowsRead = len(rows)
	budget := newAncestorBudget()
	for i := range rows {
		row := &rows[i]
		if err := loadParents(ctx, tx, root, row, budget); err != nil {
			return page, err
		}
		row.Pending, err = pendingForEntry(ctx, tx, rootID, row.State.Local.EntryID)
		if err != nil {
			return page, err
		}
		page.Queries++
		page.RowsRead += len(row.Pending)
		namespace := namespaces[row.State.Local.EntryID]
		count, err := loadNamespaceRemote(ctx, tx, root, row, namespace)
		if err != nil {
			return page, err
		}
		page.Queries += count
		if count != 0 && row.State.Remote != nil {
			page.RowsRead++
		}
		decision := decideRow(root, local, remote, *row, proof, namespace)
		page.Decisions = append(page.Decisions, sealDecision(root, local, remote, *row, proof, namespace, decision))
		page.AfterEntryID = row.State.Local.EntryID
	}
	page.Queries += budget.Queries
	page.RowsRead += budget.RowsRead
	page.AncestorRecords = budget.Records
	page.AncestorBytes = budget.Bytes
	page.AncestorBudgetExhausted = budget.Exhausted
	if err = tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}

// RevalidatePlan rejects a changed advisory decision/input/state. A caller must
// still use immutable operation identity and server-side publication CAS/fencing;
// another local event may arrive after this read transaction has ended.
func (s *Store) RevalidatePlan(ctx context.Context, decision PlanDecision, proof PlanningProofs) error {
	if decision.Witness.Domain != PlannerWitnessDomain || !validID(decision.RootID) || !validID(decision.EntryID) || !validHash(decision.Witness.StateFingerprint) || decisionFingerprint(decision) != decision.Witness.DecisionFingerprint {
		return ErrStaleGeneration
	}
	// The exact key is queried, rather than fetching a neighboring keyset page.
	namespaces, err := namespaceMap(proof)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	root, err := readRoot(ctx, tx, decision.RootID)
	if err != nil {
		return err
	}
	local, err := readCursor(ctx, tx, root.RootID, "local")
	if err != nil {
		return err
	}
	remote, err := readCursor(ctx, tx, root.RootID, "remote")
	if err != nil {
		return err
	}
	query := `SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?`
	var row planningRow
	row.State.Local, err = readJSON[Observation](ctx, tx, query, root.RootID, decision.EntryID)
	if err != nil {
		return ErrStaleGeneration
	}
	row.State.Base, err = optionalRecord[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", root.RootID, decision.EntryID)
	if err != nil {
		return err
	}
	if row.State.Base != nil {
		row.State.Remote, err = optionalRecord[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", root.RootID, root.ActiveRemoteGeneration, row.State.Base.NodeID)
		if err != nil {
			return err
		}
	}
	var dirty Dirty
	err = tx.QueryRowContext(ctx, "SELECT root_id,entry_id,observed_generation,remote_seq,reasons FROM dirty_entries WHERE root_id=? AND entry_id=?", root.RootID, decision.EntryID).Scan(&dirty.RootID, &dirty.EntryID, &dirty.ObservedGeneration, &dirty.RemoteSeq, &dirty.Reasons)
	if err != nil {
		return ErrStaleGeneration
	}
	row.State.Dirty = &dirty
	if err = loadParents(ctx, tx, root, &row, newAncestorBudget()); err != nil {
		return err
	}
	row.Pending, err = pendingForEntry(ctx, tx, root.RootID, decision.EntryID)
	if err != nil {
		return err
	}
	namespace := namespaces[decision.EntryID]
	if _, err = loadNamespaceRemote(ctx, tx, root, &row, namespace); err != nil {
		return err
	}
	current := sealDecision(root, local, remote, row, proof, namespace, decideRow(root, local, remote, row, proof, namespace))
	if current.Witness != decision.Witness {
		return fmt.Errorf("plan state/input changed: %w", ErrStaleGeneration)
	}
	return tx.Commit()
}

func optionalRecord[T any](ctx context.Context, q queryer, query string, args ...any) (*T, error) {
	value, err := readJSON[T](ctx, q, query, args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}
