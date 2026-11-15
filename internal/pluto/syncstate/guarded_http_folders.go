package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"pluto/internal/syncproto"
	"time"
)

// Folder input is sealed in the existing operations registry before transport.
// Its result hash includes private server fields and remains opaque to Pluto.
type FolderHTTPOperation struct {
	Schema   string
	Identity CapturedHTTPIdentity
	Source   SourceWitness
	Remote   RemoteWitness
	Local    Observation
	Input    FolderHTTPInput
}
type FolderHTTPInput struct {
	OperationID    string               `json:"operationId"`
	IdempotencyKey string               `json:"idempotencyKey"`
	RootID         string               `json:"rootId"`
	Epoch          string               `json:"epoch"`
	BindingVersion string               `json:"bindingVersion"`
	ParentID       string               `json:"parentId"`
	Name           string               `json:"name"`
	Mode           string               `json:"mode"`
	ParentTopology []FolderHTTPTopology `json:"parentTopology"`
}
type FolderHTTPTopology struct {
	NodeID   string  `json:"nodeId"`
	ParentID *string `json:"parentId"`
	Name     string  `json:"name"`
}
type folderHTTPReceipt struct {
	Schema, OperationID, RootID, IntentHash, Status string
	Description                                     syncproto.Descriptor
}

func readFolderHTTPReceipt(raw []byte, op Operation) (folderHTTPReceipt, error) {
	var out folderHTTPReceipt
	if op.FolderHTTP == nil || op.FolderHTTP.Schema != "pluto.folder-http-operation/v1" {
		return out, ErrInvalidReceipt
	}
	v, e := syncproto.Parse(raw)
	if e != nil {
		return out, e
	}
	m, e := strictHTTPObject(v, "replayed", "result")
	if e != nil {
		return out, e
	}
	if _, ok := m["replayed"].(bool); !ok {
		return out, syncproto.ErrContract
	}
	result, e := strictHTTPObject(m["result"], "schema", "operationId", "intentHash", "rootId", "status", "description")
	if e != nil {
		return out, e
	}
	input := op.FolderHTTP.Input
	hash, e := httpText(result, "intentHash")
	if e != nil || !validHash(hash) {
		return out, ErrInvalidReceipt
	}
	status, e := httpText(result, "status")
	if e != nil || status != "CREATED" && status != "EXISTING" {
		return out, ErrInvalidReceipt
	}
	d, e := syncproto.ReadDescriptor(result["description"])
	if e != nil {
		return out, e
	}
	if result["schema"] != "saturn.catalog-folder-result.v2" || result["operationId"] != op.OperationID || result["rootId"] != input.RootID || d.Type != "folder" || d.Availability != "AVAILABLE" || d.Name != input.Name || d.ParentID == nil || *d.ParentID != input.ParentID {
		return out, ErrInvalidReceipt
	}
	return folderHTTPReceipt{"saturn.catalog-folder-result.v2", op.OperationID, input.RootID, hash, status, d}, nil
}

func (r *RemoteImport) ackHTTPFolder(ctx context.Context, op Operation, rc folderHTTPReceipt) error {
	return r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		current, e := readOperation(ctx, tx, op.OperationID)
		if e != nil {
			return e
		}
		if current.FolderHTTP == nil || current.IntentFingerprint != op.IntentFingerprint || current.SealedFingerprint != op.SealedFingerprint || current.FolderHTTP.Input.OperationID != rc.OperationID || current.FolderHTTP.Input.RootID != rc.RootID || rc.Description.ParentID == nil || *rc.Description.ParentID != current.FolderHTTP.Input.ParentID || rc.Description.Name != current.Name || !validHash(rc.IntentHash) {
			return ErrInvalidReceipt
		}
		raw := string(mustJSON(rc))
		if len(raw) > 16384 {
			return ErrSourceQuota
		}
		if current.Stage == "CLIENT_ACKED" {
			var old string
			if e = tx.QueryRowContext(ctx, "SELECT receipt_json FROM operations WHERE operation_id=?", op.OperationID).Scan(&old); e != nil {
				return e
			}
			if old != raw {
				return ErrInvalidReceipt
			}
			return nil
		}
		if current.Stage != "SUBMITTED" {
			return ErrInvalidReceipt
		}
		// Historical receipt does not replace R/B or clear current dirty/trust.
		_, e = tx.ExecContext(ctx, "UPDATE operations SET stage='CLIENT_ACKED',receipt_json=? WHERE operation_id=?", raw, op.OperationID)
		return e
	})
}

// PrepareParents resolves the exact parents of a file, or includes the leaf for
// an observed directory. Empty directories use the same durable originals.
func (s *IsolatedHTTPSession) PrepareParents(ctx context.Context, w SourceWitness, rootID, entryID string) error {
	// Existing file B cannot authorize creating replacement parents. The normal
	// captured decision still checks every current L/B/R ancestor before NOOP or
	// transport. Avoid writable preparation/adoption passes on repeat files.
	if rootID != s.root {
		return ErrIdentityConflict
	}
	var existing int
	if e := s.r.store.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM baselines WHERE root_id=? AND entry_id=? AND json_extract(descriptor_json,'$.Kind')='file')", rootID, entryID).Scan(&existing); e != nil {
		return e
	}
	if existing == 1 {
		return nil
	}
	for attempt := 0; attempt <= MaxSourceDepth; attempt++ {
		e := s.prepareParentsOnce(ctx, w, rootID, entryID)
		if !errors.Is(e, errHTTPParentsProgress) {
			return e
		}
	}
	return ErrSourceQuota
}
func (s *IsolatedHTTPSession) prepareParentsOnce(ctx context.Context, w SourceWitness, rootID, entryID string) error {
	if rootID != s.root {
		return ErrIdentityConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.freshAt.IsZero() || time.Since(s.freshAt) > 10*time.Second {
		if e := s.refresh(ctx); e != nil {
			return e
		}
	}
	var chain []Observation
	s.r.sources.mu.Lock()
	e := s.r.store.transaction(ctx, func(tx *sql.Tx) error {
		set, e := s.r.sources.checkWitness(ctx, tx, w)
		if e != nil {
			return e
		}
		if set.AttachedRootID != rootID {
			return ErrIdentityConflict
		}
		l, e := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", rootID, entryID)
		if e != nil {
			return e
		}
		chain, _, e = localPath(ctx, tx, l)
		return e
	})
	s.r.sources.mu.Unlock()
	if e != nil {
		return e
	}
	last := 1
	if len(chain) > 0 && chain[0].Kind == "folder" {
		last = 0
	}
	for i := len(chain) - 1; i >= last; i-- {
		l := chain[i]
		if !validHTTPNamespaceName(l.Name) {
			return ErrIdentityConflict
		}
		var op *Operation
		e = s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
			set, e := s.r.sources.checkWitness(ctx, tx, w)
			if e != nil {
				return e
			}
			if set.AttachedRootID != rootID {
				return ErrIdentityConflict
			}
			current, e := readJSON[Observation](ctx, tx, "SELECT descriptor_json FROM local_entries WHERE root_id=? AND entry_id=?", rootID, l.EntryID)
			if e != nil {
				return e
			}
			if current != l {
				return ErrStaleGeneration
			}
			pending, e := pendingCapturedEntry(ctx, tx, rootID, l.EntryID)
			if e != nil {
				return e
			}
			if len(pending) > 1 {
				return ErrArtifactRetained
			}
			if len(pending) == 1 {
				if pending[0].FolderHTTP == nil {
					return ErrArtifactRetained
				}
				saved := pending[0]
				op = &saved
				return nil
			}
			c, e := readCandidate(ctx, tx, rootID)
			if e != nil || !c.Valid || c.Binding != s.binding {
				return fmt.Errorf("%w: directory candidate", ErrRemoteUnqualified)
			}
			localRoot, e := readRoot(ctx, tx, rootID)
			if e != nil || localRoot.TrustGeneration != c.TrustGeneration || localRoot.ActiveRemoteGeneration != c.Generation {
				return ErrStaleGeneration
			}
			anchor, e := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", rootID, c.Generation, c.Binding.RootID)
			if e != nil || !currentRemoteBinding(anchor, c.RemoteWitness) || anchor.Kind != "folder" || anchor.Presence != "PRESENT" || anchor.Availability != "AVAILABLE" || anchor.ParentID != "" {
				return fmt.Errorf("%w: directory root anchor", ErrRemoteUnqualified)
			}
			parents := []RemoteEntry{anchor}
			parent := anchor.NodeID
			for j := len(chain) - 1; j > i; j-- {
				p, e := namespaceCandidate(ctx, tx, c.RemoteWitness, parent, chain[j].Name)
				if e != nil || p == nil || p.Kind != "folder" || p.Availability != "AVAILABLE" || !currentRemoteBinding(*p, c.RemoteWitness) {
					return fmt.Errorf("%w: directory ancestor %d: %v", ErrRemoteUnqualified, j, e)
				}
				parents = append(parents, *p)
				parent = p.NodeID
			}
			remote, e := namespaceCandidate(ctx, tx, c.RemoteWitness, parent, l.Name)
			if e != nil {
				return e
			}
			base, be := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", rootID, l.EntryID)
			if be != nil && !errors.Is(be, sql.ErrNoRows) {
				return be
			}
			if remote != nil {
				if remote.Kind != "folder" || remote.Availability != "AVAILABLE" || !currentRemoteBinding(*remote, c.RemoteWitness) {
					return ErrIdentityConflict
				}
				if be == nil {
					if !sameParentTopologyBaseline(base, *remote, c.RemoteWitness) || base.ParentID != l.ParentID || base.Name != l.Name || base.LocalGeneration != l.Generation {
						return ErrIdentityConflict
					}
					// Matching current R/B already proves this ancestor. Cache TTL
					// refresh/pruning is not required for a no-op parent.
					return nil
				}
				if e = rememberParent(ctx, tx, c.RemoteWitness, localRoot.NameCodec, parent, l.Name, remote); e != nil {
					return e
				}
				binding := c.Binding
				b := Baseline{RootID: rootID, EntryID: l.EntryID, NodeID: remote.NodeID, Epoch: remote.Epoch, Version: remote.Version, Kind: "folder", Presence: "PRESENT", ParentID: l.ParentID, Name: l.Name, NameKey: l.NameKey, FileIdentity: l.FileIdentity, LocalGeneration: l.Generation, TrustGeneration: c.TrustGeneration, SizeBytes: remote.SizeBytes, LastSeq: remote.LastSeq, RemoteBinding: &binding, RemoteParentID: remote.ParentID}
				_, e = tx.ExecContext(ctx, "INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?)", rootID, l.EntryID, remote.NodeID, string(mustJSON(b)))
				return e
			}
			if be == nil {
				return ErrIdentityConflict
			}
			if e = rememberParent(ctx, tx, c.RemoteWitness, localRoot.NameCodec, parent, l.Name, remote); e != nil {
				return e
			}
			// An ACK can precede a failed current-feed read. The immutable
			// exact-generation operation still owns this unique intent; its
			// historical outcome cannot authorize a new ID or populate current R.
			var priorID string
			pe := tx.QueryRowContext(ctx, "SELECT operation_id FROM operations WHERE root_id=? AND entry_id=? AND local_generation=? AND kind='ENSURE_DIRECTORY'", rootID, l.EntryID, l.Generation).Scan(&priorID)
			if pe == nil {
				saved, e := readOperation(ctx, tx, priorID)
				if e != nil {
					return e
				}
				if saved.FolderHTTP == nil || saved.Stage != "CLIENT_ACKED" || saved.FolderHTTP.Local != l {
					return ErrArtifactRetained
				}
				op = &saved
				return nil
			}
			if !errors.Is(pe, sql.ErrNoRows) {
				return pe
			}
			id, e := NewOperationID()
			if e != nil {
				return e
			}
			topology := make([]FolderHTTPTopology, 0, len(parents))
			for j := len(parents) - 1; j >= 0; j-- {
				p := parents[j]
				if !httpUUID(p.NodeID) || !validHTTPNamespaceName(p.Name) {
					return ErrIdentityConflict
				}
				var parentID *string
				if p.ParentID != "" {
					copy := p.ParentID
					parentID = &copy
				}
				topology = append(topology, FolderHTTPTopology{p.NodeID, parentID, p.Name})
			}
			identity := s.identity
			identity.InputBinding = c.Binding
			f := &FolderHTTPOperation{Schema: "pluto.folder-http-operation/v1", Identity: identity, Source: w, Remote: c.RemoteWitness, Local: l, Input: FolderHTTPInput{OperationID: id, IdempotencyKey: "pluto-folder-" + id, RootID: c.Binding.RootID, Epoch: c.Binding.ServerEpoch, BindingVersion: c.Binding.BindingVersion, ParentID: parent, Name: l.Name, Mode: "ensure", ParentTopology: topology}}
			input, e := httpJSON(f.Input)
			if e != nil || len(input) > 32768 {
				return ErrSourceQuota
			}
			intent := Intent{OperationID: id, RootID: rootID, EntryID: l.EntryID, Kind: "ENSURE_DIRECTORY", ExpectedEpoch: c.Binding.ServerEpoch, ExpectedAbsent: true, ParentID: l.ParentID, Name: l.Name, NameKey: l.NameKey, FileIdentity: l.FileIdentity, LocalGeneration: l.Generation, TrustGeneration: c.TrustGeneration, FolderHTTP: f}
			ih := fingerprint(intent)
			sh := fingerprint(struct{ IntentFingerprint, SHA256 string }{ih, ""})
			saved := Operation{Intent: intent, Stage: "SUBMITTED", IntentFingerprint: ih, SealedFingerprint: sh}
			_, e = tx.ExecContext(ctx, "INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage,sealed_fingerprint) VALUES(?,?,?,?,?,?,?,'SUBMITTED',?)", id, rootID, l.EntryID, l.Generation, intent.Kind, string(mustJSON(intent)), ih, sh)
			if e != nil {
				return e
			}
			op = &saved
			return s.r.point("folder.before_submit")
		})
		if e != nil {
			return e
		}
		if op != nil {
			original := op.FolderHTTP
			if !validHTTPDomain(original.Identity.Domain) || original.Identity.Origin != s.origin || original.Input.OperationID != op.OperationID || original.Input.RootID != original.Identity.InputBinding.RootID || original.Input.Epoch != original.Identity.InputBinding.ServerEpoch || original.Input.BindingVersion != original.Identity.InputBinding.BindingVersion {
				return ErrIdentityConflict
			}
			s.mu.Unlock()
			raw, e := s.sendFolder(ctx, *op)
			s.mu.Lock()
			if e != nil {
				return s.r.store.RecordRetry(ctx, op.OperationID, e)
			}
			rc, e := readFolderHTTPReceipt(raw, *op)
			if e != nil {
				return e
			}
			if e = s.r.ackHTTPFolder(ctx, *op, rc); e != nil {
				return e
			}
			if e = s.r.store.ClearRetry(ctx, op.OperationID); e != nil {
				return e
			}
			if e = s.refresh(ctx); e != nil {
				return e
			}
			// Current R agreement is a distinct subsequent qualified observation.
			// Retry this path after ACK; never substitute the historical descriptor.
			return errHTTPParentsProgress
		}
	}
	return nil
}

var errHTTPParentsProgress = errors.New("guarded HTTP parents advanced; continue bounded preparation")
