package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func plannerModel() (Root, Cursor, Cursor, planningRow, PlanningProofs) {
	root := Root{RootBinding: testBinding, TrustGeneration: 1, ActiveRemoteGeneration: 1, Trust: TrustRequired, NameCodec: "legacy", MaxFileBytes: MaxFileBytes, MaxActiveVersions: MaxActiveVersions}
	local := Cursor{RootID: "root", Stream: "local", Epoch: "local-journal", Position: 42, Valid: true}
	remote := Cursor{RootID: "root", Stream: "remote", Epoch: "remote-epoch", Position: 100, Valid: true}
	hash := hashBytes([]byte("one"))
	l := Observation{RootID: "root", EntryID: "file", Name: "file", NameKey: "file", Kind: "file", Presence: "PRESENT", FileIdentity: "inode", Generation: 7, ExpectedGeneration: 6, HashGeneration: 7, SHA256: hash, SizeBytes: 3}
	b := Baseline{RootID: "root", EntryID: "file", NodeID: "node-file", Name: "file", NameKey: "file", Kind: "file", Presence: "PRESENT", FileIdentity: "inode", LocalGeneration: 6, TrustGeneration: 1, SHA256: hash, SizeBytes: 3, Epoch: remote.Epoch, Version: "v1", LastSeq: 90}
	r := RemoteEntry{RootID: "root", NodeID: "node-file", ParentID: root.RemoteRootID, Name: "file", Kind: "file", Presence: "PRESENT", SHA256: hash, SizeBytes: 3, Epoch: remote.Epoch, Version: "v1", LastSeq: 90, Generation: 1}
	row := planningRow{State: EntryState{Local: l, Base: &b, Remote: &r, Dirty: &Dirty{RootID: "root", EntryID: "file", ObservedGeneration: 7, RemoteSeq: 90, Reasons: "remote"}}}
	proof := fixturePlanningProof(root, local, remote)
	return root, local, remote, row, proof
}

// This certificate is a fixture for the planner boundary, not proof that Pluto
// currently has a qualified production journal/snapshot adapter.
func fixturePlanningProof(root Root, local, remote Cursor) PlanningProofs {
	return PlanningProofs{Window: ProofWindow{ValidatedAt: time.Now(), ValidUntil: time.Now().Add(MaxProofAge - time.Millisecond)}, Local: LocalCutProof{Kind: ContinuousJournal, RootID: root.RootID, SourceIdentity: root.SourceIdentity, DeviceID: root.DeviceID, AnchorReceiptID: "fixture-local-anchor", EvidenceSHA256: hashBytes([]byte("fixture-qualified-local-evidence")), TrustGeneration: root.TrustGeneration, Applied: local}, Remote: RemoteCutProof{RootID: root.RootID, ServerIdentity: root.ServerIdentity, RemoteRootID: root.RemoteRootID, SnapshotReceiptID: "fixture-snapshot", CutReceiptID: "fixture-cut", EvidenceSHA256: hashBytes([]byte("fixture-qualified-remote-evidence")), TrustGeneration: root.TrustGeneration, ActiveGeneration: root.ActiveRemoteGeneration, CommittedThrough: remote.Position, Applied: remote}}
}

func fixtureNamespace(root Root, l Observation, remote Cursor, kind NamespaceEvidenceKind) *NamespaceProof {
	return &NamespaceProof{Kind: kind, RootID: root.RootID, ServerIdentity: root.ServerIdentity, RemoteRootID: root.RemoteRootID, TrustGeneration: root.TrustGeneration, EntryID: l.EntryID, ParentNodeID: root.RemoteRootID, NameKey: l.NameKey, Epoch: remote.Epoch, ReceiptID: "fixture-membership", EvidenceSHA256: hashBytes([]byte("fixture-namespace-evidence")), Generation: root.ActiveRemoteGeneration, Cut: remote.Position}
}

func TestPlannerDecisionMatrix(t *testing.T) {
	type inputs struct {
		root          Root
		local, remote Cursor
		row           planningRow
		proof         PlanningProofs
		namespace     *NamespaceProof
	}
	cases := []struct {
		name   string
		want   DecisionKind
		mutate func(*inputs)
	}{
		{"qualified-noop", DecisionNoop, func(*inputs) {}},
		{"mtime-size-only", DecisionVerifyLocal, func(i *inputs) { i.row.State.Local.SHA256 = ""; i.row.State.Local.HashGeneration = 0 }},
		{"stale-hash-generation", DecisionVerifyLocal, func(i *inputs) { i.row.State.Local.HashGeneration-- }},
		{"local-changed-R-base", DecisionOverwrite, func(i *inputs) { i.row.State.Local.SHA256 = hashBytes([]byte("two")) }},
		{"local-same-remote-changed", DecisionConflict, func(i *inputs) {
			i.row.State.Remote.SHA256 = hashBytes([]byte("two"))
			i.row.State.Remote.Version = "v2"
		}},
		{"both-changed-conflict", DecisionConflict, func(i *inputs) {
			i.row.State.Local.SHA256 = hashBytes([]byte("two"))
			i.row.State.Remote.SHA256 = hashBytes([]byte("new"))
			i.row.State.Remote.Version = "v2"
		}},
		{"both-converged", DecisionAdoptEqual, func(i *inputs) {
			i.row.State.Local.SHA256 = hashBytes([]byte("two"))
			i.row.State.Remote.SHA256 = i.row.State.Local.SHA256
			i.row.State.Remote.Version = "v2"
		}},
		{"unknown-baseline-without-membership", DecisionReconcile, func(i *inputs) { i.row.State.Base = nil; i.row.State.Remote = nil }},
		{"not-found-is-not-absence", DecisionReconcile, func(i *inputs) {
			i.row.State.Base = nil
			i.row.State.Remote = nil
			i.namespace = fixtureNamespace(i.root, i.row.State.Local, i.remote, MetadataNotFound)
		}},
		{"qualified-absent-create", DecisionCreateOnly, func(i *inputs) {
			i.row.State.Base = nil
			i.row.State.Remote = nil
			i.namespace = fixtureNamespace(i.root, i.row.State.Local, i.remote, NamespaceAbsentAtCut)
		}},
		{"unknown-baseline-equal-content", DecisionAdoptEqual, func(i *inputs) {
			i.row.State.Base = nil
			i.namespace = fixtureNamespace(i.root, i.row.State.Local, i.remote, NamespacePresentAtCut)
			i.namespace.NodeID = i.row.State.Remote.NodeID
		}},
		{"unknown-baseline-different-content", DecisionConflict, func(i *inputs) {
			i.row.State.Base = nil
			i.row.State.Remote.SHA256 = hashBytes([]byte("two"))
			i.namespace = fixtureNamespace(i.root, i.row.State.Local, i.remote, NamespacePresentAtCut)
			i.namespace.NodeID = i.row.State.Remote.NodeID
		}},
		{"local-absent-retains-remote", DecisionKeepRemote, func(i *inputs) { i.row.State.Local.Presence = "ABSENT"; i.proof = PlanningProofs{} }},
		{"local-unknown", DecisionReconcile, func(i *inputs) { i.row.State.Local.Presence = "UNKNOWN" }},
		{"256-MiB-policy", DecisionBlockedPolicy, func(i *inputs) { i.row.State.Local.SizeBytes = MaxFileBytes + 1 }},
		{"namespace-policy", DecisionBlockedPolicy, func(i *inputs) { i.root.NameCodec = "unqualified-new-codec" }},
		{"remote-deleted-is-conflict", DecisionConflict, func(i *inputs) { i.row.State.Remote.Presence = "ABSENT"; i.row.State.Remote.Version = "v2" }},
		{"same-content-remote-move", DecisionConflict, func(i *inputs) { i.row.State.Remote.ParentID = "other-parent"; i.row.State.Remote.Version = "v2" }},
		{"local-rename-not-overwrite", DecisionConflict, func(i *inputs) { i.row.State.Local.Name = "renamed"; i.row.State.Local.NameKey = "renamed" }},
		{"local-parent-unknown", DecisionReconcile, func(i *inputs) { i.row.State.Local.ParentID = "unpublished-parent" }},
		{"missing-authoritative-R", DecisionReconcile, func(i *inputs) { i.row.State.Remote = nil }},
		{"old-baseline-trust", DecisionReconcile, func(i *inputs) { i.row.State.Base.TrustGeneration = 0 }},
		{"old-baseline-epoch", DecisionReconcile, func(i *inputs) { i.row.State.Base.Epoch = "old-epoch" }},
		{"baseline-from-future-L", DecisionReconcile, func(i *inputs) { i.row.State.Base.LocalGeneration = 8 }},
		{"directory-no-fake-hash-noop", DecisionReconcile, func(i *inputs) {
			i.row.State.Local.Kind = "folder"
			i.row.State.Local.SHA256 = ""
			i.row.State.Local.SizeBytes = 0
			i.row.State.Base.Kind = "folder"
			i.row.State.Base.SHA256 = ""
			i.row.State.Base.SizeBytes = 0
			i.row.State.Remote.Kind = "folder"
			i.row.State.Remote.SHA256 = ""
			i.row.State.Remote.SizeBytes = 0
		}},
		{"unknown-directory-identity-adoption", DecisionAdoptEqual, func(i *inputs) {
			i.row.State.Base = nil
			i.row.State.Local.Kind = "folder"
			i.row.State.Local.SHA256 = ""
			i.row.State.Local.SizeBytes = 0
			i.row.State.Remote.Kind = "folder"
			i.row.State.Remote.SHA256 = ""
			i.row.State.Remote.SizeBytes = 0
			i.namespace = fixtureNamespace(i.root, i.row.State.Local, i.remote, NamespacePresentAtCut)
			i.namespace.NodeID = i.row.State.Remote.NodeID
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, local, remote, row, proof := plannerModel()
			i := inputs{root: root, local: local, remote: remote, row: row, proof: proof}
			tc.mutate(&i)
			got := decideRow(i.root, i.local, i.remote, i.row, i.proof, i.namespace)
			if got.Kind != tc.want {
				t.Fatalf("got %s (%s), want %s", got.Kind, got.Reason, tc.want)
			}
			if got.Kind == DecisionOverwrite && (got.Expected == nil || got.Expected.Version != i.row.State.Base.Version || got.Expected.Epoch != i.row.State.Base.Epoch) {
				t.Fatal("overwrite expected came from R instead of B", got)
			}
			if i.root.EngineReady || i.root.AllowsDelete {
				t.Fatal("planner enabled engine or delete")
			}
		})
	}
}

func TestPlannerCutsAndMembershipCannotBeReused(t *testing.T) {
	for _, change := range []string{"missing-local-proof", "wrong-source", "wrong-device", "wrong-root", "wrong-server", "wrong-remote-root", "wrong-trust", "wrong-generation", "wrong-local-epoch", "wrong-remote-epoch", "older-local-cut", "older-remote-cut", "dirty-after-cut", "dirty-local-generation", "invalid-local-cursor", "invalid-remote-cursor", "remote-after-cut", "remote-before-dirty"} {
		t.Run(change, func(t *testing.T) {
			root, local, remote, row, proof := plannerModel()
			switch change {
			case "missing-local-proof":
				proof.Local.Kind = ""
			case "wrong-source":
				proof.Local.SourceIdentity = "other-source"
			case "wrong-device":
				proof.Local.DeviceID = "other-device"
			case "wrong-root":
				proof.Local.RootID = "other-root"
			case "wrong-server":
				proof.Remote.ServerIdentity = "other-server"
			case "wrong-remote-root":
				proof.Remote.RemoteRootID = "other-destination"
			case "wrong-trust":
				proof.Remote.TrustGeneration++
			case "wrong-generation":
				proof.Remote.ActiveGeneration++
			case "wrong-local-epoch":
				proof.Local.Applied.Epoch = "other-local-journal"
			case "wrong-remote-epoch":
				proof.Remote.Applied.Epoch = "other-remote-epoch"
			case "older-local-cut":
				proof.Local.Applied.Position--
			case "older-remote-cut":
				proof.Remote.CommittedThrough--
				proof.Remote.Applied.Position--
			case "dirty-after-cut":
				row.State.Dirty.RemoteSeq = remote.Position + 1
			case "dirty-local-generation":
				row.State.Dirty.ObservedGeneration++
			case "invalid-local-cursor":
				local.Valid = false
				proof.Local.Applied = local
			case "invalid-remote-cursor":
				remote.Valid = false
				proof.Remote.Applied = remote
			case "remote-after-cut":
				row.State.Remote.LastSeq = remote.Position + 1
			case "remote-before-dirty":
				row.State.Remote.LastSeq = row.State.Dirty.RemoteSeq - 1
			}
			if got := decideRow(root, local, remote, row, proof, nil); got.Kind != DecisionReconcile {
				t.Fatalf("stale/foreign proof allowed %s: %s", got.Kind, got.Reason)
			}
		})
	}
	for _, change := range []string{"cut", "root", "server", "trust", "parent", "name", "present-node-in-absent"} {
		t.Run("namespace-"+change, func(t *testing.T) {
			root, local, remote, row, proof := plannerModel()
			row.State.Base = nil
			row.State.Remote = nil
			n := fixtureNamespace(root, row.State.Local, remote, NamespaceAbsentAtCut)
			switch change {
			case "cut":
				n.Cut--
			case "root":
				n.RootID = "other"
			case "server":
				n.ServerIdentity = "other"
			case "trust":
				n.TrustGeneration++
			case "parent":
				n.ParentNodeID = "other"
			case "name":
				n.NameKey = "other"
			case "present-node-in-absent":
				n.NodeID = "existing-node"
			}
			if got := decideRow(root, local, remote, row, proof, n); got.Kind != DecisionReconcile {
				t.Fatal("reused/invalid membership proof", got)
			}
		})
	}
}

func TestPlannerPendingOutcomesAlwaysRecoverSameImmutableID(t *testing.T) {
	// Only the first three stages are in the current local schema. The pure
	// classifier is deliberately conservative for future durable pending stages.
	for _, stage := range []string{"PLANNED", "SEALED", "SUBMITTED", "Ready", "RetryWait", "CancelRequested", "Received", "UNRECOGNIZED_PENDING"} {
		t.Run(stage, func(t *testing.T) {
			root, local, remote, row, _ := plannerModel()
			row.Pending = []Operation{{Intent: Intent{OperationID: "same-immutable-id", RootID: "root", EntryID: "file", LocalGeneration: 1, TrustGeneration: 1}, Stage: stage, IntentFingerprint: hashBytes([]byte("fixed-intent"))}}
			root.TrustGeneration = 2
			row.State.Local.Generation = 9
			row.State.Remote.Version = "conflicting-v2"
			got := decideRow(root, local, remote, row, PlanningProofs{}, nil)
			if got.Kind != DecisionRecover || got.Recovery == nil || got.Recovery.OperationID != "same-immutable-id" || got.Recovery.LocalGeneration != 1 || got.Expected != nil {
				t.Fatal("pending intent was cancelled/replaced/replanned", got)
			}
		})
	}
}

func plannerFixture(t *testing.T) (*Store, PlanningProofs) {
	t.Helper()
	s, _ := stateFixture(t)
	observation := fileObservation("file", "file")
	observation.SHA256 = hashBytes([]byte("one"))
	observation.HashGeneration = 1
	capture(t, s, observation)
	op := planned(t, s, "initial-op", "file")
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Cursor(testContext, "root", "remote")
	next := before
	next.Epoch = "remote-epoch"
	next.Position = 1
	next.Valid = true
	r := RemoteEntry{RootID: "root", NodeID: "node-file", ParentID: testBinding.RemoteRootID, Name: "file", Kind: "file", Presence: "PRESENT", Epoch: next.Epoch, Version: "v1", Generation: 1, LastSeq: 1, SizeBytes: 3, SHA256: op.SHA256}
	if err := s.ApplyRemote(testContext, 1, before, next, []RemoteEntry{r}); err != nil {
		t.Fatal(err)
	}
	root, _ := s.Root(testContext, "root")
	local, _ := s.Cursor(testContext, "root", "local")
	remote, _ := s.Cursor(testContext, "root", "remote")
	return s, fixturePlanningProof(root, local, remote)
}

func TestPlannerDatabaseSnapshotWitnessAndLateState(t *testing.T) {
	for _, change := range []string{"none", "local", "remote", "trust", "receipt", "decision-mutation", "proof-mutation"} {
		t.Run(change, func(t *testing.T) {
			s, proof := plannerFixture(t)
			var beforeChanges, afterChanges int64
			if err := s.db.QueryRow("SELECT total_changes()").Scan(&beforeChanges); err != nil {
				t.Fatal(err)
			}
			page, err := s.PlanDirtyPage(testContext, "root", "", 10, proof)
			if err != nil || len(page.Decisions) != 1 || page.Decisions[0].Kind != DecisionNoop || page.Queries != 5 || page.RowsRead != 1 {
				t.Fatal("indexed qualified plan", page, err)
			}
			if err = s.db.QueryRow("SELECT total_changes()").Scan(&afterChanges); err != nil || beforeChanges != afterChanges {
				t.Fatal("planner wrote durable state", beforeChanges, afterChanges, err)
			}
			decision := page.Decisions[0]
			switch change {
			case "local":
				entry := fileObservation("file", "file")
				entry.ExpectedGeneration = 1
				entry.SHA256 = hashBytes([]byte("one"))
				entry.HashGeneration = 2
				capture(t, s, entry)
			case "remote":
				before, _ := s.Cursor(testContext, "root", "remote")
				next := before
				next.Position++
				r := RemoteEntry{RootID: "root", NodeID: "node-file", ParentID: testBinding.RemoteRootID, Name: "file", Kind: "file", Presence: "PRESENT", Epoch: next.Epoch, Version: "v2", Generation: 1, LastSeq: next.Position, SizeBytes: 3, SHA256: hashBytes([]byte("two"))}
				if err = s.ApplyRemote(testContext, 1, before, next, []RemoteEntry{r}); err != nil {
					t.Fatal(err)
				}
			case "trust":
				if err = s.InvalidateTrust(testContext, "root", 1); err != nil {
					t.Fatal(err)
				}
			case "receipt":
				entry := fileObservation("file", "file")
				entry.ExpectedGeneration = 1
				entry.SHA256 = hashBytes([]byte("one"))
				entry.HashGeneration = 2
				capture(t, s, entry)
				op := planned(t, s, "next-op", "file")
				if err = s.Ack(testContext, receipt(op, 2, "v2")); err != nil {
					t.Fatal(err)
				}
			case "decision-mutation":
				decision.Kind = DecisionOverwrite
				decision.Expected = &ExpectedRemote{NodeID: "node-file", Epoch: "remote-epoch", Version: "fresh-v999"}
			case "proof-mutation":
				proof.Local.EvidenceSHA256 = hashBytes([]byte("other-evidence"))
			}
			err = s.RevalidatePlan(testContext, decision, proof)
			if change == "none" && err != nil {
				t.Fatal("unchanged witness rejected", err)
			}
			if change != "none" && !errors.Is(err, ErrStaleGeneration) {
				t.Fatal("late/mutated plan was authorized", change, err)
			}
		})
	}
}

func TestPlannerRecoversDurableIntentAcrossNewGenerationAndTrust(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "pending-op", "file")
	entry := fileObservation("file", "file")
	entry.ExpectedGeneration = 1
	capture(t, s, entry)
	if err := s.InvalidateTrust(testContext, "root", 1); err != nil {
		t.Fatal(err)
	}
	page, err := s.PlanDirtyPage(testContext, "root", "", 1, PlanningProofs{})
	if err != nil || len(page.Decisions) != 1 || page.Decisions[0].Kind != DecisionRecover || page.Decisions[0].Recovery.OperationID != op.OperationID {
		t.Fatal("durable pending intent lost", page, err)
	}
	if err = s.RevalidatePlan(testContext, page.Decisions[0], PlanningProofs{}); err != nil {
		t.Fatal("same-ID status recovery witness rejected", err)
	}
	pending, err := s.PendingPage(testContext, "root", "", 10)
	if err != nil || len(pending) != 1 || pending[0].OperationID != op.OperationID {
		t.Fatal("planner changed pending intents", pending, err)
	}
}

func TestPlannerBoundsUnknownNamespaceAndCancellation(t *testing.T) {
	s, _ := stateFixture(t)
	entry := fileObservation("file", "file")
	entry.SHA256 = hashBytes([]byte("one"))
	entry.HashGeneration = 1
	capture(t, s, entry)
	before, _ := s.Cursor(testContext, "root", "remote")
	next := before
	next.Epoch = "remote-epoch"
	next.Valid = true
	if err := s.ApplyRemote(testContext, 1, before, next, nil); err != nil {
		t.Fatal(err)
	}
	root, _ := s.Root(testContext, "root")
	local, _ := s.Cursor(testContext, "root", "local")
	proof := fixturePlanningProof(root, local, next)
	n := fixtureNamespace(root, entry, next, NamespaceAbsentAtCut)
	proof.Namespace = []NamespaceProof{*n}
	page, err := s.PlanDirtyPage(testContext, "root", "", 1, proof)
	if err != nil || page.Decisions[0].Kind != DecisionCreateOnly {
		t.Fatal("unknown namespace planning", page, err)
	}
	if err = s.RevalidatePlan(testContext, page.Decisions[0], proof); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, MaxBatch + 1} {
		if _, err = s.PlanDirtyPage(testContext, "root", "", limit, proof); err == nil {
			t.Fatal("unbounded page accepted")
		}
	}
	duplicate := proof
	duplicate.Namespace = append(append([]NamespaceProof{}, proof.Namespace...), proof.Namespace[0])
	if _, err = s.PlanDirtyPage(testContext, "root", "", 1, duplicate); err == nil {
		t.Fatal("duplicate membership proof accepted")
	}
	unbounded := proof
	unbounded.Namespace = make([]NamespaceProof, MaxBatch+1)
	if _, err = s.PlanDirtyPage(testContext, "root", "", 1, unbounded); err == nil {
		t.Fatal("unbounded evidence accepted")
	}
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	if _, err = s.PlanDirtyPage(cancelled, "root", "", 1, proof); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled planner did not stop", err)
	}
}

func TestPlannerReadSnapshotAgainstConcurrentGeneration(t *testing.T) {
	s, proof := plannerFixture(t)
	var workers sync.WaitGroup
	errorsFound := make(chan error, 2)
	workers.Go(func() {
		page, err := s.PlanDirtyPage(testContext, "root", "", 1, proof)
		if err != nil {
			errorsFound <- err
			return
		}
		if len(page.Decisions) != 1 || (page.Decisions[0].Kind != DecisionNoop && page.Decisions[0].Kind != DecisionReconcile) {
			errorsFound <- fmt.Errorf("mixed snapshot: %+v", page)
		}
	})
	workers.Go(func() {
		entry := fileObservation("file", "file")
		entry.ExpectedGeneration = 1
		entry.HashGeneration = 2
		entry.SHA256 = hashBytes([]byte("two"))
		before, _ := s.Cursor(testContext, "root", "local")
		next := before
		next.Position++
		if err := s.CaptureLocal(testContext, 1, before, next, []Observation{entry}); err != nil {
			errorsFound <- err
		}
	})
	workers.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	page, err := s.PlanDirtyPage(testContext, "root", "", 1, proof)
	if err != nil || page.Decisions[0].Kind != DecisionReconcile {
		t.Fatal("old cut authorized later generation", page, err)
	}
}

func TestPlannerSparseDirtyLargeIndex(t *testing.T) {
	if os.Getenv("PLUTO_PLANNER_LARGE_FIXTURE") != "1" {
		t.Skip("separate bounded 100k/500k qualification fixture")
	}
	for _, count := range []int{100000, 500000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, _ := stateFixture(t)
			root, _ := s.Root(testContext, "root")
			target := fmt.Sprintf("file-%06d", count/2)
			// Fixture construction streams one bounded transaction, never a tree array.
			for offset := 0; offset < count; offset += MaxBatch {
				if err := s.transaction(testContext, func(tx *sql.Tx) error {
					stmt, err := tx.Prepare("INSERT INTO local_entries(root_id,entry_id,name_key,generation,descriptor_json) VALUES('root',?,?,1,?)")
					if err != nil {
						return err
					}
					defer stmt.Close()
					for index := offset; index < offset+MaxBatch && index < count; index++ {
						id := fmt.Sprintf("file-%06d", index)
						l := fileObservation(id, id)
						l.Generation = 1
						l.HashGeneration = 1
						l.SHA256 = hashBytes([]byte("one"))
						raw, _ := json.Marshal(l)
						if _, err = stmt.Exec(id, id, string(raw)); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			local := Cursor{RootID: "root", Stream: "local", Epoch: "local-journal", Position: 1, Valid: true}
			remote := Cursor{RootID: "root", Stream: "remote", Epoch: "remote-epoch", Position: 1, Valid: true}
			if err := s.transaction(testContext, func(tx *sql.Tx) error {
				b := Baseline{RootID: "root", EntryID: target, NodeID: "node-target", Epoch: remote.Epoch, Version: "v1", Name: target, NameKey: target, Kind: "file", Presence: "PRESENT", FileIdentity: "shared-inode", SHA256: hashBytes([]byte("one")), LocalGeneration: 1, TrustGeneration: 1, SizeBytes: 3, LastSeq: 1}
				raw, _ := json.Marshal(b)
				if _, err := tx.Exec("INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES('root',?,'node-target',?)", target, string(raw)); err != nil {
					return err
				}
				r := RemoteEntry{RootID: "root", NodeID: "node-target", ParentID: root.RemoteRootID, Name: target, Kind: "file", Epoch: remote.Epoch, Version: "v1", Presence: "PRESENT", SHA256: b.SHA256, Generation: 1, SizeBytes: 3, LastSeq: 1}
				raw, _ = json.Marshal(r)
				if _, err := tx.Exec("INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES('root',1,'node-target',1,?)", string(raw)); err != nil {
					return err
				}
				if err := addDirty(testContext, tx, "root", target, 1, 1, "remote"); err != nil {
					return err
				}
				if err := saveCursor(testContext, tx, Cursor{RootID: "root", Stream: "local"}, local); err != nil {
					return err
				}
				return saveCursor(testContext, tx, Cursor{RootID: "root", Stream: "remote"}, remote)
			}); err != nil {
				t.Fatal(err)
			}
			proof := fixturePlanningProof(root, local, remote)
			plans := []string{}
			for _, query := range []struct {
				sql  string
				args []any
			}{{dirtyPlanningQuery, []any{int64(1), "root", "", 128}}, {pendingPlanningQuery, []any{"root", target}}} {
				rows, err := s.db.Query("EXPLAIN QUERY PLAN "+query.sql, query.args...)
				if err != nil {
					t.Fatal(err)
				}
				for rows.Next() {
					var id, parent, unused int
					var detail string
					if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
						t.Fatal(err)
					}
					if strings.Contains(detail, "SCAN ") || strings.Contains(detail, "USE TEMP") {
						t.Fatal("planner query scans/sorts an entire relation", detail)
					}
					plans = append(plans, detail)
				}
				if err = rows.Err(); err != nil {
					t.Fatal(err)
				}
				rows.Close()
			}
			runtime.GC()
			var beforeMem, afterMem runtime.MemStats
			runtime.ReadMemStats(&beforeMem)
			started := time.Now()
			page, err := s.PlanDirtyPage(testContext, "root", "", 128, proof)
			elapsed := time.Since(started)
			runtime.ReadMemStats(&afterMem)
			if err != nil || len(page.Decisions) != 1 || page.Decisions[0].EntryID != target || page.Decisions[0].Kind != DecisionNoop || page.Queries != 5 || page.RowsRead != 1 {
				t.Fatal("sparse dirty work scaled with full tree", page, err)
			}
			allocated := afterMem.TotalAlloc - beforeMem.TotalAlloc
			if allocated > 4*1024*1024 || afterMem.HeapInuse > 64*1024*1024 {
				t.Fatal("planner memory exceeded bounded sparse budget", allocated, afterMem.HeapInuse)
			}
			for range 9 {
				if _, err = s.PlanDirtyPage(testContext, "root", "", 128, proof); err != nil {
					t.Fatal(err)
				}
			}
			result := map[string]any{"fixtureRows": count, "dirtyRows": 1, "pageLimit": 128, "decision": page.Decisions[0].Kind, "queries": page.Queries, "logicalRowsRead": page.RowsRead, "plannerElapsedNS": elapsed.Nanoseconds(), "plannerAllocatedBytes": allocated, "heapInuseBytes": afterMem.HeapInuse, "explainQueryPlan": plans, "noSourceReads": true, "noNetwork": true, "engineActivated": false}
			encoded, _ := json.Marshal(result)
			t.Log(string(encoded))
			if out := os.Getenv("PLUTO_PLANNER_EVIDENCE_DIR"); out != "" {
				if err = os.WriteFile(filepath.Join(out, fmt.Sprintf("sparse-%d.json", count)), append(encoded, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
