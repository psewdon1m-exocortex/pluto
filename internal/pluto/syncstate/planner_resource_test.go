package syncstate

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func insertPlannerDescriptors(tx *sql.Tx, l Observation, b Baseline, r RemoteEntry, dirty bool) error {
	lraw, _ := json.Marshal(l)
	braw, _ := json.Marshal(b)
	rraw, _ := json.Marshal(r)
	var parent any
	if l.ParentID != "" {
		parent = l.ParentID
	}
	if _, err := tx.Exec("INSERT INTO local_entries(root_id,entry_id,parent_id,name_key,generation,descriptor_json) VALUES('root',?,?,?, ?,?)", l.EntryID, parent, l.NameKey, l.Generation, string(lraw)); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES('root',?,?,?)", l.EntryID, b.NodeID, string(braw)); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES('root',1,?,1,?)", r.NodeID, string(rraw)); err != nil {
		return err
	}
	if dirty {
		return addDirty(testContext, tx, "root", l.EntryID, l.Generation, 1, "fixture")
	}
	return nil
}

func resourcePlannerFixture(t *testing.T, leaves, depth int, shared bool, longName int) (*Store, PlanningProofs) {
	t.Helper()
	s, _ := stateFixture(t)
	root, _ := s.Root(testContext, "root")
	local := Cursor{RootID: "root", Stream: "local", Epoch: "local-journal", Position: 1, Valid: true}
	remote := Cursor{RootID: "root", Stream: "remote", Epoch: "remote-epoch", Position: 1, Valid: true}
	sharedParent := ""
	for leaf := 0; leaf < leaves; leaf++ {
		if err := s.transaction(testContext, func(tx *sql.Tx) error {
			parent := ""
			if shared && leaf != 0 {
				parent = sharedParent
			} else {
				for level := 0; level < depth; level++ {
					id := fmt.Sprintf("parent-%04d-%03d", leaf, level)
					p := parentFixture(root, remote, id, parent)
					p.Base.LastSeq = 1
					p.Remote.LastSeq = 1
					if longName > 0 {
						name := strings.Repeat("x", longName) + id
						p.Local.Name = name
						p.Local.NameKey = name
						p.Base.Name = name
						p.Base.NameKey = name
						p.Remote.Name = name
					}
					if err := insertPlannerDescriptors(tx, *p.Local, *p.Base, *p.Remote, false); err != nil {
						return err
					}
					parent = id
				}
				sharedParent = parent
			}
			id := fmt.Sprintf("leaf-%06d", leaf)
			l := fileObservation(id, id)
			l.ParentID = parent
			l.Generation = 1
			l.HashGeneration = 1
			l.SHA256 = hashBytes([]byte("one"))
			b := Baseline{RootID: "root", EntryID: id, NodeID: "node-" + id, ParentID: parent, Name: id, NameKey: id, Kind: "file", Presence: "PRESENT", FileIdentity: l.FileIdentity, LocalGeneration: 1, TrustGeneration: 1, SHA256: l.SHA256, SizeBytes: 3, Epoch: remote.Epoch, Version: "v1", LastSeq: 1}
			r := RemoteEntry{RootID: "root", NodeID: b.NodeID, ParentID: "node-" + parent, Name: id, Kind: "file", Presence: "PRESENT", SHA256: l.SHA256, SizeBytes: 3, Epoch: remote.Epoch, Version: "v1", LastSeq: 1, Generation: 1}
			return insertPlannerDescriptors(tx, l, b, r, true)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.transaction(testContext, func(tx *sql.Tx) error {
		if err := saveCursor(testContext, tx, Cursor{RootID: "root", Stream: "local"}, local); err != nil {
			return err
		}
		return saveCursor(testContext, tx, Cursor{RootID: "root", Stream: "remote"}, remote)
	}); err != nil {
		t.Fatal(err)
	}
	return s, fixturePlanningProof(root, local, remote)
}

func TestPlannerDenseAndDeepPageResources(t *testing.T) {
	for _, tc := range []struct {
		name          string
		leaves, depth int
		shared        bool
		longName      int
		exhausted     bool
	}{
		{"dense-shared-parent", MaxBatch, 1, true, 0, false},
		{"deep-record-budget", 32, MaxParentDepth, false, 0, true},
		{"deep-byte-budget", 32, MaxParentDepth, false, 2000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, proof := resourcePlannerFixture(t, tc.leaves, tc.depth, tc.shared, tc.longName)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			page, err := s.PlanDirtyPage(testContext, "root", "", MaxBatch, proof)
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			if err != nil || len(page.Decisions) != tc.leaves || page.AncestorBudgetExhausted != tc.exhausted || page.AncestorRecords > MaxAncestorRecordsPerPage || page.AncestorBytes > MaxAncestorBytesPerPage {
				t.Fatal("page escaped record/byte budget", page, err)
			}
			if after.HeapInuse > 64*1024*1024 || after.TotalAlloc-before.TotalAlloc > 64*1024*1024 {
				t.Fatal("planner escaped dense/deep memory bound", after.HeapInuse, after.TotalAlloc-before.TotalAlloc)
			}
			noops, reconciles := 0, 0
			for _, decision := range page.Decisions {
				switch decision.Kind {
				case DecisionNoop:
					noops++
				case DecisionReconcile:
					reconciles++
				default:
					t.Fatal("unexpected resource decision", decision)
				}
			}
			if tc.shared && (noops != MaxBatch || page.AncestorRecords != 3 || page.Queries != 4+MaxBatch+2 || page.RowsRead != MaxBatch+1) {
				t.Fatal("snapshot-local cache did not share ancestor records", page)
			}
			if tc.exhausted {
				if noops < 1 || reconciles < 1 {
					t.Fatal("exhaustion did not stop unqualified ancestry", noops, reconciles)
				}
				old := page.Decisions[len(page.Decisions)-1]
				if err = s.RevalidatePlan(testContext, old, proof); !errors.Is(err, ErrStaleGeneration) {
					t.Fatal("budget reconciliation became executable without new planning", err)
				}
				// A new exact-entry plan gets a fresh witness; revalidation never returns a new decision.
				entryBefore := fmt.Sprintf("leaf-%06d", tc.leaves-2)
				exact, err := s.PlanDirtyPage(testContext, "root", entryBefore, 1, proof)
				if err != nil || len(exact.Decisions) != 1 || exact.Decisions[0].Kind != DecisionNoop || exact.Decisions[0].Witness == old.Witness {
					t.Fatal("new planning did not regenerate bounded witness", exact, err)
				}
			}
			result := map[string]any{"fixture": tc.name, "dirtyLeaves": tc.leaves, "ancestorDepth": tc.depth, "sharedAncestors": tc.shared, "longNameBytes": tc.longName, "deserializedAncestorRecords": page.AncestorRecords, "ancestorEncodedAndScalarBytes": page.AncestorBytes, "ancestorRecordLimit": MaxAncestorRecordsPerPage, "ancestorByteLimit": MaxAncestorBytesPerPage, "budgetExhausted": page.AncestorBudgetExhausted, "logicalSelects": page.Queries, "logicalRowsRead": page.RowsRead, "noops": noops, "reconciles": reconciles, "plannerElapsedNS": elapsed.Nanoseconds(), "plannerAllocatedBytes": after.TotalAlloc - before.TotalAlloc, "heapInuseBytes": after.HeapInuse, "engineActivated": false}
			encoded, _ := json.Marshal(result)
			t.Log(string(encoded))
			if out := os.Getenv("PLUTO_PLANNER_EVIDENCE_DIR"); out != "" {
				if err = os.WriteFile(filepath.Join(out, tc.name+".json"), append(encoded, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAncestorBudgetIncludesPendingRecordsBeforeDecode(t *testing.T) {
	s, _ := resourcePlannerFixture(t, 1, 1, true, 0)
	root, _ := s.Root(testContext, "root")
	intent := Intent{OperationID: "unknown-parent-outcome", RootID: "root", EntryID: "parent-0000-000", LocalGeneration: 3, Kind: "ENSURE_DIRECTORY"}
	raw, _ := json.Marshal(intent)
	if _, err := s.db.Exec("INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,'root',?,3,'ENSURE_DIRECTORY',?,'fixture','SUBMITTED')", intent.OperationID, intent.EntryID, string(raw)); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(testContext, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := scanPlanningRows(testContext, tx, root, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	row := rows[0]
	budget := newAncestorBudget()
	budget.Records = MaxAncestorRecordsPerPage - 3
	if err = loadParents(testContext, tx, root, &row, budget); err != nil {
		t.Fatal(err)
	}
	if !row.AncestorBudgetExceeded || !budget.Exhausted || len(row.Parents) != 0 || budget.Records != MaxAncestorRecordsPerPage-3 {
		t.Fatal("pending record was deserialized beyond budget", row, budget)
	}
}
