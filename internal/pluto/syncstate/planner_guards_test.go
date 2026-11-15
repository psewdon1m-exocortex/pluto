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

func TestPlannerProofWindowInjectedTime(t *testing.T) {
	root, local, remote, row, proof := plannerModel()
	at := time.Date(2026, 10, 12, 16, 0, 0, 0, time.UTC)
	proof.Window = ProofWindow{ValidatedAt: at, ValidUntil: at.Add(MaxProofAge)}
	for _, tc := range []struct {
		name string
		at   time.Time
		want DecisionKind
	}{
		{"fresh", at, DecisionNoop},
		{"almost-expired", at.Add(MaxProofAge - time.Nanosecond), DecisionNoop},
		{"expired", at.Add(MaxProofAge), DecisionReconcile},
		{"old", at.Add(time.Hour), DecisionReconcile},
		{"clock-before-validation", at.Add(-time.Nanosecond), DecisionReconcile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if d := decideRowAt(root, local, remote, row, proof, nil, tc.at); d.Kind != tc.want {
				t.Fatal(d)
			}
		})
	}
	proof.Window.ValidUntil = at.Add(MaxProofAge + time.Nanosecond)
	if d := decideRowAt(root, local, remote, row, proof, nil, at); d.Kind != DecisionReconcile {
		t.Fatal("unbounded certificate", d)
	}
}

func parentFixture(root Root, remote Cursor, id, parent string) parentBinding {
	l := Observation{RootID: root.RootID, EntryID: id, ParentID: parent, Name: id, NameKey: id, Kind: "folder", Presence: "PRESENT", FileIdentity: "inode-" + id, Generation: 2}
	b := Baseline{RootID: root.RootID, EntryID: id, ParentID: parent, Name: id, NameKey: id, Kind: "folder", Presence: "PRESENT", FileIdentity: l.FileIdentity, LocalGeneration: 1, TrustGeneration: root.TrustGeneration, NodeID: "node-" + id, Epoch: remote.Epoch, Version: "v1", LastSeq: 90}
	r := RemoteEntry{RootID: root.RootID, NodeID: b.NodeID, ParentID: root.RemoteRootID, Name: id, Kind: "folder", Presence: "PRESENT", Generation: root.ActiveRemoteGeneration, Epoch: remote.Epoch, Version: "v1", LastSeq: 90}
	if parent != "" {
		r.ParentID = "node-" + parent
	}
	return parentBinding{Local: &l, Base: &b, Remote: &r}
}

func TestPlannerAncestorNamespaceGuards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*planningRow)
	}{
		{"parent-local-rename", func(r *planningRow) { r.Parents[0].Local.Name = "renamed" }},
		{"parent-key-change", func(r *planningRow) { r.Parents[0].Local.NameKey = "new-key" }},
		{"parent-file-identity", func(r *planningRow) { r.Parents[0].Local.FileIdentity = "replacement" }},
		{"parent-local-move", func(r *planningRow) { r.Parents[0].Local.ParentID = "other" }},
		{"parent-remote-rename-stable-id", func(r *planningRow) { r.Parents[0].Remote.Name = "renamed"; r.Parents[0].Remote.Version = "v2" }},
		{"parent-remote-move-stable-id", func(r *planningRow) { r.Parents[0].Remote.ParentID = "other" }},
		{"parent-version", func(r *planningRow) { r.Parents[0].Remote.Version = "v2" }},
		{"parent-baseline-epoch", func(r *planningRow) { r.Parents[0].Base.Epoch = "old" }},
		{"parent-baseline-trust", func(r *planningRow) { r.Parents[0].Base.TrustGeneration-- }},
		{"parent-type", func(r *planningRow) { r.Parents[0].Local.Kind = "file" }},
		{"parent-other-root", func(r *planningRow) { r.Parents[0].Local.RootID = "other" }},
		{"grandparent-rename", func(r *planningRow) { r.Parents[1].Remote.Name = "renamed" }},
		{"grandparent-move", func(r *planningRow) { r.Parents[1].Remote.ParentID = "other-root" }},
		{"missing-grandparent", func(r *planningRow) { r.Parents = r.Parents[:1] }},
		{"ancestor-deleted", func(r *planningRow) { r.Parents[1].Remote.Presence = "ABSENT" }},
		{"unqualified-depth", func(r *planningRow) { r.ParentDepthExceeded = true }},
		{"parent-unresolved-operation", func(r *planningRow) {
			r.Parents[0].Pending = []Operation{{Intent: Intent{OperationID: "parent-outcome"}, Stage: "SUBMITTED"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, local, remote, row, proof := plannerModel()
			row.State.Local.ParentID = "parent"
			row.State.Base.ParentID = "parent"
			row.State.Remote.ParentID = "node-parent"
			row.Parents = []parentBinding{parentFixture(root, remote, "parent", "grandparent"), parentFixture(root, remote, "grandparent", "")}
			if d := decideRow(root, local, remote, row, proof, nil); d.Kind != DecisionNoop {
				t.Fatal("qualified chain", d)
			}
			tc.mutate(&row)
			if d := decideRow(root, local, remote, row, proof, nil); d.Kind != DecisionReconcile {
				t.Fatal("ancestor namespace authorized", d)
			}
		})
	}
}

func TestPlannerParentReadWitnessAndBound(t *testing.T) {
	s, proof := plannerFixture(t)
	root, _ := s.Root(testContext, "root")
	parent := parentFixture(root, proof.Remote.Applied, "parent", "")
	parent.Base.LastSeq = 1
	parent.Remote.LastSeq = 1
	if err := s.transaction(testContext, func(tx *sql.Tx) error {
		praw, _ := json.Marshal(parent.Local)
		braw, _ := json.Marshal(parent.Base)
		rraw, _ := json.Marshal(parent.Remote)
		if _, err := tx.Exec("INSERT INTO local_entries(root_id,entry_id,name_key,generation,descriptor_json) VALUES('root','parent','parent',2,?)", string(praw)); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES('root','parent','node-parent',?)", string(braw)); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES('root',1,'node-parent',1,?)", string(rraw)); err != nil {
			return err
		}
		var state EntryState
		var err error
		state.Local, err = readJSON[Observation](testContext, tx, "SELECT descriptor_json FROM local_entries WHERE root_id='root' AND entry_id='file'")
		if err != nil {
			return err
		}
		state.Base, err = optionalRecord[Baseline](testContext, tx, "SELECT descriptor_json FROM baselines WHERE root_id='root' AND entry_id='file'")
		if err != nil {
			return err
		}
		state.Remote, err = optionalRecord[RemoteEntry](testContext, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id='root' AND generation=1 AND node_id='node-file'")
		if err != nil {
			return err
		}
		state.Local.ParentID = "parent"
		state.Base.ParentID = "parent"
		state.Remote.ParentID = "node-parent"
		lr, _ := json.Marshal(state.Local)
		br, _ := json.Marshal(state.Base)
		rr, _ := json.Marshal(state.Remote)
		if _, err = tx.Exec("UPDATE local_entries SET parent_id='parent',descriptor_json=? WHERE root_id='root' AND entry_id='file'", string(lr)); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE baselines SET descriptor_json=? WHERE root_id='root' AND entry_id='file'", string(br)); err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE remote_entries SET descriptor_json=? WHERE root_id='root' AND node_id='node-file'", string(rr))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	page, err := s.PlanDirtyPage(testContext, "root", "", 1, proof)
	if err != nil || page.Decisions[0].Kind != DecisionNoop || page.Queries != 7 || page.RowsRead != 2 {
		t.Fatal(page, err)
	}
	if err = s.RevalidatePlan(testContext, page.Decisions[0], proof); err != nil {
		t.Fatal(err)
	}
	oldDomain := page.Decisions[0]
	oldDomain.Witness.Domain = "pluto-dirty-plan/v0"
	if err = s.RevalidatePlan(testContext, oldDomain, proof); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("witness domain was ignored", err)
	}
	parent.Remote.Name = "rename"
	parent.Remote.Version = "v2"
	raw, _ := json.Marshal(parent.Remote)
	if _, err = s.db.Exec("UPDATE remote_entries SET descriptor_json=? WHERE root_id='root' AND node_id='node-parent'", string(raw)); err != nil {
		t.Fatal(err)
	}
	if err = s.RevalidatePlan(testContext, page.Decisions[0], proof); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("parent witness omitted", err)
	}
}

func TestPlannerAncestryDepthIsBounded(t *testing.T) {
	s, proof := plannerFixture(t)
	root, _ := s.Root(testContext, "root")
	last := ""
	if err := s.transaction(testContext, func(tx *sql.Tx) error {
		for i := 0; i < MaxParentDepth+1; i++ {
			id := fmt.Sprintf("parent-%03d", i)
			p := parentFixture(root, proof.Remote.Applied, id, last)
			p.Base.LastSeq = 1
			p.Remote.LastSeq = 1
			lraw, _ := json.Marshal(p.Local)
			braw, _ := json.Marshal(p.Base)
			rraw, _ := json.Marshal(p.Remote)
			var parent any
			if last != "" {
				parent = last
			}
			if _, err := tx.Exec("INSERT INTO local_entries(root_id,entry_id,parent_id,name_key,generation,descriptor_json) VALUES('root',?,?,?,2,?)", id, parent, id, string(lraw)); err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES('root',?,?,?)", id, p.Base.NodeID, string(braw)); err != nil {
				return err
			}
			if _, err := tx.Exec("INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES('root',1,?,1,?)", p.Remote.NodeID, string(rraw)); err != nil {
				return err
			}
			last = id
		}
		l, err := readJSON[Observation](testContext, tx, "SELECT descriptor_json FROM local_entries WHERE root_id='root' AND entry_id='file'")
		if err != nil {
			return err
		}
		l.ParentID = last
		raw, _ := json.Marshal(l)
		_, err = tx.Exec("UPDATE local_entries SET parent_id=?,descriptor_json=? WHERE root_id='root' AND entry_id='file'", last, string(raw))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	page, err := s.PlanDirtyPage(testContext, "root", "", 1, proof)
	if err != nil || page.Decisions[0].Kind != DecisionReconcile || page.Queries != 5+2*MaxParentDepth || page.RowsRead != 1+MaxParentDepth {
		t.Fatal("ancestry work escaped bounds", page, err)
	}
}

func TestPlannerPendingLookupWithLargeAckHistory(t *testing.T) {
	if os.Getenv("PLUTO_PLANNER_LARGE_FIXTURE") != "1" {
		t.Skip("bounded 10k/100k acknowledged-history qualification")
	}
	for _, count := range []int{10000, 100000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, proof := plannerFixture(t)
			for offset := 0; offset < count; offset += MaxBatch {
				if err := s.transaction(testContext, func(tx *sql.Tx) error {
					stmt, err := tx.Prepare("INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,'root','file',?,'PUT',?,'fixture','CLIENT_ACKED')")
					if err != nil {
						return err
					}
					defer stmt.Close()
					for i := offset; i < offset+MaxBatch && i < count; i++ {
						intent := Intent{OperationID: fmt.Sprintf("ack-%06d", i), RootID: "root", EntryID: "file", LocalGeneration: int64(i + 2), Kind: "PUT"}
						raw, _ := json.Marshal(intent)
						if _, err = stmt.Exec(intent.OperationID, intent.LocalGeneration, string(raw)); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			plans := []string{}
			rows, err := s.db.Query("EXPLAIN QUERY PLAN "+pendingPlanningQuery, "root", "file")
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(detail, "SCAN ") || strings.Contains(detail, "USE TEMP") || !strings.Contains(detail, "pending_entry_operations") {
					t.Fatal("ACK history lookup is unbounded", detail)
				}
				plans = append(plans, detail)
			}
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			root, _ := s.Root(testContext, "root")
			proof = fixturePlanningProof(root, proof.Local.Applied, proof.Remote.Applied)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			page, err := s.PlanDirtyPage(testContext, "root", "", 1, proof)
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			if err != nil || page.Decisions[0].Kind != DecisionNoop || page.Queries != 5 || page.RowsRead != 1 {
				t.Fatal(page, err)
			}
			// An unknown old-generation outcome remains recoverable despite the ACK history.
			intent := Intent{OperationID: "unknown-old-outcome", RootID: "root", EntryID: "file", LocalGeneration: int64(count + 2), Kind: "PUT"}
			raw, _ := json.Marshal(intent)
			if _, err = s.db.Exec("INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,'root','file',?,'PUT',?,'fixture','SUBMITTED')", intent.OperationID, intent.LocalGeneration, string(raw)); err != nil {
				t.Fatal(err)
			}
			recovered, err := s.PlanDirtyPage(testContext, "root", "", 1, proof)
			if err != nil || recovered.Decisions[0].Kind != DecisionRecover || recovered.Decisions[0].Recovery.OperationID != intent.OperationID || recovered.RowsRead != 2 {
				t.Fatal(recovered, err)
			}
			result := map[string]any{"ackHistoryRows": count + 1, "dirtyRows": 1, "logicalSelects": page.Queries, "logicalRowsRead": page.RowsRead, "plannerElapsedNS": elapsed.Nanoseconds(), "plannerAllocatedBytes": after.TotalAlloc - before.TotalAlloc, "heapInuseBytes": after.HeapInuse, "explainQueryPlan": plans, "pendingRecoveredSameID": true, "engineActivated": false}
			encoded, _ := json.Marshal(result)
			t.Log(string(encoded))
			if out := os.Getenv("PLUTO_PLANNER_EVIDENCE_DIR"); out != "" {
				if err = os.WriteFile(filepath.Join(out, fmt.Sprintf("ack-history-%d.json", count)), append(encoded, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
