package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFolderHTTPOptionalJSONAndLegacyRefusal(t *testing.T) {
	original := Intent{OperationID: "old-operation", RootID: "root", EntryID: "file", Kind: "PUT"}
	raw, _ := json.Marshal(original)
	if strings.Contains(string(raw), "FolderHTTP") || strings.Contains(string(raw), "Captured") {
		t.Fatal("old JSON changed", string(raw))
	}
	extended := original
	extended.FolderHTTP = &FolderHTTPOperation{Schema: "pluto.folder-http-operation/v1"}
	raw, _ = json.Marshal(extended)
	var legacy struct{ OperationID, RootID, EntryID, Kind string }
	if e := json.Unmarshal(raw, &legacy); e != nil || legacy.OperationID != original.OperationID {
		t.Fatal("historical unknown field parsing broken", e)
	}
	s, _ := stateFixture(t)
	if e := s.Plan(testContext, extended); !errors.Is(e, ErrRemoteUnqualified) {
		t.Fatal("legacy plan accepts folder proof", e)
	}
}
func TestHTTPAuthorityObservedClockAndFutureRefusal(t *testing.T) {
	r, _, _, s, _, _ := actualHTTPFixture(t, 0)
	old := time.Now().Add(-time.Second)
	a, e := s.Authority(testContext)
	if e != nil {
		t.Fatal(e)
	}
	c, e := r.Candidate(testContext, "root")
	if e != nil {
		t.Fatal(e)
	}
	if authorityMatches(a, c.RemoteWitness, old) {
		t.Fatal("old caller clock accepted new observation")
	}
	if !authorityMatches(a, c.RemoteWitness, s.ExecutionTime()) {
		t.Fatal("actual execution clock doesn't follow observation")
	}
	future := *a
	future.qualifiedAtMS = time.Now().Add(time.Second).UnixMilli()
	future.expiresMS = future.qualifiedAtMS + 30000
	if authorityMatches(&future, c.RemoteWitness, s.ExecutionTime()) {
		t.Fatal("future qualification accepted")
	}
}
func TestHTTPFolderLostAckOriginalAndConflictHistory(t *testing.T) {
	r, _, w, s, f, _ := actualHTTPFixture(t, 1)
	scanSource(t, r.sources, w, "observe", nil)
	source, e := r.sources.SourceEntry(testContext, w.SetID, "tree/nested/file-000")
	if e != nil {
		t.Fatal(e)
	}
	entry, e := r.ProjectSourcePath(testContext, w, "root", source)
	if e != nil {
		t.Fatal(e)
	}
	// Fault occurs after durable SUBMITTED but before any server request.
	r.testPoint = func(point string) error {
		if point == "folder.before_submit" {
			return context.Canceled
		}
		return nil
	}
	if e = s.PrepareParents(testContext, w, "root", entry); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	pending, e := r.store.PendingPage(testContext, "root", "", 10)
	if e != nil || len(pending) != 0 {
		t.Fatal("interrupted txn persisted", pending, e)
	}
	r.testPoint = nil
	if e = s.PrepareParents(testContext, w, "root", entry); e != nil {
		t.Fatal(e)
	}
	if len(f.folders) != 2 {
		t.Fatal("missing parents", len(f.folders))
	}
	// Keep the historical exact input but emulate an ACK lost after publication.
	var op Operation
	rows, e := r.store.db.Query("SELECT operation_id FROM operations WHERE kind='ENSURE_DIRECTORY' ORDER BY operation_id LIMIT 1")
	if e != nil {
		t.Fatal(e)
	}
	var id string
	rows.Next()
	rows.Scan(&id)
	rows.Close()
	op, e = r.store.Operation(testContext, id)
	if e != nil {
		t.Fatal(e)
	}
	before := string(mustJSON(op.Intent))
	if _, e = r.store.db.Exec("UPDATE operations SET stage='SUBMITTED' WHERE operation_id=?", id); e != nil {
		t.Fatal(e)
	}
	if e = s.PrepareParents(testContext, w, "root", entry); e != nil {
		t.Fatal(e)
	}
	after, e := r.store.Operation(testContext, id)
	if e != nil || after.Stage != "CLIENT_ACKED" || string(mustJSON(after.Intent)) != before || len(f.folders) != 2 {
		t.Fatal(after, e)
	}
	// History cannot be treated as current R after remote namespace divergence.
	c, _ := r.Candidate(testContext, "root")
	b, e := readJSON[Baseline](testContext, r.store.db, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", "root", op.EntryID)
	if e != nil {
		t.Fatal(e)
	}
	changed := f.nodes[b.NodeID]
	changed.Name = "renamed"
	changed.Version = remoteVersion(9999)
	f.emit(changed, "remote-rename")
	if e = s.Refresh(testContext); e != nil {
		t.Fatal(e)
	}
	if e = s.PrepareParents(testContext, w, "root", entry); e == nil {
		t.Fatal("renamed B accepted", c)
	}
}
func TestHTTPPendingSnapshotIdentityExactAndPrivate(t *testing.T) {
	r, _, _, _, f, _ := actualHTTPFixture(t, 0)
	a, e := r.pendingHTTPSnapshot(f.binding)
	if e != nil {
		t.Fatal(e)
	}
	b, e := r.pendingHTTPSnapshot(f.binding)
	if e != nil || a != b {
		t.Fatal(a, b, e)
	}
	other := f.binding
	other.BindingVersion = remoteVersion(99)
	if _, e = r.pendingHTTPSnapshot(other); e == nil {
		t.Fatal("another binding silently reuses start identity")
	}
	if e := r.store.transaction(testContext, func(*sql.Tx) error { return context.Canceled }); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
