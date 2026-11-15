package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"pluto/internal/syncproto"
)

func TestRemoteSnapshotRestartMigrationAndRecognizedDDL(t *testing.T) {
	r, s, _ := remoteFixture(t)
	dir := filepath.Dir(r.store.filename)
	p, err := r.PrepareSnapshot(testContext, "root", 1, wireReady(remoteBindingFixture(), "s", "0"), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	p, err = r.ImportSnapshotPage(testContext, "root", p.Cursor, wirePage(p, []syncproto.Descriptor{folderRemote("remote-root", "", "root")}, "done", false), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.EnableSources(testContext, s.limits); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	restarted, err := reopened.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := restarted.Preparation(testContext, "root")
	if err != nil || fingerprint(retained) != fingerprint(p) {
		t.Fatal("restart lost invisible prepared state", retained, err)
	}
	if _, err = restarted.PublishSnapshot(testContext, "root", retained, remoteNow); err != nil {
		t.Fatal(err)
	}
	var v int
	if err = reopened.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 5 {
		t.Fatal(v, err)
	}
	if err = preflight(testContext, reopened.filename); err != nil {
		t.Fatal(err)
	}
	var manifest string
	if err = reopened.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=5").Scan(&manifest); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if json.Unmarshal([]byte(manifest), &parsed) != nil || parsed["engineActivated"] != false {
		t.Fatal(manifest)
	}
	backupPath := filepath.Join(dir, "sync-state-backups", parsed["backup"].(string))
	db, err := openDB(backupPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 4 {
		t.Fatal("module4 backup wrong", v, err)
	}
	if digest, err := fileDigest(backupPath); err != nil || digest != parsed["backupSHA256"] {
		t.Fatal("backup not exact", digest, err)
	}
	// Unsupported/missing same-version DDL must be refused before writable open.
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	mutable, err := openDB(filepath.Join(dir, "sync-state.sqlite"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mutable.Exec("DROP INDEX remote_candidate_namespace"); err != nil {
		t.Fatal(err)
	}
	mutable.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	mutable.Close()
	before, err := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(testContext, dir); !errors.Is(err, ErrUnsupportedSchema) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("missing DDL accepted", err)
	}
	after, _ := fileDigest(filepath.Join(dir, "sync-state.sqlite"))
	if before != after {
		t.Fatal("refusal rewrote database")
	}
}

func TestModuleFivePreservesOldImmutableJSONBytes(t *testing.T) {
	intent := Intent{OperationID: "original", RootID: "root", EntryID: "entry", Kind: "PUT", LocalGeneration: 1, TrustGeneration: 1, ExpectedAbsent: true, Dependencies: []string{}}
	raw := string(mustJSON(intent))
	wanted := `{"OperationID":"original","RootID":"root","EntryID":"entry","Kind":"PUT","ExpectedEpoch":"","ExpectedVersion":"","ExpectedNodeID":"","ParentID":"","Name":"","NameKey":"","FileIdentity":"","LocalGeneration":1,"TrustGeneration":1,"SizeBytes":0,"ExpectedAbsent":true,"Dependencies":[]}`
	if raw != wanted {
		t.Fatal("legacy intent fingerprint changed", raw)
	}
	b := Baseline{}
	remote := RemoteEntry{}
	for _, raw := range []string{string(mustJSON(b)), string(mustJSON(remote))} {
		if strings.Contains(raw, "RemoteBinding") || strings.Contains(raw, "CaptureProof") || strings.Contains(raw, "Availability") || strings.Contains(raw, "ContentVersionID") {
			t.Fatal("zero extension altered legacy bytes", raw)
		}
	}
}

func TestCapturedSourceGapDirtyAndParentChangeRejectLateAdoption(t *testing.T) {
	for _, change := range []string{"source-gap", "dirty-late", "parent-rename", "remote-binding"} {
		t.Run(change, func(t *testing.T) {
			r, w, v, entry, c := capturedRemoteFixture(t)
			a := fixtureRemoteAuthority(c)
			d, err := r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow)
			if err != nil || d.Kind != "ADOPT_EQUAL" {
				t.Fatal(d, err)
			}
			switch change {
			case "source-gap":
				if _, err = r.sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "owner2"); err != nil {
					t.Fatal(err)
				}
			case "dirty-late":
				if err = r.store.transaction(testContext, func(tx *sql.Tx) error { return addDirty(testContext, tx, "root", entry, 999, 999, "local") }); err != nil {
					t.Fatal(err)
				}
			case "parent-rename":
				l, _ := readJSON[Observation](testContext, r.store.db, "SELECT descriptor_json FROM local_entries WHERE root_id='root' AND entry_id=?", entry)
				p, _ := readJSON[Observation](testContext, r.store.db, "SELECT descriptor_json FROM local_entries WHERE root_id='root' AND entry_id=?", l.ParentID)
				p.Name = "changed"
				p.NameKey = p.Name
				if _, err = r.store.db.Exec("UPDATE local_entries SET name_key=?,descriptor_json=? WHERE root_id='root' AND entry_id=?", p.Name, string(mustJSON(p)), p.EntryID); err != nil {
					t.Fatal(err)
				}
			case "remote-binding":
				if err = r.InvalidateRemote(testContext, c.RemoteWitness); err != nil {
					t.Fatal(err)
				}
			}
			if err = r.AdoptCaptured(testContext, w, v, a, d, remoteNow); err == nil {
				t.Fatal("stale witness adopted after", change)
			}
			if err = r.RevalidateCapturedDecision(testContext, w, v, a, d, remoteNow); err == nil {
				t.Fatal("stale witness revalidated after", change)
			}
			if _, err = readJSON[Baseline](testContext, r.store.db, "SELECT descriptor_json FROM baselines WHERE root_id='root' AND entry_id=?", entry); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("B changed during rejected adoption", err)
			}
		})
	}
}

func TestCapturedNewLocalBytesDifferentDespiteRestoredMTimeAndOverwriteRoute(t *testing.T) {
	r, w, v, entry, c := capturedRemoteFixture(t)
	a := fixtureRemoteAuthority(c)
	d, _ := r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow)
	if err := r.AdoptCaptured(testContext, w, v, a, d, remoteNow); err != nil {
		t.Fatal(err)
	}
	seedCapturedParentBases(t, r, entry, c)
	before, err := os.Stat(v.physicalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(v.physicalPath, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(v.physicalPath, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	scanSource(t, r.sources, w, "scan-next", nil)
	source, err := r.sources.SourceEntry(testContext, w.SetID, v.evidence.Destination)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := CaptureGuarded(testContext, w, source, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	if err = r.sources.RecordVerifiedSnapshot(testContext, w, a2); err != nil {
		t.Fatal(err)
	}
	if err = r.ProjectCapturedEntry(testContext, w, "root", entry, a2); err != nil {
		t.Fatal(err)
	}
	changed, err := r.DecideCaptured(testContext, w, "root", entry, a2, a, remoteNow)
	if err != nil || changed.Kind != "OVERWRITE" || changed.Witness.Source.SHA256 == v.evidence.SHA256 {
		t.Fatal("stat metadata used as byte proof", changed, err)
	}
	if err = r.AdoptCaptured(testContext, w, a2, a, changed, remoteNow); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal("overwrite was adopted without publication", err)
	}
}

func TestCapturedConcurrentAdoptionCASOneWinner(t *testing.T) {
	r, w, v, entry, c := capturedRemoteFixture(t)
	a := fixtureRemoteAuthority(c)
	d, err := r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- r.AdoptCaptured(testContext, w, v, a, d, remoteNow) }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrStaleGeneration) && !errors.Is(err, ErrRemoteUnqualified) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatal("CAS winner count", wins)
	}
}

func TestRemoteNamespaceParentMoveUnknownAndNoMetadata404Absence(t *testing.T) {
	r, w, v, entry, c := capturedRemoteFixture(t)
	a := fixtureRemoteAuthority(c)
	d, _ := r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow)
	if err := r.AdoptCaptured(testContext, w, v, a, d, remoteNow); err != nil {
		t.Fatal(err)
	}
	seedCapturedParentBases(t, r, entry, c)
	noop, _ := r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow)
	parent := noop.Remote.ParentID
	old, _ := readJSON[RemoteEntry](testContext, r.store.db, "SELECT descriptor_json FROM remote_entries WHERE root_id='root' AND generation=2 AND node_id=?", parent)
	moved := descriptorFromRemote(old)
	moved.Version = remoteVersion(40)
	moved.Name = "renamed"
	newCut, err := r.ImportFeed(testContext, c.RemoteWitness, wireFeed(c.RemoteWitness, []syncproto.FeedItem{{Descriptor: moved, Seq: "1", Kind: "upsert", OperationID: "rename"}}, "move"))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(newCut), remoteNow)
	if err != nil || decision.Kind != "RECONCILE" && decision.Kind != "CONFLICT" {
		t.Fatal("stable parent node silently retargeted", decision, err)
	}
	// A server metadata404 cannot be fed into a descriptor importer to invent
	// absence, even if a caller tries to label it with a snapshot/cursor.
	before, _ := r.Candidate(testContext, "root")
	if _, err = r.ImportFeed(testContext, before.RemoteWitness, []byte(`{"error":"not_found"}`)); err == nil {
		t.Fatal("404 created absence")
	}
	after, _ := r.Candidate(testContext, "root")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("404 mutated candidate")
	}
}

func TestRemoteCursorAndDirtyDebtBoundedAtomic(t *testing.T) {
	r, _, _ := remoteFixture(t)
	for _, id := range []string{"a", "b", "c"} {
		capture(t, r.store, fileObservation(id, id))
	}
	c := publishRemote(t, r, []syncproto.Descriptor{folderRemote("remote-root", "", "root")})
	if n, err := r.DrainRemoteWork(testContext, "root", 2); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if n, err := r.DrainRemoteWork(testContext, "root", 2); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	var debt int
	if err := r.store.db.QueryRow("SELECT COUNT(*) FROM remote_replan_all WHERE root_id='root'").Scan(&debt); err != nil || debt != 0 {
		t.Fatal(debt, err)
	}
	if n, err := r.DrainRemoteWork(testContext, "root", 501); !errors.Is(err, ErrSourceQuota) || n != 0 {
		t.Fatal("work bound", n, err)
	}
	before, _ := r.store.Root(testContext, "root")
	if before.EngineReady || before.MaxFileBytes != MaxFileBytes || before.MaxActiveVersions != 10 || before.AllowsDelete {
		t.Fatal(before)
	}
	if _, err := r.ImportFeed(testContext, c.RemoteWitness, wireFeed(c.RemoteWitness, nil, "empty")); err != nil {
		t.Fatal("empty complete feed", err)
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err := r.DrainRemoteWork(ctx, "root", 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.PrepareSnapshot(testContext, "root", 1, wireReady(remoteBindingFixture(), "second", "0"), remoteNow.Add(time.Second)); err != nil {
		t.Fatal("same active binding reconciliation refused", err)
	}
}
