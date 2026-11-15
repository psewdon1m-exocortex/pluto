package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"pluto/internal/syncproto"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

var remoteNow = time.Unix(1750000000, 0).UTC()

func remoteVersion(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func remoteBindingFixture() RemoteBinding {
	return RemoteBinding{Protocol: syncproto.Protocol, DescriptorSchema: syncproto.DescriptorSchema, ServerIdentity: "saturn-fixture", RootID: "remote-root", ServerEpoch: "epoch", PolicyVersion: "policy", BindingVersion: remoteVersion(1)}
}
func wireBinding(b RemoteBinding) map[string]any {
	return map[string]any{"protocol": b.Protocol, "descriptor_schema": b.DescriptorSchema, "server_identity": b.ServerIdentity, "root_id": b.RootID, "server_epoch": b.ServerEpoch, "policy_version": b.PolicyVersion, "binding_version": b.BindingVersion}
}
func wireDescriptor(d syncproto.Descriptor) map[string]any {
	return map[string]any{"node_id": d.NodeID, "parent_id": d.ParentID, "name": d.Name, "type": d.Type, "size_bytes": d.SizeBytes, "content_sha256": d.ContentSHA256, "content_version_id": d.ContentVersionID, "version": d.Version, "availability": d.Availability}
}
func wireReady(b RemoteBinding, id, cut string) []byte {
	m := wireBinding(b)
	m["state"] = "READY"
	m["snapshot_id"] = id
	m["cut_seq"] = cut
	m["entries_cursor"] = "entries-" + id
	m["changes_cursor"] = "changes-" + id
	m["lease_seconds"] = 60
	m["absolute_lifetime_seconds"] = 600
	return mustJSON(m)
}
func wirePage(p SnapshotPreparation, items []syncproto.Descriptor, next string, more bool) []byte {
	m := wireBinding(p.Snapshot.Binding)
	m["snapshot_id"] = p.Snapshot.SnapshotID
	m["cut_seq"] = p.Snapshot.CutSeq
	m["after_node_id"] = p.AfterNodeID
	last := p.AfterNodeID
	values := make([]any, 0, len(items))
	for _, d := range items {
		values = append(values, wireDescriptor(d))
		id := d.NodeID
		last = &id
	}
	m["last_node_id"] = last
	m["items"] = values
	m["next_cursor"] = next
	m["has_more"] = more
	return mustJSON(m)
}
func wireFeed(w RemoteWitness, items []syncproto.FeedItem, next string) []byte {
	m := wireBinding(w.Binding)
	m["from_exclusive"] = remoteDecimal(w.Position)
	to := w.Position
	values := make([]any, 0, len(items))
	for _, i := range items {
		d := wireDescriptor(i.Descriptor)
		d["seq"] = i.Seq
		d["kind"] = i.Kind
		d["operation_id"] = i.OperationID
		if i.Kind == "tombstone" {
			d["before_version"] = i.BeforeVersion
		}
		values = append(values, d)
		to, _ = syncproto.Integer64(i.Seq)
	}
	m["to_inclusive"] = remoteDecimal(to)
	m["items"] = values
	m["next_cursor"] = next
	m["has_more"] = false
	return mustJSON(m)
}
func folderRemote(id, parent, name string) syncproto.Descriptor {
	d := syncproto.Descriptor{NodeID: id, Name: name, Type: "folder", SizeBytes: "0", Version: remoteVersion(2), Availability: "AVAILABLE"}
	if parent != "" {
		d.ParentID = &parent
	}
	return d
}
func fileRemote(id, parent, name, content string) syncproto.Descriptor {
	sha := hashBytes([]byte(content))
	version := "content-1"
	return syncproto.Descriptor{NodeID: id, ParentID: &parent, Name: name, Type: "file", SizeBytes: remoteDecimal(int64(len(content))), ContentSHA256: &sha, ContentVersionID: &version, Version: remoteVersion(3), Availability: "AVAILABLE"}
}
func remoteFixture(t *testing.T) (*RemoteImport, *Sources, SourceWitness) {
	t.Helper()
	source := t.TempDir()
	s, w, _ := sourceFixture(t, source)
	b := testBinding
	b.SourceIdentity = w.SetID
	if err := s.store.BindRoot(testContext, b); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachSourceSet(testContext, w.SetID, w.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	r, err := s.store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	return r, s, w
}
func publishRemote(t *testing.T, r *RemoteImport, descriptors []syncproto.Descriptor) RemoteCandidate {
	t.Helper()
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].NodeID < descriptors[j].NodeID })
	root, _ := r.store.Root(testContext, "root")
	p, err := r.PrepareSnapshot(testContext, "root", root.TrustGeneration, wireReady(remoteBindingFixture(), "snapshot", "0"), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	p, err = r.ImportSnapshotPage(testContext, "root", p.Cursor, wirePage(p, descriptors, "entries-done", false), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.PublishSnapshot(testContext, "root", p, remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRemoteSnapshotStageCutZeroReplayAndAtomicPublish(t *testing.T) {
	r, _, _ := remoteFixture(t)
	p, err := r.PrepareSnapshot(testContext, "root", 1, wireReady(remoteBindingFixture(), "s", "0"), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw := wirePage(p, []syncproto.Descriptor{fileRemote("a", "remote-root", "file", "one")}, "entries-two", true)
	r.testPoint = func(point string) error {
		if point == "snapshot.before_cursor" {
			return context.Canceled
		}
		return nil
	}
	if _, err = r.ImportSnapshotPage(testContext, "root", p.Cursor, firstRaw, remoteNow); !errors.Is(err, context.Canceled) {
		t.Fatal("atomic fault not surfaced", err)
	}
	var n int
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM remote_entries WHERE root_id='root'").Scan(&n); err != nil || n != 0 {
		t.Fatal("page prefix escaped rollback", n, err)
	}
	r.testPoint = nil
	next, err := r.ImportSnapshotPage(testContext, "root", p.Cursor, firstRaw, remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := r.ImportSnapshotPage(testContext, "root", p.Cursor, firstRaw, remoteNow)
	if err != nil || fingerprint(duplicate) != fingerprint(next) {
		t.Fatal("duplicate page changed key", duplicate, err)
	}
	var altered map[string]any
	json.Unmarshal(firstRaw, &altered)
	altered["forward"] = "different bytes"
	if _, err = r.ImportSnapshotPage(testContext, "root", p.Cursor, mustJSON(altered), remoteNow); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("altered replay accepted", err)
	}
	if _, err = r.PublishSnapshot(testContext, "root", next, remoteNow); !errors.Is(err, ErrRemoteIncomplete) {
		t.Fatal("incomplete became active", err)
	}
	root, _ := r.store.Root(testContext, "root")
	if root.ActiveRemoteGeneration != 1 || root.EngineReady {
		t.Fatal(root)
	}
	complete, err := r.ImportSnapshotPage(testContext, "root", next.Cursor, wirePage(next, []syncproto.Descriptor{folderRemote("remote-root", "", "root")}, "done", false), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	r.testPoint = func(point string) error {
		if point == "snapshot.before_publish" {
			return context.Canceled
		}
		return nil
	}
	if _, err = r.PublishSnapshot(testContext, "root", complete, remoteNow); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	root, _ = r.store.Root(testContext, "root")
	if root.ActiveRemoteGeneration != 1 {
		t.Fatal("publish escaped rollback")
	}
	r.testPoint = nil
	c, err := r.PublishSnapshot(testContext, "root", complete, remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	if c.Position != 0 || c.Generation != 2 || !c.Valid || c.Binding != remoteBindingFixture() {
		t.Fatal(c)
	}
	cur, _ := r.store.Cursor(testContext, "root", "remote")
	if cur.Valid || cur.Position != 0 {
		t.Fatal("raw shape fabricated authority", cur)
	}
	if _, err = r.PruneRemoteGeneration(testContext, "root", 2, 500); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("pruned active R", err)
	}
}

func TestRemoteFeedUnknownAtomicTombstoneGapAndRetiredBinding(t *testing.T) {
	r, _, _ := remoteFixture(t)
	d := fileRemote("a", "remote-root", "file", "one")
	c := publishRemote(t, r, []syncproto.Descriptor{d, folderRemote("remote-root", "", "root")})
	unknown := d
	unknown.Version = remoteVersion(4)
	unknown.Availability = "UNKNOWN"
	unknown.ContentSHA256 = nil
	unknown.ContentVersionID = nil
	raw := wireFeed(c.RemoteWitness, []syncproto.FeedItem{{Descriptor: unknown, Seq: "1", Kind: "upsert", OperationID: "op1"}}, "feed1")
	r.testPoint = func(p string) error {
		if p == "feed.before_cursor" {
			return context.Canceled
		}
		return nil
	}
	if _, err := r.ImportFeed(testContext, c.RemoteWitness, raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	before, _ := readJSON[RemoteEntry](testContext, r.store.db, "SELECT descriptor_json FROM remote_entries WHERE root_id='root' AND generation=2 AND node_id='a'")
	if before.Version != d.Version {
		t.Fatal("R escaped failed feed")
	}
	r.testPoint = nil
	next, err := r.ImportFeed(testContext, c.RemoteWitness, raw)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := r.ImportFeed(testContext, c.RemoteWitness, raw); err != nil || !reflect.DeepEqual(next, duplicate) {
		t.Fatal("exact feed replay", duplicate, err)
	}
	current, _ := readJSON[RemoteEntry](testContext, r.store.db, "SELECT descriptor_json FROM remote_entries WHERE root_id='root' AND generation=2 AND node_id='a'")
	if current.Presence != "PRESENT" || current.Availability != "UNKNOWN" {
		t.Fatal("unknown inferred absent", current)
	}
	badBefore := unknown
	badBefore.Name = "other"
	badBefore.Version = remoteVersion(5)
	bad := wireFeed(next.RemoteWitness, []syncproto.FeedItem{{Descriptor: d, Seq: "2", Kind: "upsert", OperationID: "op2"}, {Descriptor: badBefore, Seq: "3", Kind: "tombstone", OperationID: "op3", BeforeVersion: unknown.Version}}, "bad")
	if _, err = r.ImportFeed(testContext, next.RemoteWitness, bad); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("bad prestate accepted", err)
	}
	still, _ := r.Candidate(testContext, "root")
	if still.RemoteWitness != next.RemoteWitness {
		t.Fatal("failed batch advanced cursor")
	}
	deleted := unknown
	deleted.Version = remoteVersion(6)
	tomb := wireFeed(next.RemoteWitness, []syncproto.FeedItem{{Descriptor: deleted, Seq: "2", Kind: "tombstone", OperationID: "delete", BeforeVersion: unknown.Version}}, "feed2")
	latest, err := r.ImportFeed(testContext, next.RemoteWitness, tomb)
	if err != nil {
		t.Fatal(err)
	}
	current, _ = readJSON[RemoteEntry](testContext, r.store.db, "SELECT descriptor_json FROM remote_entries WHERE root_id='root' AND generation=2 AND node_id='a'")
	if current.Presence != "ABSENT" || current.Version != deleted.Version {
		t.Fatal(current)
	}
	gap := wireFeed(latest.RemoteWitness, []syncproto.FeedItem{{Descriptor: d, Seq: "4", Kind: "upsert", OperationID: "gap"}}, "gap")
	if _, err = r.ImportFeed(testContext, latest.RemoteWitness, gap); err == nil {
		t.Fatal("noncontiguous feed accepted")
	}
	if err = r.InvalidateRemote(testContext, latest.RemoteWitness); err != nil {
		t.Fatal(err)
	}
	if _, err = r.PrepareSnapshot(testContext, "root", 2, wireReady(latest.Binding, "new", "2"), remoteNow); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("revived invalidated binding", err)
	}
	fresh := latest.Binding
	fresh.BindingVersion = remoteVersion(7)
	if _, err = r.PrepareSnapshot(testContext, "root", 2, wireReady(fresh, "new", "2"), remoteNow); err != nil {
		t.Fatal("fresh binding refused", err)
	}
}

func TestRemotePreparationExpiryScopeAndBoundedAbandonment(t *testing.T) {
	r, _, _ := remoteFixture(t)
	p, err := r.PrepareSnapshot(testContext, "root", 1, wireReady(remoteBindingFixture(), "s", "0"), remoteNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ImportSnapshotPage(testContext, "root", p.Cursor, wirePage(p, []syncproto.Descriptor{folderRemote("a", "", "root")}, "done", false), remoteNow.Add(time.Minute)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("lease expired", err)
	}
	if err = r.AbandonPreparation(testContext, p); err != nil {
		t.Fatal(err)
	}
	if _, err = r.PruneRemoteGeneration(testContext, "root", p.Generation, 501); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("unbounded cleanup", err)
	}
	if _, err = r.PruneRemoteGeneration(testContext, "root", p.Generation, 500); err != nil {
		t.Fatal(err)
	}
	wrong := remoteBindingFixture()
	wrong.RootID = "other"
	if _, err = r.PrepareSnapshot(testContext, "root", 1, wireReady(wrong, "s", "0"), remoteNow); err == nil {
		t.Fatal("cross root accepted")
	}
}

func capturedRemoteFixture(t *testing.T) (*RemoteImport, SourceWitness, *VerifiedSnapshot, string, RemoteCandidate) {
	t.Helper()
	dir := t.TempDir()
	filename := filepath.Join(dir, "file")
	if err := os.WriteFile(filename, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	s, w, _ := sourceFixture(t, dir)
	b := testBinding
	b.SourceIdentity = w.SetID
	if err := s.store.BindRoot(testContext, b); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachSourceSet(testContext, w.SetID, w.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	scanSource(t, s, w, "scan", nil)
	a, err := s.store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	r, err := s.store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := s.SourceEntry(testContext, w.SetID, sourceDestination(filename))
	if err != nil {
		t.Fatal(err)
	}
	v, err := CaptureGuarded(testContext, w, entry, a.Directory(), &registryFixtureLimiter{a: a, reader: newTestCaptureLimiter()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	if err = s.RecordVerifiedSnapshot(testContext, w, v); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(entry.Destination, "/")
	parent := ""
	remoteParent := "remote-root"
	descriptors := []syncproto.Descriptor{folderRemote("remote-root", "", "root")}
	leaf := ""
	for i, name := range parts {
		id := fmt.Sprintf("local-%04d", i)
		l := Observation{RootID: "root", EntryID: id, ParentID: parent, Name: name, NameKey: name, Kind: "folder", FileIdentity: "virtual-" + id, Presence: "PRESENT"}
		if i == len(parts)-1 {
			l.Kind = "file"
			l.SizeBytes = entry.SizeBytes
			l.FileIdentity = entry.FileIdentity
			leaf = id
		}
		capture(t, s.store, l)
		node := fmt.Sprintf("node-%04d", i)
		if l.Kind == "folder" {
			descriptors = append(descriptors, folderRemote(node, remoteParent, name))
		} else {
			descriptors = append(descriptors, fileRemote(node, remoteParent, name, "one"))
		}
		parent = id
		remoteParent = node
	}
	c := publishRemote(t, r, descriptors)
	if err = r.ProjectCapturedEntry(testContext, w, "root", leaf, v); err != nil {
		t.Fatal(err)
	}
	return r, w, v, leaf, c
}
func fixtureRemoteAuthority(c RemoteCandidate) *RemoteAuthority {
	return &RemoteAuthority{witness: c.RemoteWitness, qualifiedAtMS: remoteNow.UnixMilli(), expiresMS: remoteNow.Add(30 * time.Second).UnixMilli()}
}
func seedCapturedParentBases(t *testing.T, r *RemoteImport, entry string, c RemoteCandidate) {
	t.Helper()
	if err := r.store.transaction(testContext, func(tx *sql.Tx) error {
		l, err := readJSON[Observation](testContext, tx, "SELECT descriptor_json FROM local_entries WHERE root_id='root' AND entry_id=?", entry)
		if err != nil {
			return err
		}
		chain, _, err := localPath(testContext, tx, l)
		if err != nil {
			return err
		}
		parent := "remote-root"
		for i := len(chain) - 1; i > 0; i-- {
			l := chain[i]
			e, err := namespaceCandidate(testContext, tx, c.RemoteWitness, parent, l.Name)
			if err != nil || e == nil {
				return errors.Join(err, ErrIdentityConflict)
			}
			b := Baseline{RootID: l.RootID, EntryID: l.EntryID, NodeID: e.NodeID, Epoch: e.Epoch, Version: e.Version, Kind: "folder", Presence: "PRESENT", ParentID: l.ParentID, Name: l.Name, NameKey: l.NameKey, FileIdentity: l.FileIdentity, LocalGeneration: l.Generation, TrustGeneration: 1, RemoteBinding: &c.Binding, RemoteParentID: e.ParentID, LastSeq: e.LastSeq}
			raw, _ := json.Marshal(b)
			if _, err = tx.Exec("INSERT INTO baselines(root_id,entry_id,node_id,descriptor_json) VALUES(?,?,?,?)", l.RootID, l.EntryID, e.NodeID, string(raw)); err != nil {
				return err
			}
			parent = e.NodeID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedAgreementRequiresActualAuthorityAndExactCAS(t *testing.T) {
	r, w, v, entry, c := capturedRemoteFixture(t)
	d, err := r.DecideCaptured(testContext, w, "root", entry, v, nil, remoteNow)
	if err != nil || d.Kind != "RECONCILE" {
		t.Fatal("raw READY fabricated authority", d, err)
	}
	if err = r.AdoptCaptured(testContext, w, v, nil, d, remoteNow); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal(err)
	}
	a := fixtureRemoteAuthority(c)
	d, err = r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow)
	if err != nil || d.Kind != "ADOPT_EQUAL" {
		t.Fatal(d, err)
	}
	bad := d
	bad.Witness.StateDigest = "other"
	if err = r.AdoptCaptured(testContext, w, v, a, bad, remoteNow); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("forged/stale witness", err)
	}
	r.testPoint = func(p string) error {
		if p == "capture.before_adopt" {
			return context.Canceled
		}
		return nil
	}
	if err = r.AdoptCaptured(testContext, w, v, a, d, remoteNow); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = readJSON[Baseline](testContext, r.store.db, "SELECT descriptor_json FROM baselines WHERE root_id='root' AND entry_id=?", entry); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("B escaped failed adoption", err)
	}
	r.testPoint = nil
	if err = r.AdoptCaptured(testContext, w, v, a, d, remoteNow); err != nil {
		t.Fatal(err)
	}
	b, err := readJSON[Baseline](testContext, r.store.db, "SELECT descriptor_json FROM baselines WHERE root_id='root' AND entry_id=?", entry)
	if err != nil || b.CaptureProof == nil || *b.CaptureProof != v.Evidence() || b.RemoteBinding == nil || *b.RemoteBinding != c.Binding || b.OperationID != "" {
		t.Fatal("forged receipt or capture lost", b, err)
	}
	seedCapturedParentBases(t, r, entry, c)
	noop, err := r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow)
	if err != nil || noop.Kind != "NOOP_CAPTURED" {
		t.Fatal(noop, err)
	}
	if _, err = r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	expired, _ := r.DecideCaptured(testContext, w, "root", entry, v, a, remoteNow.Add(30*time.Second))
	if expired.Kind != "RECONCILE" {
		t.Fatal("freshness boundary", expired)
	}
	// A remote metadata change conflicts even when all content bytes stay equal.
	e := descriptorFromRemote(*noop.Remote)
	e.Version = remoteVersion(20)
	newCut, err := r.ImportFeed(testContext, c.RemoteWitness, wireFeed(c.RemoteWitness, []syncproto.FeedItem{{Descriptor: e, Seq: "1", Kind: "upsert", OperationID: "remote-edit"}}, "feed1"))
	if err != nil {
		t.Fatal(err)
	}
	if err = r.AdoptCaptured(testContext, w, v, a, noop, remoteNow); err == nil {
		t.Fatal("late R accepted stale adoption")
	}
	conflict, err := r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(newCut), remoteNow)
	if err != nil || conflict.Kind != "CONFLICT" {
		t.Fatal("same L/new R was not conflict", conflict, err)
	}
}

func TestCapturedPendingOriginalIntentAndLocalAbsencePreserveRemote(t *testing.T) {
	r, w, v, entry, _ := capturedRemoteFixture(t)
	intent := fixtureIntent(t, r.store, "original-immutable", entry)
	fixtureLegacyPending(t, r.store, intent, "PLANNED", "", "")
	d, err := r.DecideCaptured(testContext, w, "root", entry, nil, nil, remoteNow)
	if err != nil || d.Kind != "RECOVER" || d.OperationID != intent.OperationID {
		t.Fatal(d, err)
	}
	before, err := r.store.Operation(testContext, intent.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ProjectCapturedEntry(testContext, w, "root", entry, v); err != nil {
		t.Fatal("equal capture may retain same generation", err)
	}
	after, _ := r.store.Operation(testContext, intent.OperationID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("intent replaced")
	}
	// Routing KEEP_REMOTE itself writes no B/receipt/dirty/trust and never sends
	// a deletion. The fixture removes the unfinished intent only to test routing.
	if _, err = r.store.db.Exec("DELETE FROM operations WHERE operation_id=?", intent.OperationID); err != nil {
		t.Fatal(err)
	}
	l, _ := readJSON[Observation](testContext, r.store.db, "SELECT descriptor_json FROM local_entries WHERE root_id='root' AND entry_id=?", entry)
	l.Presence = "ABSENT"
	raw, _ := json.Marshal(l)
	if _, err = r.store.db.Exec("UPDATE local_entries SET descriptor_json=? WHERE root_id='root' AND entry_id=?", string(raw), entry); err != nil {
		t.Fatal(err)
	}
	d, err = r.DecideCaptured(testContext, w, "root", entry, nil, nil, remoteNow)
	if err != nil || d.Kind != "KEEP_REMOTE" {
		t.Fatal(d, err)
	}
}
