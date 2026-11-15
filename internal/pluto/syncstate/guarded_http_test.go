package syncstate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"pluto/internal/syncproto"
)

type httpFixtureUpload struct {
	serverID string
	op       Operation
	input    catalogHTTPInput
	bytes    []byte
	result   map[string]any
}
type guardedHTTPFixture struct {
	t                                     *testing.T
	r                                     *RemoteImport
	binding                               RemoteBinding
	mu                                    sync.Mutex
	seq                                   int64
	nodes                                 map[string]syncproto.Descriptor
	events                                []syncproto.FeedItem
	uploads                               map[string]*httpFixtureUpload
	folders                               map[string]map[string]any
	requests                              map[string]int
	lostComplete, lostAppend, lostPrepare bool
	rejectRedirect                        bool
	rejectFeedAfterFolder                 bool
}

func (f *guardedHTTPFixture) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	raw, e := httpJSON(v)
	if e != nil {
		f.t.Error(e)
		w.WriteHeader(500)
		return
	}
	w.Write(raw)
}
func (f *guardedHTTPFixture) lose(w http.ResponseWriter) {
	conn, _, e := w.(http.Hijacker).Hijack()
	if e != nil {
		f.t.Error(e)
		return
	}
	conn.Close()
}
func (f *guardedHTTPFixture) namespace(parent, name string) *syncproto.Descriptor {
	for _, d := range f.nodes {
		if d.ParentID != nil && *d.ParentID == parent && d.Name == name {
			copy := d
			return &copy
		}
	}
	return nil
}
func (f *guardedHTTPFixture) emit(d syncproto.Descriptor, op string) {
	f.seq++
	f.nodes[d.NodeID] = d
	f.events = append(f.events, syncproto.FeedItem{Descriptor: d, Seq: remoteDecimal(f.seq), Kind: "upsert", OperationID: op})
}
func (f *guardedHTTPFixture) status(u *httpFixtureUpload) map[string]any {
	phase := "transport"
	if u.result != nil {
		phase = "published"
	}
	m := map[string]any{"session": map[string]any{"uploadId": u.serverID, "operationId": u.serverID, "rootId": f.binding.RootID, "intentHash": u.input.hash, "expectedSizeBytes": remoteDecimal(u.op.SizeBytes), "receivedSizeBytes": remoteDecimal(int64(len(u.bytes))), "phase": phase, "transferPending": false}, "replayed": false}
	if u.result != nil {
		m["result"] = u.result
	}
	return m
}
func (f *guardedHTTPFixture) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(req.URL.Path, "/sync/v1/roots/"+f.binding.RootID+"/")
	f.requests[path]++
	if req.Header.Get("Authorization") != "Bearer fixture-token" {
		w.WriteHeader(401)
		return
	}
	if f.rejectRedirect {
		w.Header().Set("Location", "http://127.0.0.1:1/secret")
		w.WriteHeader(302)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(req.Body, 4+HTTPMetadataBytes+HTTPChunkBytes+1))
	if e != nil {
		f.t.Error(e)
		w.WriteHeader(500)
		return
	}
	var payload []byte
	if path == "catalog-uploads/append" {
		if req.Header.Get("Content-Type") != HTTPFrameType || len(raw) < 5 {
			w.WriteHeader(400)
			return
		}
		n := int(binary.BigEndian.Uint32(raw))
		if n > HTTPMetadataBytes || n > len(raw)-4 {
			w.WriteHeader(400)
			return
		}
		payload = raw[4+n:]
		raw = raw[4 : 4+n]
	}
	v, e := syncproto.Parse(raw)
	if e != nil {
		f.t.Error(e)
		w.WriteHeader(400)
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		w.WriteHeader(400)
		return
	}
	got, e := syncproto.ReadBinding(m["binding"].(map[string]any))
	if e != nil || got != f.binding {
		f.t.Error("request binding", e)
		w.WriteHeader(409)
		return
	}
	switch path {
	case "snapshots/start", "snapshots/step":
		id := m["snapshot_id"].(string)
		stored, e := f.r.pendingHTTPSnapshot(f.binding)
		if e != nil || stored != id {
			f.t.Error("start UUID not durable before network", stored, id, e)
		}
		f.json(w, map[string]any{"snapshotId": id, "state": "READY", "startSeq": remoteDecimal(f.seq), "appliedSeq": remoteDecimal(f.seq), "cutSeq": remoteDecimal(f.seq), "entries": remoteDecimal(int64(len(f.nodes))), "documentBytes": "0"})
	case "snapshots/ready":
		f.json(w, jsonRawValue(wireReady(f.binding, m["snapshot_id"].(string), remoteDecimal(f.seq))))
	case "entries":
		p := SnapshotPreparation{Snapshot: syncproto.Snapshot{Binding: f.binding, SnapshotID: strings.TrimPrefix(m["cursor"].(string), "entries-"), CutSeq: remoteDecimal(f.seq)}}
		values := make([]syncproto.Descriptor, 0, len(f.nodes))
		for _, d := range f.nodes {
			values = append(values, d)
		}
		sort.Slice(values, func(i, j int) bool { return values[i].NodeID < values[j].NodeID })
		f.json(w, jsonRawValue(wirePage(p, values, "entries-done", false)))
	case "changes":
		if f.rejectFeedAfterFolder && len(f.folders) > 0 {
			w.WriteHeader(409)
			return
		}
		c, e := f.r.Candidate(req.Context(), "root")
		if e != nil {
			f.t.Error(e)
			w.WriteHeader(500)
			return
		}
		if m["cursor"] != c.Cursor {
			f.t.Error("stale client feed cursor")
		}
		items := make([]syncproto.FeedItem, 0)
		for _, item := range f.events {
			seq, _ := syncproto.Integer64(item.Seq)
			if seq > c.Position {
				items = append(items, item)
			}
		}
		f.json(w, jsonRawValue(wireFeed(c.RemoteWitness, items, "feed-"+remoteDecimal(f.seq))))
	case "directories/ensure-v2":
		input, e := strictHTTPObject(m["input"], "operationId", "idempotencyKey", "rootId", "epoch", "bindingVersion", "parentId", "name", "mode", "parentTopology")
		if e != nil {
			f.t.Error(e)
			w.WriteHeader(400)
			return
		}
		id := input["operationId"].(string)
		op, e := f.r.store.Operation(req.Context(), id)
		if e != nil || op.Stage != "SUBMITTED" && op.Stage != "CLIENT_ACKED" || op.FolderHTTP == nil {
			f.t.Error("folder not durable before effect", e)
			w.WriteHeader(500)
			return
		}
		expect, _ := httpJSON(op.FolderHTTP.Input)
		actual, _ := httpJSON(input)
		if !reflect.DeepEqual(jsonRawValue(expect), jsonRawValue(actual)) {
			f.t.Error("folder original input rewritten")
		}
		if result := f.folders[id]; result != nil {
			f.json(w, map[string]any{"replayed": true, "result": result})
			return
		}
		parent := input["parentId"].(string)
		name := input["name"].(string)
		d := f.namespace(parent, name)
		status := "EXISTING"
		if d == nil {
			next := folderRemote(remoteVersion(1000+len(f.nodes)), parent, name)
			next.Version = remoteVersion(2000 + len(f.nodes))
			d = &next
			status = "CREATED"
			f.emit(*d, id)
		}
		result := map[string]any{"schema": "saturn.catalog-folder-result.v2", "operationId": id, "intentHash": hashBytes([]byte("private-server-fields:" + id)), "rootId": f.binding.RootID, "status": status, "description": wireDescriptor(*d)}
		f.folders[id] = result
		f.json(w, map[string]any{"replayed": false, "result": result})
	case "catalog-uploads/prepare", "catalog-uploads/inspect", "catalog-uploads/complete", "catalog-uploads/append":
		given := m["input"].(map[string]any)["intent"].(map[string]any)
		id := strings.TrimPrefix(given["idempotencyKey"].(string), "pluto-sync-")
		op, e := f.r.store.Operation(req.Context(), id)
		if e != nil || op.Stage != "SUBMITTED" {
			f.t.Error("file not durable before effect", e)
			w.WriteHeader(500)
			return
		}
		original, e := originalCatalogInput(op)
		if e != nil {
			f.t.Error(e)
			w.WriteHeader(500)
			return
		}
		expectedRaw, _ := httpJSON(original.body)
		if !reflect.DeepEqual(jsonRawValue(expectedRaw), m["input"]) {
			f.t.Errorf("original transport input mismatch %s", path)
			w.WriteHeader(409)
			return
		}
		u := f.uploads[id]
		if u == nil {
			if path != "catalog-uploads/prepare" || m["upload_id"] != nil {
				f.t.Error("first prepare guessed an original server upload ID")
				w.WriteHeader(409)
				return
			}
			u = &httpFixtureUpload{op: op, input: original, serverID: remoteVersion(6000 + len(f.uploads))}
			f.uploads[id] = u
		}
		if supplied, exists := m["upload_id"]; exists && supplied != u.serverID || path != "catalog-uploads/prepare" && m["upload_id"] != u.serverID {
			f.t.Error("request server upload ID differs from accepted original")
			w.WriteHeader(409)
			return
		}
		if path != "catalog-uploads/prepare" && (op.HTTPBinding == nil || op.HTTPBinding.ServerUploadID != u.serverID) {
			f.t.Error("transport effect before durable server ID binding")
			w.WriteHeader(409)
			return
		}
		if path == "catalog-uploads/prepare" && f.lostPrepare {
			f.lostPrepare = false
			f.lose(w)
			return
		}
		if path == "catalog-uploads/append" {
			offset, e := syncproto.Integer64(m["offset"])
			if e != nil || offset != int64(len(u.bytes)) || len(payload) == 0 || len(payload) > HTTPChunkBytes {
				w.WriteHeader(409)
				return
			}
			u.bytes = append(u.bytes, payload...)
			if f.lostAppend {
				f.lostAppend = false
				f.lose(w)
				return
			}
		}
		if path == "catalog-uploads/complete" && u.result == nil {
			if int64(len(u.bytes)) != op.SizeBytes || hashBytes(u.bytes) != op.SHA256 {
				w.WriteHeader(422)
				return
			}
			chain, _ := op.ParentTopology()
			parent := chain[0].NodeID
			old := f.namespace(parent, op.Name)
			if op.ExpectedAbsent && old != nil || !op.ExpectedAbsent && (old == nil || old.NodeID != op.ExpectedNodeID || old.Version != op.ExpectedVersion) {
				w.WriteHeader(409)
				return
			}
			node := remoteVersion(1000 + len(f.nodes))
			if old != nil {
				node = old.NodeID
			}
			d := fileRemote(node, parent, op.Name, string(u.bytes))
			d.Version = remoteVersion(3000 + int(f.seq))
			content := remoteVersion(4000 + int(f.seq))
			d.ContentVersionID = &content
			f.emit(d, u.serverID)
			receipt := map[string]any{"schema": "saturn.upload-publication.v1", "uploadId": u.serverID, "operationId": u.serverID, "intentHash": u.input.hash, "rootId": f.binding.RootID, "resourceId": node, "versionId": content, "parentId": parent, "name": op.Name, "sizeBytes": remoteDecimal(op.SizeBytes), "sha256": op.SHA256, "etag": fmt.Sprintf("\"sha256-%s\"", op.SHA256), "publishedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
			u.result = map[string]any{"schema": "saturn.catalog-upload-result.v2", "status": "PUBLISHED", "uploadId": u.serverID, "operationId": u.serverID, "rootId": f.binding.RootID, "intentHash": u.input.hash, "publicationReceipt": receipt, "publishedDescription": wireDescriptor(d), "firstSeq": remoteDecimal(f.seq), "lastSeq": remoteDecimal(f.seq)}
			if f.lostComplete {
				f.lostComplete = false
				f.lose(w)
				return
			}
		}
		f.json(w, f.status(u))
	default:
		f.t.Error("unexpected route", path)
		w.WriteHeader(404)
	}
}
func jsonRawValue(raw []byte) any { v, _ := syncproto.Parse(raw); return v }

func actualHTTPFixture(t *testing.T, files int) (*RemoteImport, *Sources, SourceWitness, *IsolatedHTTPSession, *guardedHTTPFixture, string) {
	return actualHTTPFixtureInitialization(t, files, true)
}
func actualHTTPFixtureInitialization(t *testing.T, files int, initialize bool) (*RemoteImport, *Sources, SourceWitness, *IsolatedHTTPSession, *guardedHTTPFixture, string) {
	t.Helper()
	work := nativeFixtureTempDir(t)
	dir := filepath.Join(work, "tree", "nested")
	os.MkdirAll(dir, 0700)
	for n := 0; n < files; n++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%03d", n)), []byte("one"), 0600)
	}
	store, e := Open(testContext, nativeFixtureTempDir(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := store.Close(); e != nil {
			t.Error(e)
		}
	})
	sources, e := store.EnableSources(testContext, DefaultSourceLimits())
	if e != nil {
		t.Fatal(e)
	}
	set, e := sources.BindSourceSet(testContext, "set", hashBytes([]byte("fixture-config")), 0, []SourceSpec{{ID: "source", SelectedPath: "tree", WorkingDirectory: work}})
	if e != nil {
		t.Fatal(e)
	}
	binding := RemoteBinding{Protocol: syncproto.Protocol, DescriptorSchema: syncproto.DescriptorSchema, ServerIdentity: "saturn-http-fixture", RootID: remoteVersion(50), ServerEpoch: remoteVersion(52), PolicyVersion: "policy", BindingVersion: remoteVersion(1)}
	device := remoteVersion(51)
	root := RootBinding{RootID: "root", MappingID: "mapping", ServerIdentity: binding.ServerIdentity, RemoteRootID: binding.RootID, DeviceID: device, SourceIdentity: "set"}
	if e = store.BindRoot(testContext, root); e != nil {
		t.Fatal(e)
	}
	if e = sources.AttachSourceSet(testContext, set.ID, set.Revision, "root"); e != nil {
		t.Fatal(e)
	}
	w, e := sources.BeginSourceOwner(testContext, set.ID, set.Revision, "owner")
	if e != nil {
		t.Fatal(e)
	}
	registry, e := store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = registry.Reconcile(testContext, artifactTestReader); e != nil {
		t.Fatal(e)
	}
	r, e := store.EnableRemoteImport(testContext)
	if e != nil {
		t.Fatal(e)
	}
	fixture := &guardedHTTPFixture{t: t, r: r, binding: binding, nodes: map[string]syncproto.Descriptor{binding.RootID: folderRemote(binding.RootID, "", "backup")}, uploads: map[string]*httpFixtureUpload{}, folders: map[string]map[string]any{}, requests: map[string]int{}}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	session, e := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: server.URL, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(binding), DeviceID: device, BackendIdentity: "backend-own", QualificationReceiptSHA256: hashBytes([]byte("test-only-own-qualification")), Token: "fixture-token"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(session.Close)
	session.SetRecoveryReader(artifactTestReader)
	if initialize {
		if e = session.InitializeRemote(testContext); e != nil {
			t.Fatal(e)
		}
	}
	nativeFixtureRegisterCleanup(t) // actors before HTTP/store cleanup; retained originals
	return r, sources, w, session, fixture, dir
}
func runActualHTTPFixture(t *testing.T, r *RemoteImport, w SourceWitness, s *IsolatedHTTPSession) (CapturedScanReport, error) {
	t.Helper()
	return r.RunCapturedScan(testContext, CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: s, Capture: func(ctx context.Context, w SourceWitness, e SourceEntry) (*VerifiedSnapshot, error) {
		return CaptureGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	}})
}

func TestGuardedHTTPActualInitialParentsRepeatEditAndNoHead(t *testing.T) {
	r, _, w, s, f, dir := actualHTTPFixture(t, 4)
	first, e := runActualHTTPFixture(t, r, w, s)
	if e != nil || first.Uploaded != 4 || first.Failed != 0 || !first.Complete {
		t.Fatal(first, e)
	}
	if len(f.folders) != 2 || len(f.nodes) != 7 {
		t.Fatal("initial parents not created from empty remote", len(f.folders), len(f.nodes))
	}
	before := s.Metrics()
	repeat, e := runActualHTTPFixture(t, r, w, s)
	if e != nil || repeat.Uploaded != 0 || repeat.Adopted != 4 {
		t.Fatal(repeat, e)
	}
	after := s.Metrics()
	if before.DataBytes != after.DataBytes || after.Requests != before.Requests {
		t.Fatal("unchanged per-file requests", before, after)
	}
	name := filepath.Join(dir, "file-000")
	info, _ := os.Stat(name)
	os.WriteFile(name, []byte("two"), 0600)
	os.Chtimes(name, info.ModTime(), info.ModTime())
	edited, e := runActualHTTPFixture(t, r, w, s)
	if e != nil || edited.Uploaded != 1 || edited.Adopted != 3 {
		t.Fatal(edited, e)
	}
	for route := range f.requests {
		if strings.Contains(route, "HEAD") {
			t.Fatal("HEAD invoked")
		}
	}
	// The repeat preparation shortcut does not bypass full parent proof in the
	// captured decision. A renamed parent conflicts before any new upload.
	before = s.Metrics()
	f.mu.Lock()
	for _, d := range f.nodes {
		if d.Type == "folder" && d.Name == "nested" {
			d.Name = "other"
			d.Version = remoteVersion(9900)
			f.emit(d, "remote-change")
			break
		}
	}
	f.mu.Unlock()
	if e = s.Refresh(testContext); e != nil {
		t.Fatal(e)
	}
	diverged, e := runActualHTTPFixture(t, r, w, s)
	if e == nil || diverged.Failed != 4 || diverged.Uploaded != 0 || diverged.Adopted != 0 || s.Metrics().DataBytes != before.DataBytes {
		t.Fatal("parent shortcut lost proof", diverged, e, s.Metrics())
	}
}
func TestGuardedHTTPLostPublicationAndAppendRecoverOriginalIdentity(t *testing.T) {
	for _, point := range []string{"publication", "append"} {
		t.Run(point, func(t *testing.T) {
			r, sources, w, s, f, dir := actualHTTPFixture(t, 1)
			if point == "publication" {
				f.lostComplete = true
			} else {
				f.lostAppend = true
				if e := os.WriteFile(filepath.Join(dir, "file-000"), bytes.Repeat([]byte("z"), HTTPChunkBytes+17), 0600); e != nil {
					t.Fatal(e)
				}
			}
			first, e := runActualHTTPFixture(t, r, w, s)
			if e == nil || first.Failed != 1 {
				t.Fatal("loss not retained", first, e)
			}
			pending, e := r.store.PendingPage(testContext, "root", "", 10)
			if e != nil || len(pending) != 1 || pending[0].Captured == nil {
				t.Fatal(pending, e)
			}
			original := pending[0]
			if _, e = r.store.artifacts.Reconcile(testContext, artifactTestReader); e != nil {
				t.Fatal(e)
			}
			next, e := sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "owner-after-loss")
			if e != nil {
				t.Fatal(e)
			}
			recovered, e := runActualHTTPFixture(t, r, next, s)
			if e != nil || recovered.Recovered != 1 || recovered.Uploaded != 0 {
				t.Fatal(recovered, e)
			}
			ack, e := r.store.Operation(testContext, original.OperationID)
			if e != nil || ack.Stage != "CLIENT_ACKED" || ack.IntentFingerprint != original.IntentFingerprint || len(f.uploads) != 1 {
				t.Fatal(ack, e, len(f.uploads))
			}
		})
	}
}
func TestGuardedHTTPWireCanonicalAndTerminalTamper(t *testing.T) {
	stringsToEncode := []string{"<>&", "line\u2028separator\u2029", `literal\u2028\u2029`}
	raw, e := httpJSON(stringsToEncode)
	if e != nil || bytes.Contains(raw, []byte(`\u003c`)) || !bytes.Contains(raw, []byte("\u2028")) || !bytes.Contains(raw, []byte(`\\u2028`)) {
		t.Fatal(string(raw), e)
	}
	var decoded []string
	if e = json.Unmarshal(raw, &decoded); e != nil || !reflect.DeepEqual(decoded, stringsToEncode) {
		t.Fatal(decoded, e)
	}
	r, _, w, s, f, _ := actualHTTPFixture(t, 1)
	if _, e = runActualHTTPFixture(t, r, w, s); e != nil {
		t.Fatal(e)
	}
	var u *httpFixtureUpload
	for _, v := range f.uploads {
		u = v
	}
	m := f.status(u)
	m["result"].(map[string]any)["intentHash"] = strings.Repeat("0", 64)
	if _, e = readCatalogHTTPStatus(mustJSON(m), u.op, u.input); !errors.Is(e, ErrInvalidReceipt) {
		t.Fatal("tamper allowed", e)
	}
}
func TestGuardedHTTPRedirectAndUntrustedAddressRefused(t *testing.T) {
	_, _, _, s, f, _ := actualHTTPFixture(t, 0)
	f.rejectRedirect = true
	if e := s.Refresh(testContext); e == nil {
		t.Fatal("redirect followed")
	}
	if s.Metrics().DataBytes != 0 {
		t.Fatal("unexpected payload")
	}
}
