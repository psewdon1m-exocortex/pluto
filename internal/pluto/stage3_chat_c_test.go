//go:build linux

package pluto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

func cUUID(n int) string    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func cHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type cUpload struct {
	Input    map[string]any
	ID, Hash string
	Bytes    []byte
	Result   any
}
type cServer struct {
	t              *testing.T
	mu             sync.Mutex
	binding        map[string]any
	nodes          map[string]map[string]any
	events         []map[string]any
	folders        map[string]any
	uploads        map[string]*cUpload
	calls          map[string]int
	seq            int
	blockComplete  bool
	wire           []json.RawMessage
	holdChanges    chan struct{}
	changesEntered chan struct{}
}

func cFolder(id, parent, name string) map[string]any {
	var p any
	if parent != "" {
		p = parent
	}
	return map[string]any{"node_id": id, "parent_id": p, "name": name, "type": "folder", "size_bytes": "0", "content_sha256": nil, "content_version_id": nil, "version": cUUID(2), "availability": "AVAILABLE"}
}
func (f *cServer) envelope() map[string]any {
	m := map[string]any{}
	for k, v := range f.binding {
		m[k] = v
	}
	return m
}
func (f *cServer) emit(d map[string]any, op string) {
	f.seq++
	f.nodes[d["node_id"].(string)] = d
	event := map[string]any{}
	for k, v := range d {
		event[k] = v
	}
	event["seq"] = strconv.Itoa(f.seq)
	event["kind"] = "upsert"
	event["operation_id"] = op
	f.events = append(f.events, event)
}
func (f *cServer) status(u *cUpload) map[string]any {
	intent := u.Input["intent"].(map[string]any)
	phase := "transport"
	if u.Result != nil {
		phase = "published"
	}
	out := map[string]any{"session": map[string]any{"uploadId": u.ID, "operationId": u.ID, "rootId": f.binding["root_id"], "intentHash": u.Hash, "expectedSizeBytes": intent["sizeBytes"], "receivedSizeBytes": strconv.Itoa(len(u.Bytes)), "phase": phase, "transferPending": false}, "replayed": false}
	if u.Result != nil {
		out["result"] = u.Result
	}
	return out
}
func (f *cServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/sync/v1/roots/"+f.binding["root_id"].(string)+"/")
	f.calls[path]++
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			f.t.Log("fixture response closed", err)
		}
	}
	if r.Header.Get("Authorization") != "Bearer fixture-canary-credential" {
		w.WriteHeader(401)
		return
	}
	if path == "capabilities" {
		reply(map[string]any{"schema": "saturn.sync-capabilities.v1", "binding": f.binding, "device_id": cUUID(51), "backend_identity": "backend-c", "qualification_receipt_sha256": cHash([]byte("qualification")), "features": []string{"snapshot-v1", "changes-v1", "folder-v2", "catalog-upload-v2"}})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (8<<20)+65536))
	if err != nil {
		w.WriteHeader(400)
		return
	}
	if r.URL.Path == "/api/v1/pluto/check-in" {
		f.wire = append(f.wire, append([]byte(nil), raw...))
		reply(map[string]any{})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/sync/v1/") {
		f.t.Errorf("legacy or destructive route %s", r.URL.Path)
		w.WriteHeader(400)
		return
	}
	var payload []byte
	if path == "catalog-uploads/append" {
		if len(raw) < 4 {
			w.WriteHeader(400)
			return
		}
		n := int(binary.BigEndian.Uint32(raw))
		if n+4 > len(raw) {
			w.WriteHeader(400)
			return
		}
		payload = raw[n+4:]
		raw = raw[4 : n+4]
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		w.WriteHeader(400)
		return
	}
	switch path {
	case "snapshots/start", "snapshots/step":
		reply(map[string]any{"snapshotId": body["snapshot_id"], "state": "READY", "startSeq": strconv.Itoa(f.seq), "appliedSeq": strconv.Itoa(f.seq), "cutSeq": strconv.Itoa(f.seq), "entries": strconv.Itoa(len(f.nodes)), "documentBytes": "0"})
	case "snapshots/ready":
		m := f.envelope()
		m["state"] = "READY"
		m["snapshot_id"] = body["snapshot_id"]
		m["cut_seq"] = strconv.Itoa(f.seq)
		m["entries_cursor"] = "entries-" + body["snapshot_id"].(string)
		m["changes_cursor"] = "feed-" + strconv.Itoa(f.seq)
		m["lease_seconds"] = 60
		m["absolute_lifetime_seconds"] = 600
		reply(m)
	case "entries":
		m := f.envelope()
		m["snapshot_id"] = strings.TrimPrefix(body["cursor"].(string), "entries-")
		m["cut_seq"] = strconv.Itoa(f.seq)
		m["after_node_id"] = nil
		ids := []string{}
		for id := range f.nodes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		items := []any{}
		for _, id := range ids {
			items = append(items, f.nodes[id])
		}
		m["last_node_id"] = ids[len(ids)-1]
		m["items"] = items
		m["next_cursor"] = "entries-done"
		m["has_more"] = false
		reply(m)
	case "changes":
		if f.holdChanges != nil {
			if f.changesEntered != nil {
				close(f.changesEntered)
				f.changesEntered = nil
			}
			select {
			case <-r.Context().Done():
				return
			case <-f.holdChanges:
			}
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(body["cursor"].(string), "feed-"))
		m := f.envelope()
		m["from_exclusive"] = strconv.Itoa(n)
		m["to_inclusive"] = strconv.Itoa(f.seq)
		m["items"] = append([]map[string]any{}, f.events[n:]...)
		m["next_cursor"] = "feed-" + strconv.Itoa(f.seq)
		m["has_more"] = false
		reply(m)
	case "directories/ensure-v2":
		input := body["input"].(map[string]any)
		id := input["operationId"].(string)
		if result := f.folders[id]; result != nil {
			reply(map[string]any{"replayed": true, "result": result})
			return
		}
		var d map[string]any
		for _, node := range f.nodes {
			if node["parent_id"] == input["parentId"] && node["name"] == input["name"] {
				d = node
				break
			}
		}
		status := "EXISTING"
		if d == nil {
			d = cFolder(cUUID(1000+len(f.nodes)), input["parentId"].(string), input["name"].(string))
			f.emit(d, id)
			status = "CREATED"
		}
		result := map[string]any{"schema": "saturn.catalog-folder-result.v2", "operationId": id, "intentHash": cHash([]byte(id)), "rootId": f.binding["root_id"], "status": status, "description": d}
		f.folders[id] = result
		reply(map[string]any{"replayed": false, "result": result})
	case "catalog-uploads/prepare", "catalog-uploads/inspect", "catalog-uploads/append", "catalog-uploads/complete":
		input := body["input"].(map[string]any)
		intent := input["intent"].(map[string]any)
		key := intent["idempotencyKey"].(string)
		u := f.uploads[key]
		if u == nil {
			if path != "catalog-uploads/prepare" {
				w.WriteHeader(409)
				return
			}
			condition := intent["condition"].(map[string]any)
			canonical := []any{intent["schema"], intent["deviceKind"], intent["idempotencyKey"], intent["deviceId"], intent["rootId"], intent["requestPath"], intent["parentId"], intent["name"], intent["targetId"], intent["sizeBytes"], intent["sha256"], intent["ifMatch"], intent["ifNoneMatch"], intent["requireAbsent"], intent["expectedVersionId"], condition["kind"]}
			if condition["kind"] == "match" {
				canonical = append(canonical, condition["nodeId"], condition["metadataVersion"])
			}
			parents := []any{}
			for _, v := range intent["parentTopology"].([]any) {
				p := v.(map[string]any)
				parents = append(parents, []any{p["nodeId"], p["parentId"], p["name"]})
			}
			canonical = append(canonical, parents)
			var out bytes.Buffer
			encoder := json.NewEncoder(&out)
			encoder.SetEscapeHTML(false)
			encoder.Encode(canonical)
			u = &cUpload{Input: input, ID: cUUID(6000 + len(f.uploads)), Hash: cHash(bytes.TrimSuffix(out.Bytes(), []byte("\n")))}
			f.uploads[key] = u
		}
		if path == "catalog-uploads/append" {
			offset, _ := strconv.Atoi(body["offset"].(string))
			if offset != len(u.Bytes) {
				f.t.Error("duplicate append")
				w.WriteHeader(409)
				return
			}
			u.Bytes = append(u.Bytes, payload...)
		}
		if path == "catalog-uploads/complete" && u.Result == nil {
			if f.blockComplete {
				w.WriteHeader(503)
				reply(map[string]any{"code": "backend_busy"})
				return
			}
			if cHash(u.Bytes) != intent["sha256"] {
				f.t.Error("whole hash mismatch")
				w.WriteHeader(422)
				return
			}
			id := cUUID(200000 + f.seq)
			if intent["targetId"] != nil {
				id = intent["targetId"].(string)
			}
			cv := cUUID(300000 + f.seq)
			d := map[string]any{"node_id": id, "parent_id": intent["parentId"], "name": intent["name"], "type": "file", "size_bytes": intent["sizeBytes"], "content_sha256": intent["sha256"], "content_version_id": cv, "version": cUUID(400000 + f.seq), "availability": "AVAILABLE"}
			f.emit(d, u.ID)
			receipt := map[string]any{"schema": "saturn.upload-publication.v1", "uploadId": u.ID, "operationId": u.ID, "intentHash": u.Hash, "rootId": f.binding["root_id"], "resourceId": id, "versionId": cv, "parentId": intent["parentId"], "name": intent["name"], "sizeBytes": intent["sizeBytes"], "sha256": intent["sha256"], "etag": fmt.Sprintf("\"sha256-%s\"", intent["sha256"]), "publishedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
			u.Result = map[string]any{"schema": "saturn.catalog-upload-result.v2", "status": "PUBLISHED", "uploadId": u.ID, "operationId": u.ID, "rootId": f.binding["root_id"], "intentHash": u.Hash, "publicationReceipt": receipt, "publishedDescription": d, "firstSeq": strconv.Itoa(f.seq), "lastSeq": strconv.Itoa(f.seq)}
		}
		reply(f.status(u))
	default:
		f.t.Error("unknown caller route", path)
		w.WriteHeader(404)
	}
}

type cDaemonFixture struct {
	t                                               *testing.T
	server                                          *cServer
	http                                            *httptest.Server
	base, state, config, socket, source, ca, binary string
	cfg                                             Config
	processes                                       *nativeFixtureScope // PROPOSED unimplemented unified owner API
}

func cNative(t *testing.T) *cDaemonFixture {
	return cNativeWithHandler(t, nil)
}
func cNativeWithHandler(t *testing.T, decorate func(http.Handler) http.Handler) *cDaemonFixture {
	t.Helper()
	binary := os.Getenv("STAGE3_PLUTO_BINARY")
	if binary == "" {
		t.Fatal("STAGE3_PLUTO_BINARY required: build actual cmd/pluto before native lane")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute binary required")
	}
	base, _ := nativeFixtureBase(t)
	// Fresh loaded owner retains originals even on FAIL; never adopt old repair roots.
	reuseBase := ""
	source := filepath.Join(base, "source")
	os.Mkdir(source, 0700)
	binding := map[string]any{"protocol": syncproto.Protocol, "descriptor_schema": syncproto.DescriptorSchema, "server_identity": "stage3-c", "root_id": cUUID(50), "server_epoch": cUUID(52), "policy_version": "policy", "binding_version": cUUID(1)}
	server := &cServer{t: t, binding: binding, nodes: map[string]map[string]any{cUUID(50): cFolder(cUUID(50), "", "backup")}, folders: map[string]any{}, uploads: map[string]*cUpload{}, calls: map[string]int{}}
	var handler http.Handler = server
	if decorate != nil {
		handler = decorate(handler)
	}
	var host *httptest.Server
	if reuseBase != "" {
		raw, err := os.ReadFile(filepath.Join(base, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		var retained Config
		if err = json.Unmarshal(raw, &retained); err != nil {
			t.Fatal(err)
		}
		origin, err := url.Parse(retained.SaturnURL)
		if err != nil || origin.Hostname() != "127.0.0.1" {
			t.Fatal("retained proxy must be loopback")
		}
		listener, err := net.Listen("tcp", origin.Host)
		if err != nil {
			t.Fatal(err)
		}
		host = httptest.NewUnstartedServer(handler)
		_ = host.Listener.Close()
		host.Listener = listener
		host.StartTLS()
	} else {
		host = httptest.NewTLSServer(handler)
	}
	t.Cleanup(host.Close)
	ca := filepath.Join(base, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: host.Certificate().Raw}), 0600)
	state := filepath.Join(base, "state")
	config := filepath.Join(base, "config.json")
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.IntervalSeconds = 60
	cfg.Sources = []string{source}
	cfg.SaturnURL = host.URL
	cfg.AccessToken = "fixture-canary-credential"
	cfg.Indexed = &IndexedConfig{Activated: true, Policy: SourcePolicy{Revision: 1, Codec: "legacy", Excludes: []string{}}, Profile: IndexedCommandConfig{Schema: IndexedProfileSchema, LocalRootID: "root", MappingID: "mapping", SourceSetID: "set", Sources: []IndexedSourceConfig{{ID: "source", SelectedPath: source}}, Remote: syncstate.IsolatedHTTPConfig{Domain: syncstate.DaemonHTTPContract, Origin: host.URL, AllowedAddresses: []string{"127.0.0.1"}, Binding: binding, DeviceID: cUUID(51), BackendIdentity: "backend-c", QualificationReceiptSHA256: cHash([]byte("qualification"))}}}
	if reuseBase != "" {
		raw, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Indexed == nil || len(cfg.Sources) != 1 || filepath.Dir(cfg.Sources[0]) != base {
			t.Fatal("retained fixture source identity is invalid")
		}
		// Preserve durable work, bindings, policy and original source inodes.
		// Only the disposed test proxy endpoint and its test CA are replaced.
		cfg.SaturnURL = host.URL
		cfg.Indexed.Profile.Remote.Origin = host.URL
		source = cfg.Sources[0]
	}
	if err := SaveJSON(config, cfg); err != nil {
		t.Fatal(err)
	}
	if err := SaveJSON(filepath.Join(state, "indexed-activation.json"), map[string]any{"phase": "COMPLETE"}); err != nil {
		t.Fatal(err)
	}
	processes := newNativeFixtureScope(t, binary, base, ca, config, state)
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("STAGE3_C_EVIDENCE") != "" {
			destination := filepath.Join(os.Getenv("STAGE3_C_EVIDENCE"), strings.ReplaceAll(t.Name(), "/", "-")+"-state")
			if raw, err := processes.RunReviewedAuxiliaryCopy("state", state, destination); err != nil {
				t.Log("failure state copy", string(raw), err)
			}
		}
	})
	// Register AFTER the backup hook: LIFO cleanup joins every CLI before copying.
	t.Cleanup(processes.CloseAdmissionAndJoinAll)
	return &cDaemonFixture{t, server, host, base, state, config, filepath.Join(base, "control.sock"), source, ca, binary, cfg, processes}
}

// PROPOSED API FACADE ONLY. Runner/host adapter is not implemented or admitted.
func (f *cDaemonFixture) command(action string, args ...string) ([]byte, error) {
	f.t.Helper()
	result := f.processes.RunDomain(action, args...)
	if result.LifecycleError != nil {
		f.t.Error("fixture lifecycle failed; scope admission closed", result.LifecycleError)
		return result.Combined, result.LifecycleError
	}
	return result.Combined, result.DomainError
}
func (f *cDaemonFixture) start() func(bool) {
	f.t.Helper()
	owner, err := f.processes.StartDaemon()
	if err != nil {
		f.t.Fatal(err)
	}
	// Full after-exec tuple/pidfd/right-fd proof must precede readiness.
	cAwait(f.t, func() bool {
		raw, err := f.command("status")
		var status Status
		return err == nil && json.Unmarshal(raw, &status) == nil
	})
	return owner.StopExactReviewedMode
}
func cAwait(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(45 * time.Second)
	releaseDeadline := nativeFixtureDeadline(t, until)
	defer releaseDeadline()
	for {
		ok := condition()
		// Late true/exit0 must not erase the original finite45s assertion.
		if time.Now().After(until) {
			t.Fatal("daemon fixture watchdog")
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (f *cDaemonFixture) status() Status {
	f.t.Helper()
	var s Status
	raw, err := f.command("status")
	if err != nil || json.Unmarshal(raw, &s) != nil {
		f.t.Fatalf("status %s %v", raw, err)
	}
	return s
}

func TestStage3C01OrdinaryDaemonRestartBackupSemantics(t *testing.T) {
	f := cNative(t)
	path := filepath.Join(f.source, "COMLPT1.md")
	os.WriteFile(path, []byte("fixture bytes"), 0600)
	os.Mkdir(filepath.Join(f.source, "empty"), 0700)
	f.server.blockComplete = true
	stop := f.start()
	cAwait(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		return f.server.calls["catalog-uploads/complete"] > 0
	})
	before := f.status()
	cAwait(t, func() bool {
		before = f.status()
		return before.Observation.Engine != nil && before.Observation.Engine.Captured > 0
	})
	if before.Observation.Engine == nil || before.Observation.Engine.Mode != "indexed" {
		t.Fatal(before)
	}
	if before.Observation.Engine.Published != 0 || before.Observation.Engine.HTTP.DataBytes == 0 {
		t.Fatal("received bytes falsely published", before.Observation.Engine)
	}
	f.server.mu.Lock()
	keys := []string{}
	for key := range f.server.uploads {
		keys = append(keys, key)
	}
	f.server.mu.Unlock()
	qualifyC01DaemonCheckpoint(t, f)
	stop(true)
	f.server.mu.Lock()
	f.server.blockComplete = false
	f.server.mu.Unlock()
	stop = f.start()
	cAwait(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		for _, u := range f.server.uploads {
			if u.Result != nil {
				return true
			}
		}
		return false
	})
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
	})
	first, _ := os.ReadFile(filepath.Join(f.state, "indexed-session.json"))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(f.source, "new-file"), []byte("two"), 0600)
	cAwait(t, func() bool { f.server.mu.Lock(); defer f.server.mu.Unlock(); return len(f.server.uploads) == 2 })
	second, _ := os.ReadFile(filepath.Join(f.state, "indexed-session.json"))
	var a, b map[string]any
	json.Unmarshal(first, &a)
	json.Unmarshal(second, &b)
	if a["ownerId"] != b["ownerId"] {
		t.Fatal("daemon replaced long-lived owner")
	}
	for _, action := range []string{"pause", "resume", "pause"} {
		if raw, err := f.command(action); err != nil {
			t.Fatal(action, string(raw), err)
		}
	}
	f.server.mu.Lock()
	if len(keys) != 1 || f.server.uploads[keys[0]] == nil || f.server.uploads[keys[0]].Result == nil {
		t.Error("original identity lost")
	}
	found := false
	for _, node := range f.server.nodes {
		if node["name"] == "COMLPT1.md" {
			found = true
		}
	}
	if !found {
		t.Error("local delete removed remote backup")
	}
	for route := range f.server.calls {
		if strings.Contains(route, "delete") || strings.Contains(route, "move") {
			t.Error("destructive backup caller", route)
		}
	}
	f.server.mu.Unlock()
	preserveC01DaemonOutcome(t, f, first, second)
	stop(false)
}
func TestStage3C01ActivationFenceNoLegacyFallback(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "wrong-domain"} {
		t.Run(kind, func(t *testing.T) {
			f := cNative(t)
			switch kind {
			case "missing":
				f.cfg.Indexed = nil
			case "corrupt":
				f.cfg.Indexed.Profile.Schema = "broken"
			case "wrong-domain":
				f.cfg.Indexed.Profile.Remote.Domain = syncstate.IsolatedHTTPContract
			}
			SaveJSON(f.config, f.cfg)
			stop := f.start()
			cAwait(t, func() bool { s := f.status(); return s.Observation.Error != "" })
			stop(false)
			f.server.mu.Lock()
			defer f.server.mu.Unlock()
			if len(f.server.uploads) != 0 {
				t.Fatal("mutation with corrupt activation")
			}
		})
	}
}
func TestStage3C12NativeLifecycleAndWriterFence(t *testing.T) {
	f := cNative(t)
	stop := f.start()
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
	})
	if release, err := lifecycleLock(f.state); err == nil {
		release()
		t.Fatal("second owner acquired lifecycle")
	}
	for _, action := range []string{"pause", "inspect", "checkpoint", "backup", "diagnostics", "resume", "pause"} {
		raw, err := f.command(action)
		if err != nil {
			t.Fatal(action, string(raw), err)
		}
	}
	stop(false)
	for _, action := range []string{"inspect", "checkpoint", "backup"} {
		raw, err := f.command(action)
		if err != nil {
			t.Fatal("offline", action, string(raw), err)
		}
	}
	for _, version := range []int{7, 8} {
		path := filepath.Join(f.base, fmt.Sprintf("writer-%d", version))
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '{\"schema\":\"pluto.writer-compatibility.v1\",\"maximumStateSchema\":%d,\"activationFence\":true}'\n", version)
		os.WriteFile(path, []byte(script), 0700)
		err := requireIndexedWriter(context.Background(), path, f.state)
		if (err == nil) != (version == 8) {
			t.Fatal("writer fence", version, err)
		}
	}
}
func TestStage3C13ConcurrentStatusShutdownAndCheckinWire(t *testing.T) {
	f := cNative(t)
	os.WriteFile(filepath.Join(f.source, "file"), []byte("safe fixture"), 0600)
	stop := f.start()
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Published == 1
	})
	status := f.status()
	f.server.mu.Lock()
	f.server.wire = nil
	f.server.mu.Unlock()
	service := &Service{Config: f.cfg, HTTP: f.http.Client(), Version: "stage3-fixture"}
	service.heartbeat(context.Background(), heartbeatUpdate{config: f.cfg, observation: status.Observation})
	f.server.mu.Lock()
	if len(f.server.wire) != 1 {
		f.server.mu.Unlock()
		t.Fatal("no real K3 caller request")
	}
	wire := append([]byte(nil), f.server.wire[0]...)
	f.server.mu.Unlock()
	if bytes.Contains(wire, []byte("fixture-canary-credential")) || bytes.Contains(wire, []byte("ActiveData")) {
		t.Fatal("secret/local pressure in check-in")
	}
	if out := os.Getenv("STAGE3_C_EVIDENCE"); out != "" {
		if err := os.WriteFile(filepath.Join(out, "pluto-k3-checkin.json"), wire, 0600); err != nil {
			t.Fatal(err)
		}
		f.server.mu.Lock()
		for _, upload := range f.server.uploads {
			artifact := map[string]any{"caller": "cmd/pluto ordinary indexed daemon", "endpointKind": "disposable TLS fixture", "binding": f.server.binding, "catalogInput": upload.Input, "catalogStatus": f.server.status(upload)}
			if e := SaveJSON(filepath.Join(out, "pluto-catalog-caller.json"), artifact); e != nil {
				t.Error(e)
			}
			break
		}
		f.server.mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := LocalClient(f.socket)
			defer client.CloseIdleConnections()
			for n := 0; n < 10; n++ {
				response, err := client.Get("http://localhost/status")
				if err == nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
			}
		}()
	}
	stop(false)
	wg.Wait()
	raw, err := os.ReadFile(filepath.Join(f.state, "indexed-session.json"))
	if err != nil || !bytes.Contains(raw, []byte("STOPPED")) {
		t.Fatal("shutdown did not checkpoint/join", string(raw), err)
	}
	release, err := lifecycleLock(f.state)
	if err != nil {
		t.Fatal("owner leak", err)
	}
	release()
}

func TestStage3C12NativeAdoptQualification(t *testing.T) {
	for _, kind := range []string{"device", "receipt", "source", "valid"} {
		t.Run(kind, func(t *testing.T) {
			bad := kind != "valid"
			f := cNative(t)
			candidate := f.cfg.Indexed.Profile
			candidate.Remote.Token = f.cfg.AccessToken
			if kind == "device" {
				candidate.Remote.DeviceID = cUUID(999)
			}
			if kind == "receipt" {
				candidate.Remote.QualificationReceiptSHA256 = strings.Repeat("0", 64)
			}
			if kind == "source" {
				candidate.Sources[0].SelectedPath = filepath.Join(f.base, "foreign-source")
			}
			f.cfg.Indexed = nil
			f.cfg.Enabled = false
			if err := SaveJSON(f.config, f.cfg); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.state, "indexed-activation.json")); err != nil {
				t.Fatal(err)
			}
			profile := filepath.Join(f.base, "candidate.json")
			if err := SaveJSON(profile, candidate); err != nil {
				t.Fatal(err)
			}
			raw, err := f.command("migrate-plan", "--profile", profile)
			if kind == "source" {
				if err == nil {
					t.Fatal("source mismatch plan admitted", string(raw))
				}
				return
			}
			if err != nil {
				t.Fatal(string(raw), err)
			}
			var plan AdoptionPlan
			if err = json.Unmarshal(raw, &plan); err != nil {
				t.Fatal(err)
			}
			if plan.MaximumFileBytes != 256<<20 || plan.RetainedVersions != 10 || !plan.CopiesRetained {
				t.Fatal("backup policy changed", plan)
			}
			if _, err = f.command("adopt", "--profile", profile, "--plan-digest", strings.Repeat("0", 64)); err == nil {
				t.Fatal("stale digest accepted")
			}
			raw, err = f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest)
			if bad {
				if err == nil {
					t.Fatal("unqualified device activated without HTTPS handshake", string(raw))
				}
				cfg, e := LoadConfig(f.config)
				if e != nil || cfg.Indexed != nil {
					t.Fatal("failed adoption changed config", e)
				}
				return
			}
			if err != nil {
				t.Fatal(string(raw), err)
			}
			f.server.mu.Lock()
			calls := f.server.calls["capabilities"]
			snapshots := f.server.calls["snapshots/start"]
			f.server.mu.Unlock()
			if calls == 0 || snapshots == 0 {
				t.Fatal("adoption lacks qualification/fresh snapshot", calls, snapshots)
			}
			if raw, err = f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest); err != nil {
				t.Fatal("reviewed restart", string(raw), err)
			}
		})
	}
}

func TestStage3C12NativeReviewedPolicyScopesAndRestart(t *testing.T) {
	f := cNative(t)
	second := filepath.Join(f.base, "second")
	if err := os.MkdirAll(filepath.Join(second, ".hidden"), 0700); err != nil {
		t.Fatal(err)
	}
	f.cfg.Sources = append(f.cfg.Sources, second)
	f.cfg.Indexed.Profile.Sources = append(f.cfg.Indexed.Profile.Sources, IndexedSourceConfig{ID: "second", SelectedPath: second})
	for i := 0; i < 260; i++ {
		directory := f.source
		if i >= 130 {
			directory = filepath.Join(second, ".hidden")
		}
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("file-%03d", i)), []byte{byte(i)}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	stop := f.start()
	deadline := time.Now().Add(90 * time.Second)
	for {
		status := f.status()
		if status.Observation.Engine != nil && status.Observation.Engine.Published == 260 && status.Observation.Engine.Phase == "observing" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("260 publications", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if raw, err := f.command("pause"); err != nil {
		t.Fatal(string(raw), err)
	}
	stop(false)
	for _, revision := range []int64{2, 3} {
		cfg, err := LoadConfig(f.config)
		if err != nil {
			t.Fatal(err)
		}
		policy := cfg.Indexed.Policy
		policy.Revision = revision
		policy.Sources = []string{f.source}
		policy.Excludes = []string{strings.TrimLeft(filepath.ToSlash(filepath.Join(f.source, "file-000")), "/")}
		if revision == 3 {
			policy.Sources = []string{f.source, second}
			policy.Excludes = []string{}
		}
		path := filepath.Join(f.base, fmt.Sprintf("policy-%d.json", revision))
		if err = SaveJSON(path, policy); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(f.config)
		raw, err := f.command("policy-plan", "--profile", path)
		if err != nil {
			t.Fatal(string(raw), err)
		}
		var plan syncstate.PolicyPreview
		if err = json.Unmarshal(raw, &plan); err != nil {
			t.Fatal(err)
		}
		if plan.Entries <= 250 || !plan.CopiesRetained || revision == 2 && plan.NewlyExcluded < 131 || revision == 3 && plan.NewlyIncluded < 131 {
			t.Fatal("scope preview", plan)
		}
		after, _ := os.ReadFile(f.config)
		if !bytes.Equal(before, after) {
			t.Fatal("preview changed config")
		}
		if _, err = f.command("policy-apply", "--profile", path, "--plan-digest", strings.Repeat("0", 64)); err == nil {
			t.Fatal("stale digest accepted")
		}
		raw, err = f.command("policy-apply", "--profile", path, "--plan-digest", plan.Digest)
		if err != nil {
			t.Fatal(string(raw), err)
		}
		// Replay uses a fresh CLI process and the durable journal.
		raw, err = f.command("policy-apply", "--profile", path, "--plan-digest", plan.Digest)
		if err != nil {
			t.Fatal("restart reviewed apply", string(raw), err)
		}
		var progress policyApply
		if json.Unmarshal(raw, &progress) != nil || progress.Phase != "COMPLETE" || progress.PolicyDigest != policy.Digest() {
			t.Fatal(string(raw))
		}
		stop = f.start()
		if raw, err = f.command("resume"); err != nil {
			t.Fatal(string(raw), err)
		}
		// Resume schedules the daemon itself. Wait for that owner instead of
		// racing a second explicit run against the service timer.
		cAwait(t, func() bool { return f.status().Running })
		cAwait(t, func() bool {
			status := f.status()
			if status.Observation.Error != "" {
				t.Fatalf("scope revision %d: %+v", revision, status)
			}
			return status.Observation.Engine != nil && status.Observation.Engine.Phase == "observing"
		})
		if raw, err = f.command("pause"); err != nil {
			t.Fatal(string(raw), err)
		}
		stop(false)
		f.server.mu.Lock()
		uploads := len(f.server.uploads)
		f.server.mu.Unlock()
		if uploads != 260 {
			t.Fatal("scope rewrote backups", uploads)
		}
	}
	// A populated reviewed binding transition has to page every baseline.
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	candidate := cfg.Indexed.Profile
	next := map[string]any{}
	for key, value := range candidate.Remote.Binding {
		next[key] = value
	}
	next["server_epoch"] = cUUID(888)
	next["binding_version"] = cUUID(889)
	candidate.Remote.Binding = next
	profile := filepath.Join(f.base, "rebind-profile.json")
	if err = SaveJSON(profile, candidate); err != nil {
		t.Fatal(err)
	}
	raw, err := f.command("migrate-plan", "--profile", profile)
	if err != nil {
		t.Fatal(string(raw), err)
	}
	var plan AdoptionPlan
	if json.Unmarshal(raw, &plan) != nil || plan.Existing == nil || !plan.Existing.RequiresRebind || !plan.Compatible {
		t.Fatal("existing rebind plan", string(raw))
	}
	qualifyPreparedCheckpoint(t, f, candidate, plan)
	entered := make(chan struct{})
	f.server.mu.Lock()
	f.server.binding = next
	f.server.holdChanges = make(chan struct{})
	f.server.changesEntered = entered
	f.server.mu.Unlock()
	// This fixture channel is independent of server.mu, which ServeHTTP holds.
	held := f.server.holdChanges
	var releaseOnce sync.Once
	releaseHeld := func() { releaseOnce.Do(func() { close(held) }) }
	defer releaseHeld()
	child, err := f.processes.StartAdoption(profile, plan.Digest, releaseHeld)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		child.FailDeadline("adopt snapshot barrier")
		releaseHeld() // release only the test gate; no state/journal rewrite.
		actual := child.JoinActualDurable()
		t.Fatal("adopt snapshot barrier", actual)
	}
	// Preserve the original intentional PREPARED crash, not timeout cleanup.
	if err = child.CrashExactReviewedSite("adoption-prepared-changes-entry"); err != nil {
		t.Fatal(err) // deferred gate release + registered normal join still run.
	}
	child.JoinActualDurable()
	f.server.mu.Lock()
	f.server.holdChanges = nil
	f.server.mu.Unlock()
	var prepared adoptionProgress
	progressRaw, err := os.ReadFile(filepath.Join(f.state, "indexed-adoption.json"))
	if err != nil || json.Unmarshal(progressRaw, &prepared) != nil || prepared.Phase != "PREPARED" || prepared.PlanDigest != plan.Digest {
		t.Fatal("review lost on crash", string(progressRaw), err)
	}
	raw, err = f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest)
	if err != nil {
		t.Fatal("populated adoption", string(raw), err)
	}
	raw, err = f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest)
	if err != nil {
		t.Fatal("adoption restart", string(raw), err)
	}
	stop = f.start()
	if raw, err = f.command("resume"); err != nil {
		t.Fatal(string(raw), err)
	}
	cAwait(t, func() bool { return f.status().Running })
	cAwait(t, func() bool {
		status := f.status()
		if status.Observation.Error != "" {
			t.Fatal("rebound", status.Observation.Error)
		}
		return status.Observation.Engine != nil && status.Observation.Engine.Phase == "observing"
	})
	if raw, err = f.command("pause"); err != nil {
		t.Fatal(string(raw), err)
	}
	stop(false)
	f.server.mu.Lock()
	defer f.server.mu.Unlock()
	if len(f.server.uploads) != 260 {
		t.Fatal("rebind reuploaded historical copies", len(f.server.uploads))
	}
}

func TestStage3C12NativeIncompatibleRollbackRetainsJournal(t *testing.T) {
	requireFreshDisposableNativeFixture(t)
	executable := "/usr/local/bin/pluto"
	previous := executable + ".previous"
	journal := executable + ".update-pending"
	marker := "/var/lib/pluto/indexed-activation.json"
	for _, path := range []string{executable, previous, journal, marker} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refuse occupied native fixture path", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{executable, previous, journal, marker} {
		p := path
		t.Cleanup(func() { os.Remove(p) })
	}
	if err := os.WriteFile(executable, []byte("current-candidate"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, []byte("#!/bin/sh\necho '{\"schema\":\"pluto.writer-compatibility.v1\",\"maximumStateSchema\":7,\"activationFence\":true}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, []byte("pluto-replacement-v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte(`{"phase":"COMPLETE"}`), 0600); err != nil {
		t.Fatal(err)
	}
	backup := qualifyNativeRollbackBackup(t)
	before, _ := os.ReadFile(previous)
	calls := []string{}
	err := recoverInterruptedUpdate(executable, func(action string) error { calls = append(calls, action); return nil })
	if err == nil || !strings.Contains(err.Error(), "binary cannot read activated indexed state") {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(executable)
	saved, _ := os.ReadFile(previous)
	intent, _ := os.ReadFile(journal)
	if string(current) != "current-candidate" || !bytes.Equal(before, saved) || len(intent) == 0 || len(calls) != 1 || calls[0] != "stop" {
		t.Fatal("rollback destroyed recovery evidence", calls)
	}
	backup.verifyOriginals(t, true)
}

func TestStage3C01NativeFileCapAndRetention(t *testing.T) {
	f := cNative(t)
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = byte((314159 + i*31) % 251)
	}
	path := filepath.Join(f.source, "cap-256MiB")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	hasher := sha256.New()
	for i := 0; i < 256; i++ {
		if _, err = file.Write(block); err != nil {
			t.Fatal(err)
		}
		hasher.Write(block)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	tooBig, err := os.Create(filepath.Join(f.source, "cap-plus-one"))
	if err != nil {
		t.Fatal(err)
	}
	if err = tooBig.Truncate((256 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	tooBig.Close()
	stop := f.start()
	cAwait(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		for _, u := range f.server.uploads {
			if u.Result != nil {
				return true
			}
		}
		return false
	})
	stop(false)
	f.server.mu.Lock()
	defer f.server.mu.Unlock()
	if len(f.server.uploads) != 1 {
		t.Fatal("oversize got partial upload", len(f.server.uploads))
	}
	for _, u := range f.server.uploads {
		if len(u.Bytes) != 256<<20 || cHash(u.Bytes) != hex.EncodeToString(hasher.Sum(nil)) {
			t.Fatal("cap bytes/hash")
		}
		intent := u.Input["intent"].(map[string]any)
		if intent["deviceKind"] != "pluto" {
			t.Fatal("retention capability escalated")
		}
	}
	store, err := syncstate.OpenReadOnly(context.Background(), filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root, err := store.Root(context.Background(), "root")
	if err != nil || root.MaxActiveVersions != 10 || root.AllowsDelete {
		t.Fatal("backup root policy", root, err)
	}
}
