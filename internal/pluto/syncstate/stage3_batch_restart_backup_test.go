//go:build linux

package syncstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"pluto/internal/syncproto"
)

type stage3BatchUpload struct {
	ServerID  string
	Operation Operation
	Input     map[string]any
	InputHash string
	Bytes     []byte
	Result    map[string]any
}
type stage3BatchBackend struct {
	Schema                                                                                   string
	Binding                                                                                  RemoteBinding
	Identity                                                                                 CapturedHTTPIdentity
	Seq                                                                                      int64
	Nodes                                                                                    map[string]syncproto.Descriptor
	Events                                                                                   []syncproto.FeedItem
	Uploads                                                                                  map[string]stage3BatchUpload
	Folders                                                                                  map[string]map[string]any
	Requests                                                                                 map[string]int
	Groups                                                                                   map[string]json.RawMessage
	Calls, Sent                                                                              map[string]int
	LosePrepare, LoseData, Malformed, KnownMissing, Conflict                                 bool
	Partial                                                                                  int
	JobProtocol                                                                              bool
	BaseLostComplete, BaseLostAppend, BaseLostPrepare, RejectRedirect, RejectFeedAfterFolder bool
}
type stage3BatchRestartBackup struct {
	*fixtureBackup
	source      string
	plan        *smallBatchPlan
	metrics     CaptureMetrics
	backendSHA  string
	backendRoot string
}

func stage3BatchBackendBytes(t *testing.T, f *dispatchHTTPFixture) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.base.mu.Lock()
	defer f.base.mu.Unlock()
	if f.hold != nil || f.entered != nil || f.completed != nil {
		t.Fatal("unjoined channel fixture not in this restart scope")
	}
	b := stage3BatchBackend{Schema: "pluto.batch-owned-http-checkpoint.v1", Binding: f.base.binding, Identity: f.session.identity, Seq: f.base.seq, Nodes: f.base.nodes, Events: f.base.events, Uploads: map[string]stage3BatchUpload{}, Folders: f.base.folders, Requests: f.base.requests, Groups: map[string]json.RawMessage{}, Calls: f.calls, Sent: f.sent, LosePrepare: f.losePrepare, LoseData: f.loseData, Malformed: f.malformed, KnownMissing: f.knownMissing, Conflict: f.conflict, Partial: f.partial, JobProtocol: f.jobProtocol, BaseLostComplete: f.base.lostComplete, BaseLostAppend: f.base.lostAppend, BaseLostPrepare: f.base.lostPrepare, RejectRedirect: f.base.rejectRedirect, RejectFeedAfterFolder: f.base.rejectFeedAfterFolder}
	for id, u := range f.base.uploads {
		b.Uploads[id] = stage3BatchUpload{ServerID: u.serverID, Operation: u.op, Input: u.input.body, InputHash: u.input.hash, Bytes: u.bytes, Result: u.result}
	}
	for id, p := range f.groups {
		b.Groups[id] = json.RawMessage(p.manifestBytes())
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}
func stage3BatchRestoreHTTP(t *testing.T, raw []byte, r *RemoteImport, original *IsolatedHTTPSession, directory string) map[string]any {
	t.Helper()
	var b stage3BatchBackend
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if b.Schema != "pluto.batch-owned-http-checkpoint.v1" || len(b.Uploads) != 0 || len(b.Groups) != 0 || len(b.Sent) != 0 || len(b.Nodes) != 3 || len(b.Folders) != 2 || b.Seq != 2 || b.Identity != original.identity {
		t.Fatal("complete original pre-publication owned receiver checkpoint")
	}
	base := &guardedHTTPFixture{t: t, r: r, binding: b.Binding, seq: b.Seq, nodes: b.Nodes, events: b.Events, uploads: map[string]*httpFixtureUpload{}, folders: b.Folders, requests: b.Requests, lostComplete: b.BaseLostComplete, lostAppend: b.BaseLostAppend, lostPrepare: b.BaseLostPrepare, rejectRedirect: b.RejectRedirect, rejectFeedAfterFolder: b.RejectFeedAfterFolder}
	// This restored receiver uses the original already-qualified immutable
	// identity only for its read-only capabilities response. It makes no request
	// through the closed original product session and publishes no data.
	receiver := &dispatchHTTPFixture{base: base, session: original, groups: map[string]*smallBatchPlan{}, calls: b.Calls, sent: b.Sent, losePrepare: b.LosePrepare, loseData: b.LoseData, malformed: b.Malformed, knownMissing: b.KnownMissing, conflict: b.Conflict, partial: b.Partial, jobProtocol: b.JobProtocol}
	if hashBytes(stage3BatchBackendBytes(t, receiver)) != hashBytes(raw) {
		t.Fatal("actual restored receiver fields differ before probe")
	}
	server := httptest.NewServer(receiver)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(command string, body []byte) []byte {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/sync/v1/roots/"+b.Binding.RootID+"/"+command, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer fixture-token")
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != 200 || len(payload) >= 1<<20 {
			t.Fatal("actual restored HTTP metadata", response.StatusCode, readErr, closeErr)
		}
		return payload
	}
	caps := request("small-batches/capabilities", nil)
	var capability map[string]any
	if err := json.Unmarshal(caps, &capability); err != nil || capability["schema"] != "saturn.small-file-batch-capabilities.v1" || !reflect.DeepEqual(capability["binding"], jsonRawValue(mustBatchJSON(t, bindingHTTP(b.Binding)))) || capability["device_id"] != b.Identity.DeviceID || capability["backend_identity"] != b.Identity.BackendIdentity || capability["qualification_receipt_sha256"] != b.Identity.ContractReceiptSHA256 {
		t.Fatal("restored actual receiver capabilities", err)
	}
	candidate, err := r.Candidate(testContext, "root")
	if err != nil || candidate.SnapshotID == "" {
		t.Fatal("actual restored candidate", err)
	}
	body := mustBatchJSON(t, map[string]any{"binding": bindingHTTP(b.Binding), "cursor": "entries-" + candidate.SnapshotID})
	entries := request("entries", body)
	values := make([]syncproto.Descriptor, 0, len(b.Nodes))
	for _, d := range b.Nodes {
		values = append(values, d)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].NodeID < values[j].NodeID })
	expected := wirePage(SnapshotPreparation{Snapshot: syncproto.Snapshot{Binding: b.Binding, SnapshotID: candidate.SnapshotID, CutSeq: remoteDecimal(b.Seq)}}, values, "entries-done", false)
	if !reflect.DeepEqual(jsonRawValue(entries), jsonRawValue(expected)) {
		t.Fatal("actual restored receiver full original directory catalog")
	}
	stage3PendingProofWrite(t, filepath.Join(directory, "restored-http-readback.json"), map[string]any{"schema": "pluto.batch-owned-restored-http-readback.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "checkpointSHA256": hashBytes(raw), "originalIdentity": b.Identity, "actualLoopbackHTTP": true, "originalNodes": b.Nodes, "capabilities": json.RawMessage(caps), "capabilitiesSHA256": hashBytes(caps), "entries": json.RawMessage(entries), "entriesSHA256": hashBytes(entries), "publishedDuringProbe": 0, "historicalReader": false})
	return map[string]any{"actualLoopbackHTTP": true, "catalogEntries": len(b.Nodes), "publishedDuringProbe": 0, "capabilitiesSHA256": hashBytes(caps), "entriesSHA256": hashBytes(entries)}
}
func mustBatchJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func qualifyStage3BatchRestartBackup(t *testing.T, d *smallBatchDispatcher, f *dispatchHTTPFixture, p *smallBatchPlan, w SourceWitness, kind string) (*smallBatchDispatcher, *stage3BatchRestartBackup) {
	t.Helper()
	if len(p.entries) != 4 || kind != "prepare" && kind != "data-all" && kind != "data-partial" {
		t.Fatal("original four-member lost-reply fixture")
	}
	original := d.session
	store := original.r.store
	state := filepath.Dir(store.filename)
	binding, err := original.r.sources.Binding(testContext, w.SetID, "source")
	if err != nil {
		t.Fatal(err)
	}
	original.Close()
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	backendRaw := stage3BatchBackendBytes(t, f)
	var savedBackend stage3BatchBackend
	if err = json.Unmarshal(backendRaw, &savedBackend); err != nil {
		t.Fatal(err)
	}
	if savedBackend.LosePrepare != (kind == "prepare") || savedBackend.LoseData != (kind != "prepare") || savedBackend.Partial != map[string]int{"prepare": 0, "data-all": 0, "data-partial": 2}[kind] {
		t.Fatal("exact original planned fault flags")
	}
	input := os.Getenv("PLUTO_FAULT_INPUT_DIR")
	if !filepath.IsAbs(input) || filepath.Clean(input) != input {
		t.Fatal("explicit admitted input root")
	}
	backendRoot, err := os.MkdirTemp(input, "owned-batch-backend-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(backendRoot); err != nil {
			t.Error(err)
		}
	})
	stage3PendingProofWrite(t, filepath.Join(backendRoot, "backend.json"), json.RawMessage(backendRaw))
	// Keep the canonical original bytes: both genuine archives carry the same
	// serialized complete owned receiver state alongside state and real sources.
	backendRaw, err = os.ReadFile(filepath.Join(backendRoot, "backend.json"))
	if err != nil {
		t.Fatal(err)
	}
	logical, rows := stage3DatabaseLogicalDigest(t, filepath.Join(state, "sync-state.sqlite"))
	physical := stage3PendingPhysical(t, state, binding.PhysicalPath)
	preliminary := qualifyClosedFixtureBackup(t, state, []string{binding.PhysicalPath, backendRoot}, func(copy *Store) {
		filename := copy.filename
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		got, count := stage3DatabaseLogicalDigest(t, filename)
		if got != logical || count != rows {
			t.Fatal("complete preliminary SQL differs")
		}
	})
	restoreSource := filepath.Join(preliminary.directory, "restored/state/sync-state.sqlite")
	restoreSHA, err := fileDigest(restoreSource)
	if err != nil {
		t.Fatal(err)
	}
	stage3RestoreSQLiteAPI(t, state, restoreSource, restoreSHA)
	product, err := Open(testContext, state)
	if err != nil {
		t.Fatal(err)
	}
	var reads []map[string]any
	var readBytes int64
	var httpProof map[string]any
	func() {
		defer func() {
			if err := product.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err = product.EnableSources(testContext, DefaultSourceLimits()); err != nil {
			t.Fatal(err)
		}
		artifacts, e := product.EnableArtifacts(testContext, DefaultArtifactLimits())
		if e != nil {
			t.Fatal(e)
		}
		report, e := artifacts.Reconcile(testContext, artifactTestReader)
		if e != nil || !report.Admitted || report.Files != 4 || report.RecoveryOperations != 4 || report.ReservedBytes != 12 {
			t.Fatal("actual restored full pending admission", report, e)
		}
		remote, e := product.EnableRemoteImport(testContext)
		if e != nil {
			t.Fatal(e)
		}
		batches, e := remote.enableSmallBatches(testContext)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = batches.enableArtifacts(testContext); e != nil {
			t.Fatal(e)
		}
		for _, entry := range p.entries {
			current, e := product.Operation(testContext, entry.original.OperationID)
			if e != nil || !reflect.DeepEqual(current, entry.original) || current.Captured == nil {
				t.Fatal("all immutable pending originals restored", e)
			}
			var artifactName string
			if e = product.db.QueryRow("SELECT filename FROM local_artifacts WHERE operation_id=?", current.OperationID).Scan(&artifactName); e != nil {
				t.Fatal(e)
			}
			e = artifacts.WithRecoveryReader(testContext, current, artifactTestReader, func(reader io.Reader) error {
				data, err := io.ReadAll(io.LimitReader(reader, current.SizeBytes+1))
				if err != nil {
					return err
				}
				relative, err := filepath.Rel(filepath.FromSlash(binding.Destination), filepath.FromSlash(current.Captured.Evidence.Destination))
				if err != nil || relative == "." || !filepath.IsLocal(relative) {
					return ErrIdentityConflict
				}
				source, err := os.ReadFile(filepath.Join(binding.PhysicalPath, relative))
				if err != nil {
					return err
				}
				if !bytes.Equal(data, source) || int64(len(data)) != current.SizeBytes || hashBytes(data) != current.SHA256 {
					return errors.New("actual original retained bytes differ")
				}
				readBytes += int64(len(data))
				reads = append(reads, map[string]any{"operationID": current.OperationID, "snapshotID": current.SnapshotID, "artifactName": artifactName, "sourceName": filepath.ToSlash(relative), "bytes": len(data), "sha256": hashBytes(data)})
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		copiedBackend, e := os.ReadFile(filepath.Join(preliminary.directory, "restored/source-002/backend.json"))
		if e != nil || !bytes.Equal(copiedBackend, backendRaw) {
			t.Fatal("actual restored complete owned backend context", e)
		}
		httpProof = stage3BatchRestoreHTTP(t, copiedBackend, remote, original, preliminary.directory)
	}()
	if t.Failed() || len(reads) != 4 || readBytes != 12 {
		t.Fatal("full pending/source/owned-backend restore precondition")
	}
	stage3RestoreSQLiteAPI(t, state, restoreSource, restoreSHA)
	finalLogical, finalRows := stage3DatabaseLogicalDigest(t, filepath.Join(state, "sync-state.sqlite"))
	if finalLogical != logical || finalRows != rows || !reflect.DeepEqual(physical, stage3PendingPhysical(t, state, binding.PhysicalPath)) || !bytes.Equal(stage3BatchBackendBytes(t, f), backendRaw) {
		t.Fatal("whole logical checkpoint or original physical/backend graph changed before first fault")
	}
	final := qualifyClosedFixtureBackup(t, state, []string{binding.PhysicalPath, backendRoot}, func(copy *Store) {
		filename := copy.filename
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		got, count := stage3DatabaseLogicalDigest(t, filename)
		if got != logical || count != rows {
			t.Fatal("final full checkpoint SQL differs")
		}
	})
	var originals []Operation
	for _, entry := range p.entries {
		originals = append(originals, entry.original)
	}
	stage3PendingProofWrite(t, filepath.Join(final.directory, "batch-restore.json"), map[string]any{"schema": "pluto.batch-restart-same-inode-restore.v1", "case": t.Name(), "kind": kind, "at": time.Now().UTC().Format(time.RFC3339Nano), "preliminaryDirectory": filepath.Base(preliminary.directory), "preliminaryArchiveSHA256": preliminary.archiveSHA, "finalArchiveSHA256": final.archiveSHA, "backendSHA256": hashBytes(backendRaw), "restoreCallsBeforeFault": 2, "originalLogicalSHA256": logical, "finalLogicalSHA256": finalLogical, "logicalRows": rows, "originalPhysical": physical, "restoredOnOriginalPhysicalInodes": true, "manualAuthorityOrRowEdits": false, "pendingOperations": 4, "pendingBytes": 12, "actualRestoredReads": reads, "actualRestoredBytes": readBytes, "restoredHTTP": httpProof, "originals": originals, "historicalReader": false, "realSaturnPGSFTPAcceptance": false})
	remote, native := reopenNativeSmallBatch(t, state)
	f.base.r = remote
	session, e := NewIsolatedHTTPSession(testContext, remote, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: original.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(original.binding), DeviceID: original.identity.DeviceID, BackendIdentity: original.identity.BackendIdentity, QualificationReceiptSHA256: original.identity.ContractReceiptSHA256, Token: "fixture-token"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(session.Close)
	session.SetRecoveryReader(artifactTestReader)
	f.session = session
	dispatcher, e := newSmallBatchDispatcher(native, session, artifactTestReader)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("BATCH_RESTART_GENUINE_GRAPH_RESTORED kind=%s operations=4 bytes=12 backendSHA256=%s", kind, hashBytes(backendRaw))
	return dispatcher, &stage3BatchRestartBackup{fixtureBackup: final, source: binding.PhysicalPath, plan: p, metrics: CaptureMetricSnapshot(), backendSHA: hashBytes(backendRaw), backendRoot: backendRoot}
}
func stage3BatchExportSQL(t *testing.T, store *Store, directory, phase string) map[string]any {
	t.Helper()
	backup, err := store.Backup(testContext)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(filepath.Dir(store.filename), "sync-state-backups", backup.Filename)
	raw, err := os.ReadFile(source)
	if err != nil || len(raw) == 0 || len(raw) > 64<<20 || hashBytes(raw) != backup.SHA256 {
		t.Fatal("actual complete product SQLite backup", err)
	}
	target := filepath.Join(directory, phase+".sqlite")
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	syncFixtureDirectory(t, directory)
	return map[string]any{"sqliteSHA256": hashBytes(raw), "sqliteBytes": len(raw), "actualSQLiteBackup": backup}
}
func (b *stage3BatchRestartBackup) recordInterrupted(t *testing.T, d *smallBatchDispatcher, f *dispatchHTTPFixture, p *smallBatchPlan, kind string, saved smallBatchRecord) {
	t.Helper()
	if saved.Phase != "ATTEMPTED" || saved.FileIdentity == "" {
		t.Fatal("actual original interrupted durable attempt")
	}
	for _, entry := range p.entries {
		op, err := d.session.r.store.Operation(testContext, entry.original.OperationID)
		if err != nil || !reflect.DeepEqual(op, entry.original) {
			t.Fatal("interrupted original changed", err)
		}
	}
	// Use the product guard: saved batch identity includes statx birth time.
	opened, err := d.native.open(saved, saved.Name, false)
	if err != nil {
		t.Fatal("actual guarded interrupted aggregate open", err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(opened, 13))
	inputClose := opened.Close()
	if readErr != nil || inputClose != nil || len(raw) != 12 || hashBytes(raw) != saved.SHA256 {
		t.Fatal("actual interrupted aggregate bytes", readErr, inputClose)
	}
	target := filepath.Join(b.directory, "interrupted.aggregate")
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := out.Write(raw)
	syncErr, closeErr := out.Sync(), out.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	backendRaw := stage3BatchBackendBytes(t, f)
	var backend stage3BatchBackend
	if err = json.Unmarshal(backendRaw, &backend); err != nil {
		t.Fatal(err)
	}
	expectedPublished := map[string]int{"prepare": 0, "data-all": 4, "data-partial": 2}[kind]
	if len(backend.Uploads) != expectedPublished || len(backend.Groups) != 1 || backend.LosePrepare || backend.LoseData {
		t.Fatal("actual planned socket reply loss was not consumed", len(backend.Uploads), kind)
	}
	stage3PendingProofWrite(t, filepath.Join(b.directory, "interrupted-backend.json"), json.RawMessage(backendRaw))
	sql := stage3BatchExportSQL(t, d.session.r.store, b.directory, "interrupted")
	sql["schema"] = "pluto.batch-restart-interrupted.v1"
	sql["case"] = t.Name()
	sql["kind"] = kind
	sql["at"] = time.Now().UTC().Format(time.RFC3339Nano)
	sql["actualReplyLoss"] = true
	sql["durablePhase"] = saved.Phase
	sql["aggregateFileIdentity"] = saved.FileIdentity
	sql["aggregateSHA256"] = saved.SHA256
	sql["aggregateBytes"] = len(raw)
	sql["backendSHA256"] = hashBytes(backendRaw)
	sql["publishedBeforeReopen"] = expectedPublished
	sql["historicalReader"] = false
	stage3PendingProofWrite(t, filepath.Join(b.directory, "interrupted.json"), sql)
	t.Logf("BATCH_RESTART_ACTUAL_SOCKET_LOSS kind=%s published=%d phase=ATTEMPTED", kind, expectedPublished)
}
func (b *stage3BatchRestartBackup) recordRecovered(t *testing.T, d *smallBatchDispatcher, f *dispatchHTTPFixture, p *smallBatchPlan, kind string) {
	t.Helper()
	backendRaw := stage3BatchBackendBytes(t, f)
	var backend stage3BatchBackend
	if err := json.Unmarshal(backendRaw, &backend); err != nil {
		t.Fatal(err)
	}
	if len(backend.Uploads) != 4 || backend.Calls["status"] != 1 {
		t.Fatal("actual original receiver recovery incomplete")
	}
	var originals []Operation
	for _, entry := range p.entries {
		op, err := d.session.r.store.Operation(testContext, entry.original.OperationID)
		expected := entry.original
		expected.Stage = "CLIENT_ACKED"
		upload, ok := backend.Uploads[entry.original.OperationID]
		if !ok {
			t.Fatal("actual receiver receipt missing original")
		}
		accepted, bindingErr := makeHTTPUploadBinding(entry.original, upload.ServerID, upload.InputHash)
		if bindingErr != nil {
			t.Fatal("actual receiver receipt does not bind immutable original", bindingErr)
		}
		expected.HTTPBinding = &accepted
		if err != nil || !reflect.DeepEqual(op, expected) {
			t.Fatal("recovered immutable original differs", err)
		}
		originals = append(originals, op)
	}
	metrics := CaptureMetricSnapshot().Since(b.metrics)
	if metrics.SourceReads != 0 || metrics.SourceHashBytes != 0 {
		t.Fatal("recovery recaptured original source", metrics)
	}
	for _, entry := range p.entries {
		u, ok := backend.Uploads[entry.original.OperationID]
		if !ok || u.Result == nil || !reflect.DeepEqual(u.Operation, entry.original) || int64(len(u.Bytes)) != entry.original.SizeBytes || hashBytes(u.Bytes) != entry.original.SHA256 {
			t.Fatal("actual published original payload differs")
		}
	}
	for _, directory := range []string{d.session.r.store.artifacts.Directory(), d.native.path} {
		items, err := os.ReadDir(directory)
		if err != nil || len(items) != 0 {
			t.Fatal("ACK cleanup left retained aggregate/plaintext", err)
		}
	}
	beforeRaw, err := os.ReadFile(filepath.Join(b.directory, "batch-restore.json"))
	if err != nil {
		t.Fatal(err)
	}
	var before struct{ OriginalPhysical []stage3PhysicalEntry }
	if err = json.Unmarshal(beforeRaw, &before); err != nil {
		t.Fatal(err)
	}
	after := stage3PendingPhysical(t, filepath.Dir(d.session.r.store.filename), b.source)
	var originalSource, currentSource []stage3PhysicalEntry
	for _, e := range before.OriginalPhysical {
		if e.Root == b.source {
			originalSource = append(originalSource, e)
		}
	}
	for _, e := range after {
		if e.Root == b.source {
			currentSource = append(currentSource, e)
		}
	}
	if !reflect.DeepEqual(originalSource, currentSource) {
		t.Fatal("recovery changed actual original source inode graph")
	}
	stage3PendingProofWrite(t, filepath.Join(b.directory, "recovered-backend.json"), json.RawMessage(backendRaw))
	sql := stage3BatchExportSQL(t, d.session.r.store, b.directory, "recovered")
	sql["schema"] = "pluto.batch-restart-recovered.v1"
	sql["case"] = t.Name()
	sql["kind"] = kind
	sql["at"] = time.Now().UTC().Format(time.RFC3339Nano)
	sql["originals"] = originals
	sql["backendSHA256"] = hashBytes(backendRaw)
	sql["metricsSinceBeforeFault"] = metrics
	sql["recoveryDataBytes"] = d.session.Metrics().DataBytes
	sql["originalSourceUnchanged"] = true
	sql["originalSource"] = currentSource
	sql["retainedDirectoriesEmpty"] = true
	sql["physicalAfter"] = after
	sql["historicalReader"] = false
	sql["realSaturnPGSFTPAcceptance"] = false
	stage3PendingProofWrite(t, filepath.Join(b.directory, "recovered.json"), sql)
	t.Logf("BATCH_RESTART_ORIGINALS_RECOVERED kind=%s originals=4 dataBytes=%d sourceHashBytes=0", kind, d.session.Metrics().DataBytes)
}
