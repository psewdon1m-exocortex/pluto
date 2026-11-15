package syncstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The local receiver uses the pre-existing catalog fixture's full publication
// receipts and feed. It is not a substitute for real Saturn/PG/SFTP acceptance.
type dispatchHTTPFixture struct {
	mu                                                       sync.Mutex
	base                                                     *guardedHTTPFixture
	session                                                  *IsolatedHTTPSession
	groups                                                   map[string]*smallBatchPlan
	calls                                                    map[string]int
	sent                                                     map[string]int
	losePrepare, loseData, malformed, knownMissing, conflict bool
	partial                                                  int
	hold                                                     chan struct{}
	entered                                                  chan struct{}
	completed                                                chan struct{}
	jobProtocol                                              bool
}

func (f *dispatchHTTPFixture) outcome(p *smallBatchPlan) map[string]any {
	m := bindingHTTP(p.binding)
	m["schema"] = "saturn.small-file-batch-result.v1"
	m["batch_id"] = p.id
	items := make([]any, len(p.entries))
	for n, e := range p.entries {
		item := map[string]any{"operation_id": "pluto-sync-" + e.original.OperationID, "source_generation": remoteDecimal(e.original.LocalGeneration), "source_identity": e.sourceIdentity, "state": "MISSING"}
		if u := f.base.uploads[e.original.OperationID]; u != nil {
			item["state"] = "PENDING"
			if u.result != nil {
				item["state"] = "PUBLISHED"
			}
			item["status"] = f.base.status(u)
		}
		if f.conflict && n == 0 {
			delete(item, "status")
			item["state"] = "CONFLICT"
			item["code"] = "precondition_failed"
		}
		if f.knownMissing && n == 0 {
			delete(item, "status")
			item["state"] = "MISSING"
		}
		items[n] = item
	}
	if f.malformed {
		items[0], items[len(items)-1] = items[len(items)-1], items[0]
	}
	m["items"] = items
	return m
}
func (f *dispatchHTTPFixture) publish(op Operation, data []byte) error {
	if int64(len(data)) != op.SizeBytes || hashBytes(data) != op.SHA256 {
		return ErrIdentityConflict
	}
	if f.base.uploads[op.OperationID] != nil {
		return errors.New("fixture refuses duplicate packet payload")
	}
	input, err := originalCatalogInput(op)
	if err != nil {
		return err
	}
	u := &httpFixtureUpload{op: op, input: input, serverID: remoteVersion(6000 + len(f.base.uploads)), bytes: data}
	f.base.uploads[op.OperationID] = u
	chain, _ := op.ParentTopology()
	parent := chain[0].NodeID
	old := f.base.namespace(parent, op.Name)
	if op.ExpectedAbsent && old != nil || !op.ExpectedAbsent && (old == nil || old.NodeID != op.ExpectedNodeID || old.Version != op.ExpectedVersion) {
		return ErrInvalidReceipt
	}
	node := remoteVersion(1000 + len(f.base.nodes))
	if old != nil {
		node = old.NodeID
	}
	descriptor := fileRemote(node, parent, op.Name, string(data))
	descriptor.Version = remoteVersion(3000 + int(f.base.seq))
	content := remoteVersion(4000 + int(f.base.seq))
	descriptor.ContentVersionID = &content
	f.base.emit(descriptor, u.serverID)
	receipt := map[string]any{"schema": "saturn.upload-publication.v1", "uploadId": u.serverID, "operationId": u.serverID, "intentHash": input.hash, "rootId": f.base.binding.RootID, "resourceId": node, "versionId": content, "parentId": parent, "name": op.Name, "sizeBytes": remoteDecimal(op.SizeBytes), "sha256": op.SHA256, "etag": fmt.Sprintf("\"sha256-%s\"", op.SHA256), "publishedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
	u.result = map[string]any{"schema": "saturn.catalog-upload-result.v2", "status": "PUBLISHED", "uploadId": u.serverID, "operationId": u.serverID, "rootId": f.base.binding.RootID, "intentHash": input.hash, "publicationReceipt": receipt, "publishedDescription": wireDescriptor(descriptor), "firstSeq": remoteDecimal(f.base.seq), "lastSeq": remoteDecimal(f.base.seq)}
	return nil
}
func (f *dispatchHTTPFixture) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	jobRequest := strings.HasPrefix(req.URL.Path, "/sync/v1/roots/"+f.base.binding.RootID+"/small-jobs/")
	if jobRequest && !f.jobProtocol {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		f.base.json(w, map[string]any{"code": "batch_missing"})
		return
	}
	prefix := "/sync/v1/roots/" + f.base.binding.RootID + "/small-batches/"
	if jobRequest {
		prefix = "/sync/v1/roots/" + f.base.binding.RootID + "/small-jobs/"
	}
	if !strings.HasPrefix(req.URL.Path, prefix) {
		f.base.ServeHTTP(w, req)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.base.mu.Lock()
	defer f.base.mu.Unlock()
	command := strings.TrimPrefix(req.URL.Path, prefix)
	dataCommand := command == "data" || command == "execute"
	if command == "data" && f.completed != nil {
		defer close(f.completed)
	}
	call := command
	if jobRequest {
		call = "job-" + call
	}
	f.calls[call]++
	if req.Header.Get("Authorization") != "Bearer fixture-token" {
		w.WriteHeader(401)
		return
	}
	if jobRequest && strings.HasSuffix(command, "capabilities") {
		schema := "saturn.small-execution-job-capabilities.v1"
		limits := map[string]any{"items": 16, "file_bytes": "262144", "data_bytes": "4194304", "manifest_bytes": "1048576"}
		if command != "capabilities" {
			schema = "saturn.small-execution-job-" + strings.TrimSuffix(command, "-capabilities") + "-capabilities.v1"
			limits["jobs"] = 2
		}
		f.base.json(w, map[string]any{"schema": schema, "transport": "saturn.small-execution-job.v1", "binding": bindingHTTP(f.base.binding), "device_id": f.session.identity.DeviceID, "backend_identity": f.session.identity.BackendIdentity, "qualification_receipt_sha256": f.session.identity.ContractReceiptSHA256, "limits": limits})
		return
	}
	if command == "capabilities" {
		f.base.json(w, map[string]any{"schema": "saturn.small-file-batch-capabilities.v1", "transport": smallBatchSchema, "binding": bindingHTTP(f.base.binding), "device_id": f.session.identity.DeviceID, "backend_identity": f.session.identity.BackendIdentity, "qualification_receipt_sha256": f.session.identity.ContractReceiptSHA256, "limits": map[string]any{"items": 500, "file_bytes": "262144", "data_bytes": "33554432", "manifest_bytes": "4194304"}})
		return
	}
	var multipartReader *multipart.Reader
	var raw []byte
	var err error
	if dataCommand {
		kind, params, e := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if e != nil || kind != "multipart/related" {
			f.base.t.Error("wrong MIME")
			w.WriteHeader(400)
			return
		}
		multipartReader = multipart.NewReader(req.Body, params["boundary"])
		part, e := multipartReader.NextPart()
		if e != nil {
			f.base.t.Error(e)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(part, smallBatchMaximumMetadataBytes+1))
		part.Close()
	} else {
		raw, err = io.ReadAll(io.LimitReader(req.Body, smallBatchMaximumMetadataBytes+1))
	}
	if err != nil {
		f.base.t.Error(err)
		return
	}
	value, ok := jsonRawValue(raw).(map[string]any)
	if !ok {
		f.base.t.Error("bad JSON")
		return
	}
	var id string
	if command == "prepare" || jobRequest {
		id = value["manifest"].(map[string]any)["batch_id"].(string)
	} else {
		id = value["batch_id"].(string)
	}
	saved, err := f.session.r.store.batches.state.read(req.Context(), id)
	if req.Context().Err() != nil {
		return
	}
	if err != nil || saved.Phase != "ATTEMPTED" {
		f.base.t.Error("effect before durable Attempted", err)
		w.WriteHeader(500)
		return
	}
	p := saved.Plan
	if p.executionJob != jobRequest {
		f.base.t.Error("durable transport changed")
		w.WriteHeader(409)
		return
	}
	if jobRequest {
		expected, _ := p.prepareBytes()
		if !bytes.Equal(raw, expected) {
			f.base.t.Error("job wire bytes changed")
			w.WriteHeader(409)
			return
		}
	}
	if command == "prepare" || command == "execute" {
		expected, _ := p.prepareBytes()
		if !reflect.DeepEqual(jsonRawValue(expected), value) {
			f.base.t.Error("original inputs differ")
			return
		}
		f.groups[id] = p
		if f.losePrepare {
			f.losePrepare = false
			f.base.lose(w)
			return
		}
	} else if f.groups[id] == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		f.base.json(w, map[string]any{"code": "batch_missing"})
		return
	}
	if dataCommand {
		expected := p.manifest
		if jobRequest {
			expected, _ = p.prepareBytes()
		}
		if !reflect.DeepEqual(jsonRawValue(expected), value) {
			f.base.t.Error("manifest differs")
			return
		}
		for n, entry := range p.entries {
			part, e := multipartReader.NextPart()
			if e != nil {
				f.base.t.Error(e)
				return
			}
			data, e := io.ReadAll(io.LimitReader(part, smallBatchMaximumFileBytes+1))
			part.Close()
			if e != nil {
				return
			} // An interrupted part is never published.
			if part.Header.Get("Content-ID") != "<pluto-sync-"+entry.original.OperationID+">" {
				f.base.t.Error("part identity", e)
				return
			}
			f.sent[entry.original.OperationID]++
			if n == 0 && f.hold != nil {
				close(f.entered)
				select {
				case <-f.hold:
				case <-req.Context().Done():
					return
				}
				if req.Context().Err() != nil {
					return
				}
			}
			if f.partial == 0 || n < f.partial {
				if jobRequest && f.base.uploads[entry.original.OperationID] != nil {
					if !bytes.Equal(f.base.uploads[entry.original.OperationID].bytes, data) {
						f.base.t.Error("replay bytes changed")
					}
					continue
				}
				if e = f.publish(entry.original, data); e != nil {
					f.base.t.Error(e)
					return
				}
			}
		}
		if _, e := multipartReader.NextPart(); e != io.EOF {
			f.base.t.Error("extra part", e)
			return
		}
		f.partial = 0
		if f.loseData {
			f.loseData = false
			f.base.lose(w)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if command != "status" {
		w.WriteHeader(202)
	}
	f.base.json(w, f.outcome(p))
}

func dispatchFixture(t *testing.T, count int) (*smallBatchDispatcher, *dispatchHTTPFixture, *smallBatchPlan, SourceWitness) {
	return dispatchFixtureWithHandler(t, count, nil)
}

func dispatchFixtureWithHandler(t *testing.T, count int, decorate func(*dispatchHTTPFixture) http.Handler) (*smallBatchDispatcher, *dispatchHTTPFixture, *smallBatchPlan, SourceWitness) {
	t.Helper()
	r, _, w, old, base, _ := actualHTTPFixture(t, count)
	old.Close()
	f := &dispatchHTTPFixture{base: base, groups: map[string]*smallBatchPlan{}, calls: map[string]int{}, sent: map[string]int{}}
	var handler http.Handler = f
	if decorate != nil {
		handler = decorate(f)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	s, err := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: server.URL, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(base.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"})
	if err != nil {
		t.Fatal(err)
	}
	f.session = s
	t.Cleanup(s.Close)
	s.SetRecoveryReader(artifactTestReader)
	if err = s.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	report, err := r.RunCapturedScan(testContext, CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: pendingSmallBatchSession{s}, Capture: func(ctx context.Context, w SourceWitness, e SourceEntry) (*VerifiedSnapshot, error) {
		return CaptureGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	}})
	if report.Failed != int64(count) || report.Uploaded != 0 {
		t.Fatal(report, err)
	}
	rows, err := r.store.db.Query("SELECT operation_id FROM operations WHERE kind='PUT' ORDER BY json_extract(intent_json,'$.Name')")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	var ops []Operation
	for _, id := range ids {
		op, e := r.store.Operation(testContext, id)
		if e != nil {
			t.Fatal(e)
		}
		ops = append(ops, op)
	}
	if len(ops) != count {
		t.Fatal(len(ops))
	}
	if err = os.Chmod(filepath.Dir(r.store.filename), 0700); err != nil {
		t.Fatal(err)
	}
	state, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	native, err := state.enableArtifacts(testContext)
	if err != nil {
		t.Fatal(err)
	}
	d, err := newSmallBatchDispatcher(native, s, artifactTestReader)
	if err != nil {
		t.Fatal(err)
	}
	return d, f, stateBatchPlan(t, "dispatch-original", ops), w
}
func assertDispatchedOriginals(t *testing.T, d *smallBatchDispatcher, p *smallBatchPlan, dirty bool) {
	t.Helper()
	for _, entry := range p.entries {
		op, err := d.session.r.store.Operation(testContext, entry.original.OperationID)
		if err != nil || op.Stage != "CLIENT_ACKED" || op.SealedFingerprint != entry.original.SealedFingerprint || op.IntentFingerprint != entry.original.IntentFingerprint || op.LocalGeneration != entry.original.LocalGeneration {
			t.Fatal("original changed or not acknowledged", err, op.Stage)
		}
		state, err := d.session.r.store.Entry(testContext, op.RootID, op.EntryID)
		if err != nil || state.Base == nil || state.Base.OperationID != op.OperationID || (state.Dirty != nil) != dirty {
			t.Fatal("baseline/dirty incorrect", state, err)
		}
	}
	charge, err := d.session.r.store.artifacts.Charge(testContext)
	if err != nil || charge != 0 {
		t.Fatal("retained plaintext after ACK", charge, err)
	}
}

func TestSmallBatchDispatchNativeHTTPOriginalReceiptsAndCleanup(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 4)
	before := CaptureMetricSnapshot()
	if err := d.dispatch(testContext, p); err != nil {
		t.Fatal(err)
	}
	assertDispatchedOriginals(t, d, p, false)
	if f.calls["prepare"] != 1 || f.calls["data"] != 1 || f.calls["status"] != 0 || d.session.Metrics().DataBytes != 12 {
		t.Fatal(f.calls, d.session.Metrics())
	}
	if CaptureMetricSnapshot().SourceHashBytes != before.SourceHashBytes {
		t.Fatal("recaptured source")
	}
	if err := d.dispatch(testContext, p); err != nil {
		t.Fatal("repeat GONE", err)
	}
	if f.calls["data"] != 1 {
		t.Fatal("resent published data")
	}
}
func TestSmallBatchDispatchLostPrepareAndDataRestartSubset(t *testing.T) {
	for _, kind := range []string{"prepare", "data-all", "data-partial"} {
		t.Run(kind, func(t *testing.T) {
			d, f, p, witness := dispatchFixture(t, 4)
			f.losePrepare = kind == "prepare"
			f.loseData = kind != "prepare"
			if kind == "data-partial" {
				f.partial = 2
			}
			d, backup := qualifyStage3BatchRestartBackup(t, d, f, p, witness, kind)
			if err := d.dispatch(testContext, p); err == nil {
				t.Fatal("loss accepted")
			}
			saved, err := d.native.state.read(testContext, p.id)
			if err != nil || saved.Phase != "ATTEMPTED" {
				t.Fatal(saved.Phase, err)
			}
			originalFile := saved.FileIdentity
			backup.recordInterrupted(t, d, f, p, kind, saved)
			directory := filepath.Dir(d.session.r.store.filename)
			d.session.Close()
			if err = d.session.r.store.Close(); err != nil {
				t.Fatal(err)
			}
			r, native := reopenNativeSmallBatch(t, directory)
			f.base.r = r
			old := d.session
			s, err := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: old.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(old.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			s.SetRecoveryReader(artifactTestReader)
			f.session = s
			d, err = newSmallBatchDispatcher(native, s, artifactTestReader)
			if err != nil {
				t.Fatal(err)
			}
			saved, err = native.state.read(testContext, p.id)
			if err != nil || saved.FileIdentity != originalFile {
				t.Fatal("native identity changed", err)
			}
			if err = d.dispatch(testContext, saved.Plan); err != nil {
				t.Fatal(err)
			}
			// Reopening the state invalidates the former source owner's witness.
			// Historical ACK is valid; clearing current dirty work is not.
			assertDispatchedOriginals(t, d, p, true)
			if f.calls["status"] != 1 {
				t.Fatal(f.calls)
			}
			expected := int64(12)
			if kind == "data-all" {
				expected = 0
			}
			if kind == "data-partial" {
				expected = 6
			}
			if s.Metrics().DataBytes != expected {
				t.Fatal("unexpected resent bytes", s.Metrics(), expected)
			}
			for n, entry := range p.entries {
				want := 1
				if kind == "data-partial" && n >= 2 {
					want = 2
				}
				if f.sent[entry.original.OperationID] != want {
					t.Fatal("published member resent", n, f.sent)
				}
			}
			backup.recordRecovered(t, d, f, p, kind)
		})
	}
}
func TestSmallBatchDispatchCommittedAttemptBeforeFirstRequest(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 2)
	if _, err := d.native.build(testContext, p); err != nil {
		t.Fatal(err)
	}
	if err := d.native.withAttempt(testContext, p.id, func(smallBatchRecord, io.ReadSeeker) error { return context.Canceled }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := d.dispatch(testContext, p); err != nil {
		t.Fatal(err)
	}
	assertDispatchedOriginals(t, d, p, false)
	if f.calls["status"] != 1 || f.calls["prepare"] != 1 || f.calls["data"] != 1 {
		t.Fatal(f.calls)
	}
}
func TestSmallBatchDispatchAckCrashAndNewSourceGeneration(t *testing.T) {
	for _, point := range []string{"small_batch.before_outcomes", "capture.before_ack", "small_batch.after_outcomes"} {
		t.Run(point, func(t *testing.T) {
			d, f, p, _ := dispatchFixture(t, 3)
			r := d.session.r
			hits := 0
			r.testPoint = func(value string) error {
				if value == point {
					hits++
					if point != "capture.before_ack" || hits == 2 {
						return context.Canceled
					}
				}
				return nil
			}
			if err := d.dispatch(testContext, p); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			r.testPoint = nil
			if point == "small_batch.before_outcomes" {
				for _, entry := range p.entries {
					op := entry.original
					_, err := r.store.db.Exec("UPDATE local_entries SET generation=generation+1,descriptor_json=json_set(descriptor_json,'$.Generation',generation+1) WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			before := d.session.Metrics().DataBytes
			if err := d.dispatch(testContext, p); err != nil {
				t.Fatal(err)
			}
			assertDispatchedOriginals(t, d, p, point == "small_batch.before_outcomes")
			if d.session.Metrics().DataBytes != before || f.calls["status"] != 1 {
				t.Fatal("crash recovery resent", f.calls)
			}
		})
	}
}
func TestSmallBatchDispatchRejectsWholeMalformedOrMissingKnownOutcome(t *testing.T) {
	for _, kind := range []string{"order", "known-missing"} {
		t.Run(kind, func(t *testing.T) {
			d, f, p, _ := dispatchFixture(t, 3)
			d.session.r.testPoint = func(value string) error {
				if value == "capture.before_ack" {
					return context.Canceled
				}
				return nil
			}
			if err := d.dispatch(testContext, p); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			d.session.r.testPoint = nil
			f.malformed = kind == "order"
			f.knownMissing = kind == "known-missing"
			ops := []Operation{}
			for _, entry := range p.entries {
				ops = append(ops, entry.original)
			}
			before := batchOriginalState(t, d.session.r, ops)
			if err := d.dispatch(testContext, p); err == nil {
				t.Fatal("bad outcome accepted")
			}
			if batchOriginalState(t, d.session.r, ops) != before {
				t.Fatal("invalid response partially mutated originals")
			}
			f.malformed = false
			f.knownMissing = false
			if err := d.dispatch(testContext, p); err != nil {
				t.Fatal(err)
			}
			assertDispatchedOriginals(t, d, p, false)
		})
	}
}
func TestSmallBatchDispatchConflictRetainsOriginalAndSingletonFallback(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 2)
	f.conflict = true
	if err := d.dispatch(testContext, p); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal(err)
	}
	first, _ := d.session.r.store.Operation(testContext, p.entries[0].original.OperationID)
	second, _ := d.session.r.store.Operation(testContext, p.entries[1].original.OperationID)
	if first.Stage != "SUBMITTED" || first.HTTPBinding != nil || second.Stage != "CLIENT_ACKED" || second.IntentFingerprint != p.entries[1].original.IntentFingerprint || f.calls["data"] != 0 || f.base.requests["catalog-uploads/append"] != 1 {
		t.Fatal(first.Stage, second.Stage, f.calls, f.base.requests)
	}
	if err := d.session.r.store.artifacts.WithRecoveryReader(testContext, first, artifactTestReader, func(reader io.Reader) error {
		raw, e := io.ReadAll(reader)
		if string(raw) != "one" {
			t.Error("fallback lost bytes")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSmallBatchDispatchAcceptedOriginalContinuesBeforeMissingSubset(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 3)
	op := p.entries[0].original
	input, err := originalCatalogInput(op)
	if err != nil {
		t.Fatal(err)
	}
	// Model an original accepted before this group with one byte already stored.
	f.base.mu.Lock()
	f.base.uploads[op.OperationID] = &httpFixtureUpload{op: op, input: input, serverID: remoteVersion(6000), bytes: []byte("o")}
	f.base.mu.Unlock()
	if err = d.dispatch(testContext, p); err != nil {
		t.Fatal(err)
	}
	assertDispatchedOriginals(t, d, p, false)
	if f.sent[op.OperationID] != 0 || d.session.Metrics().DataBytes != 8 || f.calls["data"] != 1 || f.calls["prepare"] != 2 || f.base.requests["catalog-uploads/append"] != 1 {
		t.Fatal("accepted original resent in subset", f.sent, f.calls, d.session.Metrics())
	}
	accepted, err := d.session.r.store.Operation(testContext, op.OperationID)
	if err != nil || accepted.HTTPBinding == nil || accepted.HTTPBinding.ServerUploadID != remoteVersion(6000) {
		t.Fatal("accepted server UUID changed", err)
	}
}

func TestSmallBatchDispatchCancellationJoinsNativeHandleAndAdmission(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 2)
	f.hold = make(chan struct{})
	f.entered = make(chan struct{})
	f.completed = make(chan struct{})
	var releaseServer sync.Once
	unblock := func() { releaseServer.Do(func() { close(f.hold) }) }
	defer unblock()
	var active atomic.Int32
	d.acquire = func(context.Context) (func(), error) { active.Add(1); return func() { active.Add(-1) }, nil }
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.dispatch(ctx, p) }()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no data request")
	}
	if err := d.session.r.store.Close(); !errors.Is(err, ErrArtifactInUse) {
		t.Fatal("store closed active packet", err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not join")
	}
	if active.Load() != 0 || len(d.lanes) != 0 {
		t.Fatal("admission leak")
	}
	// Cancellation joins the local sender. A remote server can still commit;
	// allow this receiver to finish before checking the retained local fallback.
	unblock()
	select {
	case <-f.completed:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not finish")
	}
	saved, err := d.native.state.read(testContext, p.id)
	if err != nil || saved.Phase != "ATTEMPTED" {
		t.Fatal(saved.Phase, err)
	}
	if err = d.native.cleanup(testContext, p.id); err != nil {
		t.Fatal("native reader leaked", err)
	}
}
