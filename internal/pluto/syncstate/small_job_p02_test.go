package syncstate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func p02JobEnvelope(plan []byte) []byte {
	return mustJSON(map[string]any{"schema": "pluto.small-execution-job/v1", "plan_base64": base64.StdEncoding.EncodeToString(plan)})
}

func TestSmallJobP02EncodingProofRechecksCurrentRowsAndOwnsCopies(t *testing.T) {
	for _, damage := range []string{"returned-plan", "sealed-original", "manifest", "phase", "member"} {
		t.Run(damage, func(t *testing.T) {
			r, ops := smallBatchStateFixture(t, 2)
			state, err := r.enableSmallBatches(testContext)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := stateBatchPlan(t, "p02-proof", ops).asExecutionJob()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = state.reserve(testContext, plan); err != nil {
				t.Fatal(err)
			}
			first, err := state.read(testContext, plan.id)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.proofs.entries) != 1 {
				t.Fatal("encoding proof not retained")
			}
			wire, _ := first.Plan.prepareBytes()
			switch damage {
			case "returned-plan":
				first.Plan.entries[0].original.Captured.SourceFileIdentity = "changed"
				first.Plan.entries[0].input.body["intent"].(map[string]any)["name"] = "changed"
				first.Plan.manifest[0] = '!'
				first.Plan.jobWire[0] = '!'
			case "sealed-original":
				_, err = r.store.db.Exec("UPDATE operations SET sealed_fingerprint=? WHERE operation_id=?", hashBytes([]byte("wrong")), ops[0].OperationID)
			case "manifest":
				raw := append([]byte("!"), plan.persistedBytes()...)
				_, err = r.store.db.Exec("UPDATE small_batch_groups SET manifest=?,manifest_sha256=? WHERE batch_id=?", raw, hashBytes(raw), plan.id)
			case "phase":
				_, err = r.store.db.Exec("UPDATE small_batch_groups SET phase='READY' WHERE batch_id=?", plan.id)
			case "member":
				_, err = r.store.db.Exec("UPDATE small_batch_members SET source_identity=? WHERE batch_id=? AND ordinal=1", hashBytes([]byte("changed")), plan.id)
			}
			if err != nil {
				t.Fatal(err)
			}
			next, err := state.read(testContext, plan.id)
			if damage != "returned-plan" {
				if err == nil {
					t.Fatal("warm encoding proof accepted changed authority rows")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := next.Plan.prepareBytes()
			if !bytes.Equal(got, wire) || next.Plan.entries[0].original.Captured.SourceFileIdentity == "changed" || next.Plan.entries[0].input.body["intent"].(map[string]any)["name"] == "changed" {
				t.Fatal("caller changed cached proof")
			}
		})
	}
}

func TestSmallJobP02EncodingProofCacheHasFixedBounds(t *testing.T) {
	ops, _ := smallBatchWireFixture(t, 2)
	var cache smallJobProofCache
	for i := 0; i < 20; i++ {
		plan, err := newSmallBatchPlan(fmt.Sprintf("p02-bounded-%d", i), "p02", ops)
		if err != nil {
			t.Fatal(err)
		}
		plan, err = plan.asExecutionJob()
		if err != nil {
			t.Fatal(err)
		}
		cache.put(fmt.Sprint(i), plan)
		if len(cache.entries) > 2 || cache.bytes > 4<<20 {
			t.Fatal("unbounded proof retention")
		}
	}
	if _, hit, err := cache.get("p02-bounded-0", "0", ops); hit || err != nil {
		t.Fatal("old proof not evicted", err)
	}
}

func TestSmallJobP02ReservationRejectsDetachedPlanFields(t *testing.T) {
	for _, jobProtocol := range []bool{false, true} {
		for _, field := range []string{"id", "rules", "bytes"} {
			t.Run(fmt.Sprintf("job=%t/%s", jobProtocol, field), func(t *testing.T) {
				r, ops := smallBatchStateFixture(t, 2)
				state, err := r.enableSmallBatches(testContext)
				if err != nil {
					t.Fatal(err)
				}
				plan := stateBatchPlan(t, "p02-detached", ops)
				if jobProtocol {
					plan, err = plan.asExecutionJob()
					if err != nil {
						t.Fatal(err)
					}
				}
				before := batchOriginalState(t, r, ops)
				switch field {
				case "id":
					plan.id = "different-id"
				case "rules":
					plan.rules = "different-rules"
				case "bytes":
					plan.dataBytes++
				}
				if _, err = state.reserve(testContext, plan); err == nil {
					t.Fatal("detached plan field accepted")
				}
				var groups int
				if err = r.store.db.QueryRow("SELECT count(*) FROM small_batch_groups").Scan(&groups); err != nil || groups != 0 {
					t.Fatal("failed admission persisted a group", groups, err)
				}
				if batchOriginalState(t, r, ops) != before {
					t.Fatal("failed admission changed originals")
				}
			})
		}
	}
}

func TestSmallJobP02PersistedPlanAndMultipartKeepExactWireBytes(t *testing.T) {
	ops, _ := smallBatchWireFixture(t, 2)
	p, err := newSmallBatchPlan("p02-wire", "p02", ops)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := p.prepareBytes()
	if err != nil {
		t.Fatal(err)
	}
	// The server pins bytes, not just JSON values. Reopening must retain them.
	wire = append([]byte(" \n"), wire...)
	restored, err := restoreSmallBatchPlan(p02JobEnvelope(wire), ops)
	if err != nil {
		t.Fatal("durable job must reopen", err)
	}
	got, err := restored.prepareBytes()
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("plan bytes changed", err)
	}
	stream, err := newSmallBatchStream(testContext, restored, bytes.NewReader([]byte("abcabc")), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, params, _ := mime.ParseMediaType(stream.contentType)
	reader := multipart.NewReader(stream, params["boundary"])
	part, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(part)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("job multipart must carry complete exact plan", err)
	}
}

func TestSmallJobP02CapabilityRequiresBoundedAdvertisedCredits(t *testing.T) {
	ops, _ := smallBatchWireFixture(t, 2)
	p, err := newSmallBatchPlan("p02-cap", "p02", ops)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := p.prepareBytes()
	job, err := restoreSmallBatchPlan(p02JobEnvelope(wire), ops)
	if err != nil {
		t.Fatal(err)
	}
	id := ops[0].Captured.Transport
	for _, kind := range []string{"single-request", "pipeline", "plain"} {
		t.Run(kind, func(t *testing.T) {
			limits := map[string]any{"items": 16, "file_bytes": "262144", "data_bytes": "4194304", "manifest_bytes": "1048576"}
			schema := "saturn.small-execution-job-capabilities.v1"
			if kind != "plain" {
				schema = "saturn.small-execution-job-" + kind + "-capabilities.v1"
				limits["jobs"] = 2
			}
			body := map[string]any{"schema": schema, "transport": "saturn.small-execution-job.v1", "binding": bindingHTTP(p.binding), "device_id": id.DeviceID, "backend_identity": id.BackendIdentity, "qualification_receipt_sha256": id.ContractReceiptSHA256, "limits": limits}
			read := func() (*smallBatchCapability, error) {
				return readSmallBatchCapability(mustJSON(body), p.binding, id.DeviceID, id.BackendIdentity, id.ContractReceiptSHA256)
			}
			cap, err := read()
			if err != nil || !cap.admits(job) || cap.admits(p) {
				t.Fatal("qualified job capability", err)
			}
			for _, bad := range []any{0, 3, "2", nil} {
				limits["jobs"] = bad
				if _, err = read(); err == nil {
					t.Fatal("invalid credits accepted", bad)
				}
			}
			delete(limits, "jobs")
			if kind != "plain" {
				limits["jobs"] = 2
			}
			limits["items"] = 17
			if _, err = read(); err == nil {
				t.Fatal("job item ceiling accepted")
			}
		})
	}
}

func TestSmallJobP02RejectsPersistedPlanDriftAndUnknownWrapper(t *testing.T) {
	ops, _ := smallBatchWireFixture(t, 2)
	p, err := newSmallBatchPlan("p02-negative", "p02", ops)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := p.prepareBytes()
	var body map[string]any
	if err = json.Unmarshal(wire, &body); err != nil {
		t.Fatal(err)
	}
	body["inputs"].([]any)[1].(map[string]any)["intent"].(map[string]any)["name"] = "changed"
	if _, err = restoreSmallBatchPlan(p02JobEnvelope(mustJSON(body)), ops); err == nil {
		t.Fatal("changed original accepted")
	}
	if _, err = restoreSmallBatchPlan(mustJSON(map[string]any{"schema": "unknown", "plan_base64": base64.StdEncoding.EncodeToString(wire)}), ops); err == nil {
		t.Fatal("unknown persisted protocol accepted")
	}
}

func TestSmallJobP02SingleRequestAndUnknownOutcomeResumeSameOriginals(t *testing.T) {
	for _, partial := range []int{0, 5} {
		t.Run(string(rune('0'+partial)), func(t *testing.T) {
			d, f, p, _ := dispatchFixtureWithHandler(t, 16, func(f *dispatchHTTPFixture) http.Handler { f.jobProtocol = true; return f })
			job, err := p.asExecutionJob()
			if err != nil {
				t.Fatal(err)
			}
			f.loseData = true
			f.partial = partial
			if err = d.dispatch(testContext, job); err == nil {
				t.Fatal("lost response reported success")
			}
			saved, err := d.native.state.read(testContext, p.id)
			if err != nil || saved.Phase != "ATTEMPTED" || !saved.Plan.executionJob {
				t.Fatal("immutable job not retained", err)
			}
			for _, entry := range saved.Plan.entries {
				if _, err = d.session.r.store.Operation(testContext, entry.original.OperationID); err != nil {
					t.Fatal(err)
				}
			}
			evidence := job.entries[0].original.Captured.Evidence
			source, err := d.session.r.sources.SourceEntry(testContext, evidence.SetID, evidence.Destination)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(source.PhysicalPath, []byte("next generation after sealing"), 0600); err != nil {
				t.Fatal(err)
			}
			before := CaptureMetricSnapshot()
			originalFile := saved.FileIdentity
			directory := filepath.Dir(d.session.r.store.filename)
			old := d.session
			old.Close()
			if err = old.r.store.Close(); err != nil {
				t.Fatal(err)
			}
			r, native := reopenNativeSmallBatch(t, directory)
			f.base.r = r
			s, err := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: old.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(old.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			s.SetRecoveryReader(artifactTestReader)
			f.session = s
			next, err := newSmallBatchDispatcher(native, s, artifactTestReader)
			if err != nil {
				t.Fatal(err)
			}
			saved, err = native.state.read(testContext, job.id)
			if err != nil || saved.FileIdentity != originalFile {
				t.Fatal("aggregate identity changed", err)
			}
			if err = next.dispatch(testContext, saved.Plan); err != nil {
				t.Fatal("resume", err)
			}
			assertDispatchedOriginals(t, next, job, true)
			if CaptureMetricSnapshot().SourceHashBytes != before.SourceHashBytes {
				t.Fatal("changed source was recaptured")
			}
			if f.calls["job-execute"] != 1 || f.calls["job-status"] != 1 || f.calls["job-prepare"] != 0 || f.calls["prepare"] != 0 {
				t.Fatal(f.calls)
			}
			if partial == 0 && f.calls["job-data"] != 0 || partial != 0 && f.calls["job-data"] != 1 {
				t.Fatal(f.calls)
			}
		})
	}
}

func TestSmallJobP02DurableAttemptBeforeRequestWithoutRecapture(t *testing.T) {
	d, f, p, _ := dispatchFixtureWithHandler(t, 2, func(f *dispatchHTTPFixture) http.Handler { f.jobProtocol = true; return f })
	job, err := p.asExecutionJob()
	if err != nil {
		t.Fatal(err)
	}
	record, err := d.build(testContext, job)
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != "READY" {
		t.Fatal(record.Phase)
	}
	before := CaptureMetricSnapshot()
	if err = d.dispatch(testContext, record.Plan); err != nil {
		t.Fatal(err)
	}
	if CaptureMetricSnapshot().SourceHashBytes != before.SourceHashBytes {
		t.Fatal("recaptured source")
	}
	assertDispatchedOriginals(t, d, job, false)
	if f.calls["job-execute"] != 1 {
		t.Fatal(f.calls)
	}
}

func TestSmallJobP02RetainedJobCannotChangeTransportOrBytes(t *testing.T) {
	d, _, p, _ := dispatchFixture(t, 2)
	job, err := p.asExecutionJob()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.build(testContext, job); err != nil {
		t.Fatal(err)
	}
	if _, err = d.build(testContext, p); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("same ID rebound to old transport", err)
	}
	changed := *job
	changed.jobWire = append([]byte(" "), job.jobWire...)
	if _, err = d.build(testContext, &changed); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("same ID rebound to new bytes", err)
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if err = d.dispatch(ctx, job); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSmallJobP02ServerWireOracleExport(t *testing.T) {
	output := os.Getenv("P02_WIRE_OUTPUT")
	if output == "" {
		t.Skip("independent server oracle fixture export not requested")
	}
	ops, _ := smallBatchWireFixture(t, 2)
	p, err := newSmallBatchPlan("p02-cross-language", "p02", ops)
	if err != nil {
		t.Fatal(err)
	}
	job, err := p.asExecutionJob()
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := job.prepareBytes()
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "go-job-plan.json"), wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "go-job-binding.json"), mustJSON(bindingHTTP(p.binding)), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSmallJobP02EngineCapabilityLossKeepsOriginalRecovery(t *testing.T) {
	r, w, f, _ := engineFixture(t, []int{1, 7, 1024}, true)
	f.jobProtocol = true
	f.loseData = true
	report, err := runEngineFixture(t, testContext, r, w, f, "bulk")
	if err == nil || report.Failed != 3 || f.calls["job-execute"] != 1 {
		t.Fatal(report, err, f.calls)
	}
	pending, err := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if err != nil || len(pending) != 3 {
		t.Fatal(pending, err)
	}
	f.jobProtocol = false
	next, err := r.sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "p02-capability-downgrade")
	if err != nil {
		t.Fatal(err)
	}
	report, err = runEngineFixture(t, testContext, r, next, f, "bulk")
	if err != nil || !report.Complete {
		t.Fatal(report, err)
	}
	for _, original := range pending {
		op, e := r.store.Operation(testContext, original.OperationID)
		if e != nil || op.Stage != "CLIENT_ACKED" || op.SealedFingerprint != original.SealedFingerprint || op.LocalGeneration != original.LocalGeneration {
			t.Fatal("downgrade changed original", e)
		}
	}
	if f.calls["job-execute"] != 1 || f.calls["job-data"] != 0 {
		t.Fatal(f.calls)
	}
	var live int
	if err = r.store.db.QueryRow("SELECT count(*) FROM small_batch_groups WHERE phase<>'GONE'").Scan(&live); err != nil || live != 0 {
		t.Fatal(live, err)
	}
}
