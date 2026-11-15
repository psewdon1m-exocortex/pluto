package syncstate

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func smallBatchWireFixture(t *testing.T, count int) ([]Operation, *guardedHTTPFixture) {
	t.Helper()
	r, _, w, s, f, _ := actualHTTPFixture(t, count)
	if _, err := runActualHTTPFixture(t, r, w, s); err != nil {
		t.Fatal(err)
	}
	var originals []Operation
	for _, u := range f.uploads {
		op, err := r.store.Operation(testContext, u.op.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		originals = append(originals, op)
	}
	sort.Slice(originals, func(i, j int) bool { return originals[i].Name < originals[j].Name })
	if len(originals) != count {
		t.Fatal(len(originals))
	}
	return originals, f
}
func cloneSmallBatchOperation(t *testing.T, op Operation) Operation {
	t.Helper()
	var out Operation
	if err := json.Unmarshal(mustJSON(op), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func resealSmallBatchOperation(op *Operation) {
	op.IntentFingerprint = fingerprint(op.Intent)
	op.SealedFingerprint = fingerprint(struct{ IntentFingerprint, SHA256 string }{op.IntentFingerprint, op.SHA256})
}
func smallBatchWireResult(p *smallBatchPlan, f *guardedHTTPFixture) map[string]any {
	m := bindingHTTP(p.binding)
	m["schema"] = "saturn.small-file-batch-result.v1"
	m["batch_id"] = p.id
	items := make([]any, 0, len(p.entries))
	for _, e := range p.entries {
		items = append(items, map[string]any{"operation_id": "pluto-sync-" + e.original.OperationID, "source_generation": remoteDecimal(e.original.LocalGeneration), "source_identity": e.sourceIdentity, "state": "PUBLISHED", "status": f.status(f.uploads[e.original.OperationID])})
	}
	m["items"] = items
	return m
}

func TestSmallBatchWireRoundTripImmutableAndOriginalPublishedReceipts(t *testing.T) {
	originals, f := smallBatchWireFixture(t, 3)
	p, err := newSmallBatchPlan("batch-test-1", "rules-1", originals)
	if err != nil {
		t.Fatal(err)
	}
	if p.dataBytes != 9 || len(p.entries) != 3 {
		t.Fatal(p.dataBytes)
	}
	raw := p.manifestBytes()
	restored, err := restoreSmallBatchPlan(raw, originals)
	if err != nil || !bytes.Equal(restored.manifestBytes(), raw) {
		t.Fatal(err)
	}
	outcome, err := p.readOutcome(mustJSON(smallBatchWireResult(p, f)))
	if err != nil || len(outcome) != 3 {
		t.Fatal(outcome, err)
	}
	for n, item := range outcome {
		if item.status == nil || item.status.publication == nil || item.status.binding == nil || item.operationID != originals[n].OperationID || !reflect.DeepEqual(*item.status.binding, *originals[n].HTTPBinding) {
			t.Fatal(item)
		}
	}
	originals[0].Captured.Transport.BackendIdentity = "rebound"
	originals[0].Captured.Parents[0].Remote.Name = "rebound"
	raw[0] = '!'
	if _, err = p.readOutcome(mustJSON(smallBatchWireResult(p, f))); err != nil {
		t.Fatal("caller mutated frozen original", err)
	}
	if _, err = p.prepareBytes(); err != nil {
		t.Fatal(err)
	}
	if _, err = p.statusBytes(); err != nil {
		t.Fatal(err)
	}
}

func TestSmallBatchWireRejectsOriginalScopeBoundsAndManifestDrift(t *testing.T) {
	originals, _ := smallBatchWireFixture(t, 2)
	for _, name := range []string{"zero-generation", "file-ceiling", "captured-generation", "intent-hash", "sealed-hash", "duplicate-operation", "duplicate-destination", "server-binding", "backend", "accepted-id", "zero-hash"} {
		t.Run(name, func(t *testing.T) {
			ops := []Operation{cloneSmallBatchOperation(t, originals[0]), cloneSmallBatchOperation(t, originals[1])}
			switch name {
			case "zero-generation":
				ops[0].LocalGeneration = 0
			case "file-ceiling":
				ops[0].SizeBytes = smallBatchMaximumFileBytes + 1
			case "captured-generation":
				ops[0].Captured.LocalGeneration++
			case "intent-hash":
				ops[0].IntentFingerprint = strings.Repeat("0", 64)
			case "sealed-hash":
				ops[0].SealedFingerprint = strings.Repeat("0", 64)
			case "duplicate-operation":
				ops[1] = ops[0]
			case "duplicate-destination":
				ops[1].Name = ops[0].Name
				ops[1].HTTPBinding = nil
				resealSmallBatchOperation(&ops[1])
			case "server-binding":
				ops[1].Captured.Transport.InputBinding.ServerEpoch = remoteVersion(9999)
				ops[1].HTTPBinding = nil
				resealSmallBatchOperation(&ops[1])
			case "backend":
				ops[1].Captured.Transport.BackendIdentity = "other"
				ops[1].HTTPBinding = nil
				resealSmallBatchOperation(&ops[1])
			case "accepted-id":
				ops[0].HTTPBinding.ServerUploadID = remoteVersion(9999)
			case "zero-hash":
				ops[0].SizeBytes = 0
				ops[0].Captured.Evidence.SizeBytes = 0
				ops[0].HTTPBinding = nil
				resealSmallBatchOperation(&ops[0])
			}
			if _, err := newSmallBatchPlan("batch-1", "rules", ops); err == nil {
				t.Fatal("invalid original admitted")
			}
		})
	}
	for _, id := range []string{"", "has space", "/path", strings.Repeat("a", 129)} {
		if _, err := newSmallBatchPlan(id, "rules", originals); err == nil {
			t.Fatal(id)
		}
	}
	if _, err := newSmallBatchPlan("batch-1", "rules", nil); err == nil {
		t.Fatal("empty")
	}
	if _, err := newSmallBatchPlan("batch-1", "rules", make([]Operation, 501)); err == nil {
		t.Fatal("count")
	}
	p, err := newSmallBatchPlan("batch-1", "rules", originals)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err = json.Unmarshal(p.manifestBytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["items"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	if _, err = restoreSmallBatchPlan(mustJSON(manifest), originals); err == nil {
		t.Fatal("manifest changed")
	}
	if _, err = restoreSmallBatchPlan([]byte(`{"batch_id":"one","batch_id":"two"}`), originals); err == nil {
		t.Fatal("duplicate JSON")
	}
}

func TestSmallBatchWireRejectsOutcomeRebindingAndMissingAcceptedUpload(t *testing.T) {
	originals, f := smallBatchWireFixture(t, 2)
	p, err := newSmallBatchPlan("batch-1", "rules", originals)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"order", "count", "batch", "epoch", "generation", "identity", "state", "intent", "server-id", "sha", "extra", "missing"} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(mustJSON(smallBatchWireResult(p, f)), &m)
			items := m["items"].([]any)
			first := items[0].(map[string]any)
			switch name {
			case "order":
				items[0], items[1] = items[1], items[0]
			case "count":
				m["items"] = items[:1]
			case "batch":
				m["batch_id"] = "other"
			case "epoch":
				m["server_epoch"] = remoteVersion(9999)
			case "generation":
				first["source_generation"] = "9007199254740993"
			case "identity":
				first["source_identity"] = strings.Repeat("0", 64)
			case "state":
				first["state"] = "PENDING"
			case "intent":
				first["status"].(map[string]any)["session"].(map[string]any)["intentHash"] = strings.Repeat("0", 64)
			case "server-id":
				first["status"].(map[string]any)["session"].(map[string]any)["uploadId"] = remoteVersion(9999)
			case "sha":
				first["status"].(map[string]any)["result"].(map[string]any)["publicationReceipt"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			case "extra":
				first["unexpected"] = true
			case "missing":
				delete(first, "status")
				first["state"] = "MISSING"
			}
			if _, err := p.readOutcome(mustJSON(m)); err == nil {
				t.Fatal("invalid outcome accepted")
			}
		})
	}
}

func TestSmallBatchWireExactInt64UnicodeAndOptionalInteropExport(t *testing.T) {
	originals, _ := smallBatchWireFixture(t, 1)
	op := cloneSmallBatchOperation(t, originals[0])
	op.HTTPBinding = nil
	op.Name = "café😀"
	op.Captured.Evidence.Destination = "tree/nested/" + op.Name
	op.Captured.Transport.RequestPath = "/" + op.Captured.Evidence.Destination
	op.LocalGeneration = math.MaxInt64
	op.Captured.LocalGeneration = math.MaxInt64
	resealSmallBatchOperation(&op)
	p, err := newSmallBatchPlan("batch-exact-1", "rules-é", []Operation{op})
	if err == nil {
		t.Fatal("non-ASCII rules admitted", p)
	}
	p, err = newSmallBatchPlan("batch-exact-1", "rules-v1", []Operation{op})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(p.manifestBytes(), []byte(`"source_generation":"9223372036854775807"`)) || !bytes.Contains(p.manifestBytes(), []byte(op.Name)) {
		t.Fatal(string(p.manifestBytes()))
	}
	raw, err := p.prepareBytes()
	if err != nil {
		t.Fatal(err)
	}
	if output := os.Getenv("PLUTO_BATCH_WIRE_FIXTURE"); output != "" {
		if !filepath.IsAbs(output) {
			t.Fatal("absolute owned export required")
		}
		if err = os.WriteFile(output, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSmallBatchWireExactByteCeilingsAndZeroLength(t *testing.T) {
	originals, _ := smallBatchWireFixture(t, 1)
	ops := make([]Operation, 129)
	for n := range ops {
		op := cloneSmallBatchOperation(t, originals[0])
		op.HTTPBinding = nil
		op.OperationID = remoteVersion(20000 + n)
		op.Name = "bounded-" + op.OperationID
		op.SizeBytes = smallBatchMaximumFileBytes
		op.Captured.Evidence.SizeBytes = op.SizeBytes
		op.Captured.Evidence.Destination = "tree/nested/" + op.Name
		op.Captured.Transport.RequestPath = "/" + op.Captured.Evidence.Destination
		resealSmallBatchOperation(&op)
		ops[n] = op
	}
	p, err := newSmallBatchPlan("batch-boundary", "rules", ops[:128])
	if err != nil || p.dataBytes != smallBatchMaximumDataBytes {
		t.Fatal(err)
	}
	if _, err = newSmallBatchPlan("batch-too-large", "rules", ops); err == nil {
		t.Fatal("32MiB aggregate ceiling exceeded")
	}
	op := ops[0]
	op.SizeBytes = 0
	op.SHA256 = hashBytes(nil)
	op.Captured.Evidence.SizeBytes = 0
	op.Captured.Evidence.SHA256 = op.SHA256
	resealSmallBatchOperation(&op)
	if p, err = newSmallBatchPlan("batch-empty-content", "rules", []Operation{op}); err != nil || p.dataBytes != 0 {
		t.Fatal(err)
	}
}

func TestSmallBatchWireQualifiedCapabilityAndConservativeCeilings(t *testing.T) {
	originals, _ := smallBatchWireFixture(t, 1)
	p, err := newSmallBatchPlan("batch-capability", "rules", originals)
	if err != nil {
		t.Fatal(err)
	}
	identity := originals[0].Captured.Transport
	envelope := func() map[string]any {
		return map[string]any{"schema": "saturn.small-file-batch-capabilities.v1", "transport": smallBatchSchema, "binding": bindingHTTP(p.binding), "device_id": identity.DeviceID, "backend_identity": identity.BackendIdentity, "qualification_receipt_sha256": identity.ContractReceiptSHA256, "limits": map[string]any{"items": 500, "file_bytes": "262144", "data_bytes": "33554432", "manifest_bytes": "4194304"}}
	}
	cap, err := readSmallBatchCapability(mustJSON(envelope()), p.binding, identity.DeviceID, identity.BackendIdentity, identity.ContractReceiptSHA256)
	if err != nil || !cap.admits(p) {
		t.Fatal(cap, err)
	}
	for _, name := range []string{"device", "backend", "receipt", "epoch", "extra", "item-string", "item-zero", "file-number", "data-ceiling", "metadata-ceiling", "fraction"} {
		t.Run(name, func(t *testing.T) {
			m := envelope()
			limits := m["limits"].(map[string]any)
			switch name {
			case "device":
				m["device_id"] = remoteVersion(33333)
			case "backend":
				m["backend_identity"] = "other"
			case "receipt":
				m["qualification_receipt_sha256"] = strings.Repeat("0", 64)
			case "epoch":
				m["binding"].(map[string]any)["server_epoch"] = remoteVersion(33333)
			case "extra":
				m["extra"] = true
			case "item-string":
				limits["items"] = "500"
			case "item-zero":
				limits["items"] = 0
			case "file-number":
				limits["file_bytes"] = 262144
			case "data-ceiling":
				limits["data_bytes"] = "33554433"
			case "metadata-ceiling":
				limits["manifest_bytes"] = "4194305"
			case "fraction":
				limits["items"] = 1.5
			}
			if _, err := readSmallBatchCapability(mustJSON(m), p.binding, identity.DeviceID, identity.BackendIdentity, identity.ContractReceiptSHA256); err == nil {
				t.Fatal("invalid capability admitted")
			}
		})
	}
	cap.fileBytes = 1
	if cap.admits(p) {
		t.Fatal("lower server ceiling ignored")
	}
}
