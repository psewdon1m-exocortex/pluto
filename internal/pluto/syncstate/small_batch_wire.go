package syncstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"pluto/internal/syncproto"
	"strings"
)

const smallBatchSchema = "saturn.small-file-batch.v1"
const smallBatchMaximumItems = 500
const smallBatchMaximumFileBytes int64 = 256 * 1024
const smallBatchMaximumDataBytes int64 = 32 * 1024 * 1024
const smallBatchMaximumMetadataBytes = 4 * 1024 * 1024

// A transport plan freezes references to already submitted captured originals.
// Neither the plan nor a batch response establishes current L/B/R agreement.
type smallBatchPlan struct {
	id, rules    string
	binding      RemoteBinding
	entries      []smallBatchEntry
	dataBytes    int64
	manifest     []byte
	executionJob bool
	jobWire      []byte
}
type smallBatchEntry struct {
	original       Operation
	input          catalogHTTPInput
	sourceIdentity string
}
type smallBatchItemOutcome struct {
	operationID, state, code string
	sourceGeneration         int64
	sourceIdentity           string
	status                   *catalogHTTPStatus
}
type smallBatchCapability struct {
	binding                             RemoteBinding
	device, backend, receipt            string
	items                               int
	fileBytes, dataBytes, metadataBytes int64
	executionJob, singleRequest         bool
	jobs                                int
}

func readSmallBatchCapability(raw []byte, binding RemoteBinding, device, backend, receipt string) (*smallBatchCapability, error) {
	if len(raw) > 16*1024 {
		return nil, syncproto.ErrLimit
	}
	value, err := syncproto.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, err := strictHTTPObject(value, "schema", "transport", "binding", "device_id", "backend_identity", "qualification_receipt_sha256", "limits")
	if err != nil {
		return nil, err
	}
	given, err := strictHTTPObject(m["binding"], "protocol", "descriptor_schema", "server_identity", "root_id", "server_epoch", "policy_version", "binding_version")
	if err != nil {
		return nil, err
	}
	actual, err := syncproto.ReadBinding(given)
	job, single, pipeline := false, false, false
	switch m["schema"] {
	case "saturn.small-file-batch-capabilities.v1":
	case "saturn.small-execution-job-capabilities.v1":
		job = true
	case "saturn.small-execution-job-pipeline-capabilities.v1":
		job, pipeline = true, true
	case "saturn.small-execution-job-single-request-capabilities.v1":
		job, pipeline, single = true, true, true
	default:
		return nil, ErrRemoteUnqualified
	}
	transport := smallBatchSchema
	if job {
		transport = "saturn.small-execution-job.v1"
	}
	if err != nil || actual != binding || !httpUUID(device) || !validHTTPBackend(backend) || !validHash(receipt) || m["transport"] != transport || m["device_id"] != device || m["backend_identity"] != backend || m["qualification_receipt_sha256"] != receipt {
		return nil, ErrRemoteUnqualified
	}
	fields := []string{"items", "file_bytes", "data_bytes", "manifest_bytes"}
	if pipeline {
		fields = append(fields, "jobs")
	}
	limits, err := strictHTTPObject(m["limits"], fields...)
	if err != nil {
		return nil, err
	}
	number, ok := limits["items"].(json.Number)
	if !ok {
		return nil, syncproto.ErrContract
	}
	count, err := number.Int64()
	if err != nil || count < 1 || count > smallBatchMaximumItems {
		return nil, syncproto.ErrLimit
	}
	file, e1 := syncproto.Integer64(limits["file_bytes"])
	data, e2 := syncproto.Integer64(limits["data_bytes"])
	metadata, e3 := syncproto.Integer64(limits["manifest_bytes"])
	if e1 != nil || e2 != nil || e3 != nil || file < 1 || file > smallBatchMaximumFileBytes || data < file || data > smallBatchMaximumDataBytes || metadata < 1024 || metadata > smallBatchMaximumMetadataBytes {
		return nil, syncproto.ErrLimit
	}
	jobs := 1
	if pipeline {
		if limits["jobs"] != json.Number("2") {
			return nil, ErrRemoteUnqualified
		}
		jobs = 2
	}
	if job && (count > 16 || data > 4194304 || metadata > 1048576) {
		return nil, syncproto.ErrLimit
	}
	return &smallBatchCapability{binding: binding, device: device, backend: backend, receipt: receipt, items: int(count), fileBytes: file, dataBytes: data, metadataBytes: metadata, executionJob: job, singleRequest: single, jobs: jobs}, nil
}
func (c *smallBatchCapability) admits(p *smallBatchPlan) bool {
	if c == nil || p == nil || c.executionJob != p.executionJob || p.binding != c.binding || len(p.entries) > c.items || p.dataBytes > c.dataBytes {
		return false
	}
	raw, err := p.prepareBytes()
	if err != nil || int64(len(raw)) > c.metadataBytes {
		return false
	}
	for _, e := range p.entries {
		if e.original.SizeBytes > c.fileBytes || e.original.Captured.Transport.DeviceID != c.device || e.original.Captured.Transport.BackendIdentity != c.backend || e.original.Captured.Transport.ContractReceiptSHA256 != c.receipt {
			return false
		}
	}
	return true
}

func smallBatchOpaque(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}
func smallBatchToken(s string) bool {
	if !smallBatchOpaque(s) {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || !strings.ContainsRune("._:-", rune(c)) {
			return false
		}
	}
	return true
}

func newSmallBatchPlan(id, rules string, originals []Operation) (*smallBatchPlan, error) {
	if !smallBatchToken(id) || !smallBatchOpaque(rules) || len(originals) < 1 || len(originals) > smallBatchMaximumItems {
		return nil, syncproto.ErrContract
	}
	p := &smallBatchPlan{id: id, rules: rules, entries: make([]smallBatchEntry, 0, len(originals))}
	items := make([]map[string]any, 0, len(originals))
	operations := map[string]bool{}
	destinations := map[[2]string]bool{}
	retained := 0
	device, backend := "", ""
	for _, given := range originals {
		// The caller's nested capture/topology and HTTP binding must not be able to
		// change encoded bytes or outcome validation after construction.
		raw, err := json.Marshal(given)
		if err != nil || len(raw) > HTTPMetadataBytes || retained > smallBatchMaximumMetadataBytes-len(raw) {
			return nil, ErrSourceQuota
		}
		retained += len(raw)
		var op Operation
		if err = json.Unmarshal(raw, &op); err != nil {
			return nil, err
		}
		c := op.Captured
		if c == nil || c.Transport == nil || op.Stage != "SUBMITTED" && op.Stage != "CLIENT_ACKED" || op.LocalGeneration < 1 || op.SizeBytes < 0 || op.SizeBytes > smallBatchMaximumFileBytes ||
			c.Schema != "pluto.captured-operation/v1" || c.LocalGeneration != op.LocalGeneration || c.SourceFileIdentity != op.FileIdentity || c.Evidence.SnapshotID != op.SnapshotID || c.Evidence.SHA256 != op.SHA256 || c.Evidence.SizeBytes != op.SizeBytes ||
			fingerprint(op.Intent) != op.IntentFingerprint || fingerprint(struct{ IntentFingerprint, SHA256 string }{op.IntentFingerprint, op.SHA256}) != op.SealedFingerprint ||
			op.HTTPBinding != nil && !validHTTPUploadBinding(op, *op.HTTPBinding) {
			return nil, ErrIdentityConflict
		}
		if op.SizeBytes == 0 && op.SHA256 != hashBytes(nil) {
			return nil, ErrIdentityConflict
		}
		input, err := originalCatalogInput(op)
		if err != nil {
			return nil, err
		}
		binding := c.Transport.InputBinding
		if _, err = syncproto.ReadBinding(bindingHTTP(binding)); err != nil {
			return nil, err
		}
		if len(p.entries) == 0 {
			p.binding = binding
			device = c.Transport.DeviceID
			backend = c.Transport.BackendIdentity
		}
		if binding != p.binding || device != c.Transport.DeviceID || backend != c.Transport.BackendIdentity || p.dataBytes > smallBatchMaximumDataBytes-op.SizeBytes {
			return nil, ErrIdentityConflict
		}
		intent := input.body["intent"].(map[string]any)
		parent := intent["parentId"].(string)
		destination := [2]string{parent, op.Name}
		if operations[op.OperationID] || destinations[destination] {
			return nil, ErrIdentityConflict
		}
		operations[op.OperationID] = true
		destinations[destination] = true
		identity := fingerprint(c)
		expected := map[string]any{"kind": "absent"}
		if !op.ExpectedAbsent {
			expected = map[string]any{"kind": "version", "node_id": op.ExpectedNodeID, "version": op.ExpectedVersion}
		}
		items = append(items, map[string]any{"operation_id": "pluto-sync-" + op.OperationID, "source_generation": remoteDecimal(op.LocalGeneration), "source_identity": identity, "parent_id": parent, "name": op.Name, "size_bytes": remoteDecimal(op.SizeBytes), "sha256": op.SHA256, "expected": expected})
		p.entries = append(p.entries, smallBatchEntry{op, input, identity})
		p.dataBytes += op.SizeBytes
	}
	manifest := bindingHTTP(p.binding)
	manifest["schema"] = smallBatchSchema
	manifest["batch_id"] = p.id
	manifest["rules_version"] = p.rules
	manifest["items"] = items
	raw, err := httpJSON(manifest)
	if err != nil || len(raw) > smallBatchMaximumMetadataBytes {
		return nil, errors.Join(ErrSourceQuota, err)
	}
	p.manifest = raw
	return p, nil
}

func (p *smallBatchPlan) manifestBytes() []byte { return bytes.Clone(p.manifest) }
func (p *smallBatchPlan) prepareBytes() ([]byte, error) {
	if p.executionJob {
		return bytes.Clone(p.jobWire), nil
	}
	var manifest any
	if err := json.Unmarshal(p.manifest, &manifest); err != nil {
		return nil, err
	}
	inputs := make([]map[string]any, len(p.entries))
	for n, entry := range p.entries {
		inputs[n] = entry.input.body
	}
	raw, err := httpJSON(map[string]any{"manifest": manifest, "inputs": inputs})
	if len(raw) > smallBatchMaximumMetadataBytes {
		return nil, ErrSourceQuota
	}
	return raw, err
}
func (p *smallBatchPlan) statusBytes() ([]byte, error) {
	return httpJSON(map[string]any{"binding": bindingHTTP(p.binding), "batch_id": p.id})
}

// Persisted manifests are checked against the same authoritative operations
// read from the original store; a saved manifest can never mint an operation.
func restoreSmallBatchPlan(raw []byte, originals []Operation) (*smallBatchPlan, error) {
	value, err := syncproto.Parse(raw)
	if err != nil {
		return nil, err
	}
	if top, ok := value.(map[string]any); ok && top["schema"] == "pluto.small-execution-job/v1" {
		return restoreSmallJobPlan(top, originals)
	}
	return restoreSmallBatchValue(value, originals)
}

// The caller has already performed the strict, bounded JSON parse. Reusing
// that value avoids reparsing a job's nested immutable manifest; originals
// are still read and checked anew inside the current store transaction.
func restoreSmallBatchValue(value any, originals []Operation) (*smallBatchPlan, error) {
	m, err := strictHTTPObject(value, "protocol", "descriptor_schema", "server_identity", "root_id", "server_epoch", "policy_version", "binding_version", "schema", "batch_id", "rules_version", "items")
	if err != nil {
		return nil, err
	}
	id, e1 := httpText(m, "batch_id")
	rules, e2 := httpText(m, "rules_version")
	if e1 != nil || e2 != nil || m["schema"] != smallBatchSchema {
		return nil, syncproto.ErrContract
	}
	p, err := newSmallBatchPlan(id, rules, originals)
	if err != nil {
		return nil, err
	}
	canonical, err := httpJSON(value)
	if err != nil || !bytes.Equal(canonical, p.manifest) {
		return nil, ErrIdentityConflict
	}
	return p, nil
}

func (p *smallBatchPlan) readOutcome(raw []byte) ([]smallBatchItemOutcome, error) {
	value, err := syncproto.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, err := strictHTTPObject(value, "protocol", "descriptor_schema", "server_identity", "root_id", "server_epoch", "policy_version", "binding_version", "schema", "batch_id", "items")
	if err != nil {
		return nil, err
	}
	binding, err := syncproto.ReadBinding(m)
	if err != nil || binding != p.binding || m["schema"] != "saturn.small-file-batch-result.v1" || m["batch_id"] != p.id {
		return nil, ErrInvalidReceipt
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != len(p.entries) {
		return nil, ErrInvalidReceipt
	}
	result := make([]smallBatchItemOutcome, len(items))
	for n, item := range items {
		entry := p.entries[n]
		op := entry.original
		itemMap, ok := item.(map[string]any)
		if !ok || itemMap["operation_id"] != "pluto-sync-"+op.OperationID || itemMap["source_generation"] != remoteDecimal(op.LocalGeneration) || itemMap["source_identity"] != entry.sourceIdentity {
			return nil, ErrInvalidReceipt
		}
		state, err := httpText(itemMap, "state")
		if err != nil {
			return nil, err
		}
		out := smallBatchItemOutcome{operationID: op.OperationID, state: state, sourceGeneration: op.LocalGeneration, sourceIdentity: entry.sourceIdentity}
		if status, exists := itemMap["status"]; exists {
			if _, err = strictHTTPObject(itemMap, "operation_id", "source_generation", "source_identity", "state", "status"); err != nil {
				return nil, err
			}
			encoded, err := httpJSON(status)
			if err != nil || len(encoded) > HTTPMetadataBytes {
				return nil, ErrInvalidReceipt
			}
			parsed, err := readCatalogHTTPStatus(encoded, op, entry.input)
			if err != nil {
				return nil, err
			}
			expected := "PENDING"
			switch parsed.phase {
			case "published":
				expected = "PUBLISHED"
			case "not_published":
				expected = "NOT_PUBLISHED"
			case "physical_pending", "reconciliation_required":
				expected = "UNRESOLVED"
			}
			if state != expected {
				return nil, ErrInvalidReceipt
			}
			out.status = &parsed
		} else if state == "MISSING" {
			if _, err = strictHTTPObject(itemMap, "operation_id", "source_generation", "source_identity", "state"); err != nil || op.HTTPBinding != nil {
				return nil, ErrInvalidReceipt
			}
		} else {
			if _, err = strictHTTPObject(itemMap, "operation_id", "source_generation", "source_identity", "state", "code"); err != nil {
				return nil, err
			}
			code, err := httpText(itemMap, "code")
			if err != nil {
				return nil, err
			}
			conflict := code == "operation_reused" || code == "membership_changed" || code == "precondition_failed"
			if conflict {
				if state != "CONFLICT" {
					return nil, ErrInvalidReceipt
				}
			} else {
				if state != "UNRESOLVED" {
					return nil, ErrInvalidReceipt
				}
				switch code {
				case "reconciliation_required", "admission_full", "transfer_unresolved", "verification_failed", "upload_too_large", "counter_exhausted", "sync_internal_error":
				default:
					return nil, ErrInvalidReceipt
				}
			}
			out.code = code
		}
		result[n] = out
	}
	return result, nil
}
