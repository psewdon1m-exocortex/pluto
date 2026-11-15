package syncstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"pluto/internal/syncproto"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const IsolatedHTTPContract = "pluto.isolated-guarded-http/v1"
const DaemonHTTPContract = "pluto.guarded-daemon-http/v1"

func validHTTPDomain(domain string) bool {
	return domain == IsolatedHTTPContract || domain == DaemonHTTPContract
}

const HTTPMetadataBytes = 40 * 1024
const HTTPChunkBytes = 8 * 1024 * 1024
const HTTPFrameType = "application/vnd.saturn.sync-upload.v1"

// Persisted inside the existing immutable captured operation. This is the
// original HTTP identity, not a second operation registry or current authority.
type CapturedHTTPIdentity struct {
	Domain, Origin, DeviceID, BackendIdentity, ContractReceiptSHA256, RequestPath string
	InputBinding                                                                  RemoteBinding
}

func bindingHTTP(b RemoteBinding) map[string]any {
	return map[string]any{"protocol": b.Protocol, "descriptor_schema": b.DescriptorSchema, "server_identity": b.ServerIdentity, "root_id": b.RootID, "server_epoch": b.ServerEpoch, "policy_version": b.PolicyVersion, "binding_version": b.BindingVersion}
}

// JSON.stringify compatible canonical strings, including U+2028/U+2029; do
// not accidentally rewrite a literal backslash followed by 'u2028'.
func httpJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	raw := bytes.TrimSuffix(out.Bytes(), []byte{'\n'})
	result := make([]byte, 0, len(raw))
	for n := 0; n < len(raw); n++ {
		if raw[n] == '\\' && n+1 < len(raw) {
			if n+5 < len(raw) && (string(raw[n:n+6]) == `\u2028` || string(raw[n:n+6]) == `\u2029`) {
				if raw[n+5] == '8' {
					result = append(result, 0xe2, 0x80, 0xa8)
				} else {
					result = append(result, 0xe2, 0x80, 0xa9)
				}
				n += 5
				continue
			}
			result = append(result, raw[n], raw[n+1])
			n++
			continue
		}
		result = append(result, raw[n])
	}
	return result, nil
}

func strictHTTPObject(v any, keys ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, syncproto.ErrContract
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, syncproto.ErrContract
		}
	}
	return m, nil
}
func httpText(m map[string]any, key string) (string, error) {
	s, ok := m[key].(string)
	if !ok {
		return "", syncproto.ErrContract
	}
	return s, nil
}
func httpUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range []byte(s) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

func validHTTPNamespaceName(s string) bool {
	if !utf8.ValidString(s) || s == "" || s == "." || s == ".." || utf8.RuneCountInString(s) > 255 || strings.ContainsAny(s, "/\\") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validHTTPBackend(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-' {
			continue
		}
		return false
	}
	return true
}

type catalogHTTPInput struct {
	body map[string]any
	hash string
}

func originalCatalogInput(op Operation) (catalogHTTPInput, error) {
	var result catalogHTTPInput
	if op.Captured == nil || op.Captured.Transport == nil || !httpUUID(op.OperationID) || !validHash(op.SHA256) || op.SizeBytes < 0 || op.SizeBytes > MaxFileBytes {
		return result, ErrRemoteUnqualified
	}
	i := op.Captured.Transport
	b := i.InputBinding
	if !validHTTPDomain(i.Domain) || b != op.Captured.Witness.Remote.Binding || !httpUUID(b.RootID) || !httpUUID(b.ServerEpoch) || !httpUUID(b.BindingVersion) || !httpUUID(i.DeviceID) || !validHTTPBackend(i.BackendIdentity) || !validHTTPNamespaceName(op.Name) || len(i.RequestPath) > 4096 || !validHash(i.ContractReceiptSHA256) || i.RequestPath != "/"+op.Captured.Evidence.Destination {
		return result, ErrIdentityConflict
	}
	chain, e := op.ParentTopology()
	if e != nil {
		return result, e
	}
	topology := make([]map[string]any, 0, len(chain))
	triples := make([]any, 0, len(chain))
	for _, p := range chain {
		if !httpUUID(p.NodeID) || p.ParentID != "" && !httpUUID(p.ParentID) || !validHTTPNamespaceName(p.Name) {
			return result, ErrIdentityConflict
		}
		var parent any
		if p.ParentID != "" {
			parent = p.ParentID
		}
		topology = append(topology, map[string]any{"nodeId": p.NodeID, "parentId": parent, "name": p.Name})
		triples = append(triples, []any{p.NodeID, parent, p.Name})
	}
	var target, content, none any
	condition := map[string]any{"kind": "absent"}
	conditionArray := []any{"absent"}
	if op.ExpectedAbsent {
		none = "*"
	} else {
		if !httpUUID(op.ExpectedNodeID) || !httpUUID(op.ExpectedVersion) || !httpUUID(op.Captured.ExpectedContentVersionID) {
			return result, ErrIdentityConflict
		}
		target = op.ExpectedNodeID
		content = op.Captured.ExpectedContentVersionID
		condition = map[string]any{"kind": "match", "nodeId": target, "metadataVersion": op.ExpectedVersion}
		conditionArray = []any{"match", target, op.ExpectedVersion}
	}
	key := "pluto-sync-" + op.OperationID
	intent := map[string]any{"schema": "saturn.upload-intent.v2", "deviceKind": "pluto", "deviceId": i.DeviceID, "rootId": b.RootID, "requestPath": i.RequestPath, "idempotencyKey": key, "parentId": chain[0].NodeID, "name": op.Name, "targetId": target, "sizeBytes": remoteDecimal(op.SizeBytes), "sha256": op.SHA256, "ifMatch": nil, "ifNoneMatch": none, "requireAbsent": op.ExpectedAbsent, "expectedVersionId": content, "condition": condition, "parentTopology": topology}
	canonical := []any{intent["schema"], "pluto", key, i.DeviceID, b.RootID, i.RequestPath, chain[0].NodeID, op.Name, target, remoteDecimal(op.SizeBytes), op.SHA256, nil, none, op.ExpectedAbsent, content}
	canonical = append(canonical, conditionArray...)
	canonical = append(canonical, triples)
	raw, e := httpJSON(canonical)
	if e != nil {
		return result, e
	}
	sum := sha256.Sum256(raw)
	intentRaw, e := httpJSON(intent)
	if e != nil || len(intentRaw) > 32768 {
		return result, ErrSourceQuota
	}
	result = catalogHTTPInput{body: map[string]any{"epoch": b.ServerEpoch, "bindingVersion": b.BindingVersion, "backendIdentity": i.BackendIdentity, "intent": intent}, hash: hex.EncodeToString(sum[:])}
	return result, nil
}

type catalogHTTPStatus struct {
	received        int64
	phase           string
	transferPending bool
	publication     *CapturedPublication
	binding         *HTTPUploadBinding
}

func readCatalogHTTPStatus(raw []byte, op Operation, input catalogHTTPInput) (catalogHTTPStatus, error) {
	var out catalogHTTPStatus
	v, e := syncproto.Parse(raw)
	if e != nil {
		return out, e
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) < 2 || len(m) > 3 {
		return out, syncproto.ErrContract
	}
	if _, ok := m["session"]; !ok {
		return out, syncproto.ErrContract
	}
	if _, ok := m["replayed"].(bool); !ok {
		return out, syncproto.ErrContract
	}
	for k := range m {
		if k != "session" && k != "replayed" && k != "result" {
			return out, syncproto.ErrContract
		}
	}
	s, e := strictHTTPObject(m["session"], "uploadId", "operationId", "rootId", "intentHash", "expectedSizeBytes", "receivedSizeBytes", "phase", "transferPending")
	if e != nil {
		return out, e
	}
	b := op.Captured.Transport.InputBinding
	serverID, ok := s["uploadId"].(string)
	if !ok || !httpUUID(serverID) || s["operationId"] != serverID || s["rootId"] != b.RootID || s["intentHash"] != input.hash || s["expectedSizeBytes"] != remoteDecimal(op.SizeBytes) {
		return out, ErrInvalidReceipt
	}
	association, e := makeHTTPUploadBinding(op, serverID, input.hash)
	if e != nil || op.HTTPBinding != nil && *op.HTTPBinding != association {
		return out, ErrInvalidReceipt
	}
	op.HTTPBinding = &association
	out.binding = &association
	out.received, e = syncproto.Integer64(s["receivedSizeBytes"])
	if e != nil || out.received > op.SizeBytes {
		return out, ErrInvalidReceipt
	}
	out.phase, e = httpText(s, "phase")
	if e != nil {
		return out, e
	}
	switch out.phase {
	case "transport", "verified", "physical_pending", "reconciliation_required", "published", "not_published":
	default:
		return out, syncproto.ErrContract
	}
	out.transferPending, ok = s["transferPending"].(bool)
	if !ok {
		return out, syncproto.ErrContract
	}
	if value, ok := m["result"]; ok {
		r, ok := value.(map[string]any)
		if !ok {
			return out, syncproto.ErrContract
		}
		if r["status"] == "NOT_PUBLISHED" {
			r, e = strictHTTPObject(r, "schema", "status", "uploadId", "operationId", "rootId", "intentHash", "reason")
			if e != nil || r["schema"] != "saturn.catalog-upload-result.v2" || r["uploadId"] != serverID || r["operationId"] != serverID || r["rootId"] != b.RootID || r["intentHash"] != input.hash || r["reason"] != "cancelled_before_publication" || out.phase != "not_published" {
				return out, ErrInvalidReceipt
			}
			return out, nil
		}
		r, e = strictHTTPObject(r, "schema", "status", "uploadId", "operationId", "rootId", "intentHash", "publicationReceipt", "publishedDescription", "firstSeq", "lastSeq")
		if e != nil {
			return out, e
		}
		if r["schema"] != "saturn.catalog-upload-result.v2" || r["status"] != "PUBLISHED" || r["uploadId"] != serverID || r["operationId"] != serverID || r["rootId"] != b.RootID || r["intentHash"] != input.hash || out.phase != "published" || out.transferPending || out.received != op.SizeBytes {
			return out, ErrInvalidReceipt
		}
		rc, e := strictHTTPObject(r["publicationReceipt"], "schema", "uploadId", "operationId", "intentHash", "rootId", "resourceId", "versionId", "parentId", "name", "sizeBytes", "sha256", "etag", "publishedAt")
		if e != nil {
			return out, e
		}
		d, e := syncproto.ReadDescriptor(r["publishedDescription"])
		if e != nil {
			return out, e
		}
		chain, e := op.ParentTopology()
		if e != nil {
			return out, e
		}
		if rc["schema"] != "saturn.upload-publication.v1" || rc["uploadId"] != serverID || rc["operationId"] != serverID || rc["rootId"] != b.RootID || rc["intentHash"] != input.hash || rc["resourceId"] != d.NodeID || d.ParentID == nil || *d.ParentID != chain[0].NodeID || rc["parentId"] != *d.ParentID || rc["name"] != op.Name || d.Name != op.Name || d.Type != "file" || d.Availability != "AVAILABLE" || d.ContentVersionID == nil || rc["versionId"] != *d.ContentVersionID || d.ContentSHA256 == nil || *d.ContentSHA256 != op.SHA256 || rc["sha256"] != op.SHA256 || rc["etag"] != fmt.Sprintf("\"sha256-%s\"", op.SHA256) || rc["sizeBytes"] != remoteDecimal(op.SizeBytes) || d.SizeBytes != remoteDecimal(op.SizeBytes) {
			return out, ErrInvalidReceipt
		}
		published, e := httpText(rc, "publishedAt")
		if e != nil {
			return out, e
		}
		stamp, e := time.Parse("2006-01-02T15:04:05.000Z", published)
		if e != nil || stamp.Format("2006-01-02T15:04:05.000Z") != published {
			return out, ErrInvalidReceipt
		}
		first, e := syncproto.Integer64(r["firstSeq"])
		if e != nil {
			return out, e
		}
		last, e := syncproto.Integer64(r["lastSeq"])
		if e != nil || first < 1 || first > last {
			return out, ErrInvalidReceipt
		}
		pub := CapturedPublication{Binding: b, HTTPBinding: &association, FirstSeq: first, Description: remoteFromDescriptor(op.RootID, op.Captured.Witness.Remote.Generation, last, b, d, serverID), Receipt: Receipt{OperationID: op.OperationID, RootID: op.RootID, EntryID: op.EntryID, NodeID: d.NodeID, Epoch: b.ServerEpoch, Version: d.Version, SHA256: op.SHA256, SealedFingerprint: op.SealedFingerprint, LocalGeneration: op.LocalGeneration, SizeBytes: op.SizeBytes, Seq: last, Published: true, ContentVerified: true}}
		if !validCapturedReceipt(op, Receipt{OperationID: pub.Receipt.OperationID, RootID: pub.Receipt.RootID, EntryID: pub.Receipt.EntryID, NodeID: pub.Receipt.NodeID, Epoch: pub.Receipt.Epoch, Version: pub.Receipt.Version, SHA256: pub.Receipt.SHA256, SealedFingerprint: pub.Receipt.SealedFingerprint, LocalGeneration: pub.Receipt.LocalGeneration, SizeBytes: pub.Receipt.SizeBytes, Seq: last, Published: true, ContentVerified: true, CapturedResult: &CapturedPublicationEvidence{Binding: b, HTTPBinding: &association, Description: pub.Description, FirstSeq: first}}) {
			return out, ErrInvalidReceipt
		}
		out.publication = &pub
	} else if out.phase == "published" || out.phase == "not_published" {
		return out, errors.New("terminal upload has no original outcome")
	}
	return out, nil
}
