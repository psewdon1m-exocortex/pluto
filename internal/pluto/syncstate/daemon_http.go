package syncstate

import (
	"context"
	"encoding/json"
	"pluto/internal/syncproto"
	"time"
)

// The HTTPS capability reply must match the protected adopted binding. A new
// epoch/backend/receipt does not silently authorize a different writer.
func (s *IsolatedHTTPSession) Negotiate(ctx context.Context) error {
	raw, err := s.request(ctx, "GET", "capabilities", "application/json", nil, 0)
	if err != nil {
		return err
	}
	v, err := syncproto.Parse(raw)
	if err != nil {
		return err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ErrRemoteUnqualified
	}
	binding, ok := m["binding"].(map[string]any)
	if !ok {
		return ErrRemoteUnqualified
	}
	b, err := syncproto.ReadBinding(binding)
	if err != nil || b != s.binding || m["schema"] != "saturn.sync-capabilities.v1" || m["device_id"] != s.identity.DeviceID || m["backend_identity"] != s.identity.BackendIdentity || m["qualification_receipt_sha256"] != s.identity.ContractReceiptSHA256 {
		return ErrRemoteUnqualified
	}
	values, ok := m["features"].([]any)
	if !ok || len(values) > 64 {
		return ErrRemoteUnqualified
	}
	features := map[string]bool{}
	for _, v := range values {
		f, ok := v.(string)
		if !ok || len(f) > 128 {
			return ErrRemoteUnqualified
		}
		features[f] = true
	}
	for _, required := range []string{"snapshot-v1", "changes-v1", "folder-v2", "catalog-upload-v2"} {
		if !features[required] {
			return ErrRemoteUnqualified
		}
	}
	optional := []string{"changes-wait-v1", "folder-batch-v1", "namespace-mutations-v1", "stream-upload-v1", "metadata-gzip-v1", "clone-content-v1", "scale-transfer-v2"}
	wanted := map[string]bool{}
	for _, name := range s.requested.Features {
		known := false
		for _, allowed := range optional {
			if name == allowed {
				known = true
			}
		}
		if !known || wanted[name] {
			return ErrRemoteUnqualified
		}
		wanted[name] = true
	}
	if ext, ok := m["extensions"].(map[string]any); ok {
		revisions, ok := ext["revisions"].(map[string]any)
		if !ok {
			return ErrRemoteUnqualified
		}
		for key, want := range map[string]string{"K1": "2", "K2": "2", "K3": "2", "K4": "1"} {
			if revisions[key] != json.Number(want) {
				return ErrRemoteUnqualified
			}
		}
		limits, ok := ext["limits"].(map[string]any)
		if !ok {
			return ErrRemoteUnqualified
		}
		maximumChunks := "256"
		if features["scale-transfer-v2"] {
			maximumChunks = "2147483648"
		}
		for key, want := range map[string]string{"metadata_items": "500", "metadata_bytes": "4194304", "long_poll_ms": "25000", "gzip_threshold_bytes": "16384", "stream_chunk_bytes": "4194304", "stream_maximum_chunks": maximumChunks} {
			if limits[key] != json.Number(want) {
				return ErrRemoteUnqualified
			}
		}
		policy, ok := ext["namespace"].(map[string]any)
		if !ok || len(policy) != 2 {
			return ErrRemoteUnqualified
		}
		hash, ok := policy["policyHash"].(string)
		if !ok || !validHash(hash) {
			return ErrRemoteUnqualified
		}
		codec := s.requested.NameCodec
		if codec == "" {
			codec = "legacy"
		}
		if policy["codec"] != codec || s.requested.PolicyHash != "" && s.requested.PolicyHash != hash || ext["minimum_writer"] != "saturn.namespace-mutation.v1" || ext["backend_policy"] != "managed-exclusive" {
			return ErrRemoteUnqualified
		}
		s.namespace = policy
	} else if len(wanted) > 0 || s.requested.NameCodec == "portable_v1" || features["scale-transfer-v2"] {
		return ErrRemoteUnqualified
	}
	for _, name := range optional {
		features[name] = features[name] && wanted[name] && s.namespace != nil
	}
	// v2 is an explicit profile request and requires the stream contract too.
	// Existing profiles keep their v1 wire identities and bounded fallback.
	if features["scale-transfer-v2"] && !features["stream-upload-v1"] {
		return ErrRemoteUnqualified
	}
	if features["clone-content-v1"] && !features["namespace-mutations-v1"] {
		return ErrRemoteUnqualified
	}
	streamFileBytes := int64(MaxFileBytes)
	if features["scale-transfer-v2"] {
		limits, ok := m["limits"].(map[string]any)
		if !ok {
			return ErrRemoteUnqualified
		}
		maximum, err := syncproto.Integer64(limits["maximum_file_bytes"])
		if err != nil || maximum < 1 {
			return ErrRemoteUnqualified
		}
		streamFileBytes = min(maximum, int64(streamV2MaximumFileBytes))
	}
	s.streamFileBytes = streamFileBytes
	s.features = features
	return nil
}
func (s *IsolatedHTTPSession) Features() map[string]bool {
	out := map[string]bool{}
	for k, v := range s.features {
		out[k] = v
	}
	return out
}

// WaitChanges imports every returned page at its durable cursor. No transaction
// remains open during a long poll, and cancellation never advances the cursor.
func (s *IsolatedHTTPSession) WaitChanges(ctx context.Context) error {
	if !s.features["changes-wait-v1"] {
		return s.Refresh(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.r.Candidate(ctx, s.root)
	if err != nil || !c.Valid || c.Binding != s.binding {
		return ErrRemoteUnqualified
	}
	raw, err := s.post(ctx, "changes", map[string]any{"binding": bindingHTTP(s.binding), "cursor": c.Cursor, "wait_ms": 25000})
	if err != nil {
		if s.eligibleRebootstrapFailure(err) {
			s.freshAt = time.Time{}
			return s.rebootstrap(ctx, c, err)
		}
		return err
	}
	feed, err := syncproto.ReadFeed(raw, c.Binding, remoteDecimal(c.Position))
	if err != nil {
		return err
	}
	if _, err = s.r.importFeed(ctx, c.RemoteWitness, raw, c.HTTPRebootstrap); err != nil {
		return err
	}
	if feed.HasMore {
		return s.refresh(ctx)
	}
	s.freshAt = time.Now()
	return nil
}

func (s *IsolatedHTTPSession) CapabilityJSON() json.RawMessage {
	raw, _ := json.Marshal(s.features)
	return raw
}
