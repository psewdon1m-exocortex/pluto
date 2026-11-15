package syncstate

import (
	"encoding/json"
	"pluto/internal/syncproto"
)

// Wire support alone does not enable the v2 writer. A page has at most 256
// acknowledged parts and four unresolved physical parts regardless of size.
// Persisted originals, bounded source admission and recovery enable transport.
type streamV2Status struct {
	StreamStatus
	AfterIndex    int           `json:"afterIndex"`
	NextIndex     *int          `json:"nextIndex"`
	PendingChunks []StreamChunk `json:"pendingChunks"`
}

func readStreamV2Status(op Operation, raw []byte) (streamV2Status, error) {
	var status streamV2Status
	if op.Stream == nil || op.Stream.Schema != "pluto.stream-original/v2" || op.SizeBytes < 1 || op.SizeBytes > 9007199254740991 || len(raw) > 256*1024 {
		return status, ErrInvalidReceipt
	}
	value, err := syncproto.Parse(raw)
	if err != nil {
		return status, err
	}
	body, err := strictHTTPObject(value, "schema", "operationId", "state", "receivedSizeBytes", "chunks", "pendingChunks", "afterIndex", "nextIndex", "finalSha256", "publication")
	if err != nil {
		return status, err
	}
	for key, maximum := range map[string]int{"chunks": 256, "pendingChunks": 4} {
		parts, ok := body[key].([]any)
		if !ok || len(parts) > maximum {
			return status, ErrInvalidReceipt
		}
		for _, part := range parts {
			if _, err = strictHTTPObject(part, "index", "offset", "length", "sha256"); err != nil {
				return status, err
			}
		}
	}
	if err = json.Unmarshal(raw, &status); err != nil {
		return status, err
	}
	maximumParts := (op.SizeBytes + StreamChunkBytes - 1) / StreamChunkBytes
	if status.Schema != "saturn.stream-upload-status.v2" || status.OperationID != op.OperationID || status.AfterIndex < -1 || int64(status.AfterIndex) >= maximumParts {
		return status, ErrInvalidReceipt
	}
	switch status.State {
	case "RECEIVING", "SEALED", "PUBLISHING", "UNKNOWN", "PUBLISHED":
	default:
		return status, ErrInvalidReceipt
	}
	seen := make(map[int]bool, len(status.Chunks)+len(status.PendingChunks))
	check := func(chunk StreamChunk) bool {
		if chunk.Index < 0 || int64(chunk.Index) >= maximumParts || seen[chunk.Index] || !validHash(chunk.SHA256) {
			return false
		}
		seen[chunk.Index] = true
		offset := int64(chunk.Index) * StreamChunkBytes
		return chunk.Offset == remoteDecimal(offset) && chunk.Length == remoteDecimal(min(int64(StreamChunkBytes), op.SizeBytes-offset))
	}
	previous, acknowledged := status.AfterIndex, int64(0)
	for _, chunk := range status.Chunks {
		if chunk.Index <= previous || !check(chunk) {
			return status, ErrInvalidReceipt
		}
		previous = chunk.Index
		acknowledged += min(int64(StreamChunkBytes), op.SizeBytes-int64(chunk.Index)*StreamChunkBytes)
	}
	for _, chunk := range status.PendingChunks {
		if !check(chunk) {
			return status, ErrInvalidReceipt
		}
	}
	if status.NextIndex != nil && (len(status.Chunks) != 256 || *status.NextIndex != previous) {
		return status, ErrInvalidReceipt
	}
	received, err := syncproto.Integer64(status.Received)
	if err != nil || received < acknowledged || received > op.SizeBytes || remoteDecimal(received) != status.Received {
		return status, ErrInvalidReceipt
	}
	if status.FinalSHA256 != nil {
		if !validHash(*status.FinalSHA256) || op.SHA256 != "" && *status.FinalSHA256 != op.SHA256 || received != op.SizeBytes || len(status.PendingChunks) != 0 || status.State == "RECEIVING" {
			return status, ErrInvalidReceipt
		}
	} else if status.State == "SEALED" || status.State == "PUBLISHING" || status.State == "PUBLISHED" || body["publication"] != nil {
		return status, ErrInvalidReceipt
	}
	if body["publication"] != nil {
		publication, ok := body["publication"].(map[string]any)
		if !ok {
			return status, ErrInvalidReceipt
		}
		session, ok := publication["session"].(map[string]any)
		if !ok || (session["phase"] == "published") != (status.State == "PUBLISHED") {
			return status, ErrInvalidReceipt
		}
	} else if status.State == "PUBLISHED" {
		return status, ErrInvalidReceipt
	}
	return status, nil
}
