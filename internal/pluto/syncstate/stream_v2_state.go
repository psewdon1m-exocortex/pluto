package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"pluto/internal/syncproto"
	"sort"
)

// This client bound is independent of the 256 MiB sealed-artifact quota.
// A v2 writer keeps at most 512 part proofs and two unacknowledged attempts.
// The ordinary planner applies its own qualified file-size ceiling.
const streamV2MaximumFileBytes int64 = 2 << 30
const streamV2MaximumParts = int(streamV2MaximumFileBytes / StreamChunkBytes)

type streamV2Progress struct {
	Schema       string        `json:"schema"`
	OperationID  string        `json:"operationId"`
	InputSHA256  string        `json:"inputSha256"`
	Acknowledged []StreamChunk `json:"acknowledged"`
	Pending      []StreamChunk `json:"pending"`
}

func newStreamV2Progress(op Operation) streamV2Progress {
	return streamV2Progress{Schema: "pluto.stream-progress/v2", OperationID: op.OperationID, InputSHA256: op.Stream.InputSHA256,
		Acknowledged: []StreamChunk{}, Pending: []StreamChunk{}}
}

func (p streamV2Progress) validate(op Operation) error {
	if op.Stream == nil || op.Stream.Schema != "pluto.stream-original/v2" || op.SizeBytes < 1 || op.SizeBytes > streamV2MaximumFileBytes ||
		p.Schema != "pluto.stream-progress/v2" || p.OperationID != op.OperationID || !validHash(p.InputSHA256) || p.InputSHA256 != op.Stream.InputSHA256 ||
		p.Acknowledged == nil || p.Pending == nil || len(p.Acknowledged) > streamV2MaximumParts || len(p.Pending) > 2 {
		return ErrInvalidReceipt
	}
	seen := map[int]bool{}
	for _, parts := range [][]StreamChunk{p.Acknowledged, p.Pending} {
		previous := -1
		for _, c := range parts {
			offset := int64(c.Index) * StreamChunkBytes
			if c.Index <= previous || c.Index < 0 || c.Index >= streamV2MaximumParts || seen[c.Index] || offset >= op.SizeBytes ||
				c.Offset != remoteDecimal(offset) || c.Length != remoteDecimal(min(int64(StreamChunkBytes), op.SizeBytes-offset)) || !validHash(c.SHA256) {
				return ErrInvalidReceipt
			}
			seen[c.Index] = true
			previous = c.Index
		}
	}
	return nil
}

func readStreamV2Progress(raw string, op Operation) (streamV2Progress, error) {
	var progress streamV2Progress
	if len(raw) > 256*1024 {
		return progress, ErrSourceQuota
	}
	parsed, err := syncproto.Parse([]byte(raw))
	if err != nil {
		return progress, err
	}
	body, err := strictHTTPObject(parsed, "schema", "operationId", "inputSha256", "acknowledged", "pending")
	if err != nil {
		return progress, err
	}
	for key, limit := range map[string]int{"acknowledged": streamV2MaximumParts, "pending": 2} {
		parts, ok := body[key].([]any)
		if !ok || len(parts) > limit {
			return progress, ErrSourceQuota
		}
		for _, part := range parts {
			if _, err = strictHTTPObject(part, "index", "offset", "length", "sha256"); err != nil {
				return progress, err
			}
		}
	}
	if err = json.Unmarshal([]byte(raw), &progress); err != nil {
		return progress, err
	}
	return progress, progress.validate(op)
}

func (p *streamV2Progress) reserve(op Operation, chunk StreamChunk) error {
	if err := p.validate(op); err != nil {
		return err
	}
	for _, part := range p.Acknowledged {
		if part.Index == chunk.Index {
			if part != chunk {
				return ErrCaptureChanged
			}
			return nil
		}
	}
	for _, part := range p.Pending {
		if part.Index == chunk.Index {
			if part != chunk {
				return ErrCaptureChanged
			}
			return nil
		}
	}
	if len(p.Pending) == 2 {
		return ErrSourceQuota
	}
	next := append(append([]StreamChunk{}, p.Pending...), chunk)
	sort.Slice(next, func(i, j int) bool { return next[i].Index < next[j].Index })
	copy := *p
	copy.Pending = next
	if err := copy.validate(op); err != nil {
		return err
	}
	*p = copy
	return nil
}

func (p *streamV2Progress) acknowledge(op Operation, status streamV2Status) error {
	if err := p.validate(op); err != nil {
		return err
	}
	if status.Schema != "saturn.stream-upload-status.v2" || status.OperationID != op.OperationID || len(status.Chunks) > 256 {
		return ErrInvalidReceipt
	}
	parts := make(map[int]StreamChunk, len(p.Acknowledged)+len(status.Chunks))
	for _, part := range p.Acknowledged {
		parts[part.Index] = part
	}
	for _, part := range status.Chunks {
		if previous, exists := parts[part.Index]; exists && previous != part {
			return ErrInvalidReceipt
		}
		for _, pending := range p.Pending {
			if pending.Index == part.Index && pending != part {
				return ErrInvalidReceipt
			}
		}
		parts[part.Index] = part
	}
	if len(parts) > streamV2MaximumParts {
		return ErrSourceQuota
	}
	copy := *p
	copy.Acknowledged = make([]StreamChunk, 0, len(parts))
	for _, part := range parts {
		copy.Acknowledged = append(copy.Acknowledged, part)
	}
	sort.Slice(copy.Acknowledged, func(i, j int) bool { return copy.Acknowledged[i].Index < copy.Acknowledged[j].Index })
	copy.Pending = []StreamChunk{}
	for _, pending := range p.Pending {
		if _, acknowledged := parts[pending.Index]; !acknowledged {
			copy.Pending = append(copy.Pending, pending)
		}
	}
	if err := copy.validate(op); err != nil {
		return err
	}
	*p = copy
	return nil
}

// The marker and each pending part commit before its network attempt. This is
// progress for one immutable original, never a new operation or a receipt.
func (s *IsolatedHTTPSession) updateStreamV2Progress(ctx context.Context, op Operation, change func(*streamV2Progress) error) (progress streamV2Progress, created bool, err error) {
	if op.Stream == nil || op.IntentFingerprint != fingerprint(op.Intent) || op.Stream.InputSHA256 != hashBytes(op.Stream.Input) {
		return progress, false, ErrIdentityConflict
	}
	err = s.r.sources.change(ctx, 1<<20, func(tx *sql.Tx) error {
		current, e := readOperation(ctx, tx, op.OperationID)
		if e != nil {
			return e
		}
		if current.Kind != "STREAM_PUT" || current.Stream == nil || current.Stream.Schema != "pluto.stream-original/v2" ||
			current.IntentFingerprint != op.IntentFingerprint || current.IntentFingerprint != fingerprint(current.Intent) ||
			current.Stream.InputSHA256 != hashBytes(current.Stream.Input) || current.Stream.InputSHA256 != op.Stream.InputSHA256 ||
			current.Stage != "SUBMITTED" && current.Stage != "CLIENT_ACKED" {
			return ErrIdentityConflict
		}
		var raw string
		if e = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(CAST(status_json AS BLOB))<=262144 THEN status_json ELSE NULL END FROM stream_progress WHERE operation_id=?", op.OperationID).Scan(&raw); e != nil {
			return e
		}
		created = raw == ""
		if created {
			progress = newStreamV2Progress(op)
		} else if progress, e = readStreamV2Progress(raw, op); e != nil {
			return e
		}
		if change != nil {
			if e = change(&progress); e != nil {
				return e
			}
		}
		if e = progress.validate(op); e != nil {
			return e
		}
		encoded, e := json.Marshal(progress)
		if e != nil || len(encoded) > 256*1024 {
			return ErrSourceQuota
		}
		if e = s.r.point("stream_v2.progress.before_commit"); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, "UPDATE stream_progress SET status_json=? WHERE operation_id=?", string(encoded), op.OperationID)
		return e
	})
	return
}
