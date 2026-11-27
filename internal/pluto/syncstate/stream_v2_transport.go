package syncstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

// The ordinary dispatcher uses these helpers only for an explicitly negotiated
// v2 original. The planner's file ceiling remains separate from frame bounds.
func (s *IsolatedHTTPSession) streamV2Request(ctx context.Context, op Operation, command string, extra map[string]any) (streamV2Status, error) {
	var zero streamV2Status
	if op.Stream == nil || op.Stream.Schema != "pluto.stream-original/v2" || op.IntentFingerprint != fingerprint(op.Intent) || op.Stream.InputSHA256 != hashBytes(op.Stream.Input) {
		return zero, ErrIdentityConflict
	}
	var input any
	if json.Unmarshal(op.Stream.Input, &input) != nil {
		return zero, ErrInvalidReceipt
	}
	body := map[string]any{"binding": bindingHTTP(op.Stream.Remote.Binding), "input": input}
	for key, value := range extra {
		body[key] = value
	}
	raw, err := s.post(ctx, "stream-uploads/"+command, body)
	if err != nil {
		return zero, err
	}
	status, err := readStreamV2Status(op, raw)
	if err != nil {
		return zero, err
	}
	after := -1
	if command == "status" {
		if value, ok := extra["afterIndex"].(int); ok {
			after = value
		}
	}
	if status.AfterIndex != after {
		return zero, ErrInvalidReceipt
	}
	_, _, err = s.updateStreamV2Progress(ctx, op, func(p *streamV2Progress) error { return p.acknowledge(op, status) })
	return status, err
}

func (s *IsolatedHTTPSession) streamV2Pages(ctx context.Context, op Operation, status streamV2Status) (streamV2Status, streamV2Progress, error) {
	var progress streamV2Progress
	for page := 0; status.NextIndex != nil; page++ {
		if page >= streamV2MaximumParts/256 {
			return status, progress, ErrSourceQuota
		}
		next := *status.NextIndex
		var err error
		status, err = s.streamV2Request(ctx, op, "status", map[string]any{"afterIndex": next})
		if err != nil {
			return status, progress, err
		}
	}
	progress, _, err := s.updateStreamV2Progress(ctx, op, nil)
	if err != nil {
		return status, progress, err
	}
	var acknowledged int64
	for _, chunk := range progress.Acknowledged {
		acknowledged += min(int64(StreamChunkBytes), op.SizeBytes-int64(chunk.Index)*StreamChunkBytes)
	}
	// No chunk workers run while collecting this complete initial/final view.
	if status.Received != remoteDecimal(acknowledged) {
		return status, progress, ErrInvalidReceipt
	}
	return status, progress, nil
}

func (s *IsolatedHTTPSession) streamV2Chunk(ctx context.Context, op Operation, chunk StreamChunk, frame []byte, metadataBytes int) error {
	raw, err := s.request(ctx, "PATCH", "stream-uploads/chunk", "application/vnd.saturn.sync-stream.v1", frame, metadataBytes)
	if err != nil {
		return err
	}
	status, err := readStreamV2Status(op, raw)
	if err != nil {
		return err
	}
	// v2 chunk replies page from this exact part, so even part511 has a
	// bounded response containing its own durable ACK.
	if status.AfterIndex != chunk.Index-1 {
		return ErrInvalidReceipt
	}
	found := false
	for _, part := range status.Chunks {
		if part.Index == chunk.Index {
			if part != chunk {
				return ErrInvalidReceipt
			}
			found = true
		}
	}
	if !found || status.State == "UNKNOWN" {
		return ErrArtifactRetained
	}
	_, _, err = s.updateStreamV2Progress(ctx, op, func(p *streamV2Progress) error { return p.acknowledge(op, status) })
	return err
}

func (s *IsolatedHTTPSession) streamOriginalV2(ctx context.Context, op Operation, acquire func(context.Context) (func(), error)) error {
	if acquire == nil || op.Stream == nil || op.RootID != s.root || op.Stream.Remote.Binding != s.binding || op.SizeBytes < 1 || op.SizeBytes > streamV2MaximumFileBytes {
		return ErrIdentityConflict
	}
	_, created, err := s.updateStreamV2Progress(ctx, op, nil)
	if err != nil {
		return err
	}
	command := "status"
	if created {
		command = "prepare"
	}
	status, err := s.streamV2Request(ctx, op, command, nil)
	if err != nil && !created {
		var failure *guardedHTTPFailure
		// The server uses operation_reused for an absent status as well as an
		// identity collision. Exact prepare is idempotent and rejects the latter;
		// it never replaces this original after an interrupted first prepare.
		if errors.As(err, &failure) && failure.status == 409 && failure.code == "operation_reused" && failure.path == "stream-uploads/status" && failure.binding == s.binding && failure.transportPin == s.transportPin {
			status, err = s.streamV2Request(ctx, op, "prepare", nil)
		}
	}
	if err != nil {
		return err
	}
	status, progress, err := s.streamV2Pages(ctx, op, status)
	if err != nil {
		return err
	}
	if status.State == "UNKNOWN" || len(status.PendingChunks) != 0 {
		return ErrArtifactRetained
	}
	if status.State == "PUBLISHED" {
		return s.ackStream(ctx, op, status.StreamStatus)
	}
	if op.SHA256 == "" {
		hash, err := s.streamV2Source(ctx, op, progress, acquire)
		if err != nil {
			return err
		}
		seal := fingerprint(struct{ IntentFingerprint, SHA256 string }{op.IntentFingerprint, hash})
		err = s.r.sources.change(ctx, 1<<20, func(tx *sql.Tx) error {
			current, e := readOperation(ctx, tx, op.OperationID)
			if e != nil {
				return e
			}
			if current.IntentFingerprint != op.IntentFingerprint || current.IntentFingerprint != fingerprint(current.Intent) || current.SHA256 != "" && current.SHA256 != hash {
				return ErrIdentityConflict
			}
			var raw string
			if e = tx.QueryRowContext(ctx, "SELECT status_json FROM stream_progress WHERE operation_id=?", op.OperationID).Scan(&raw); e != nil {
				return e
			}
			p, e := readStreamV2Progress(raw, op)
			if e != nil {
				return e
			}
			if len(p.Pending) != 0 || len(p.Acknowledged) != int((op.SizeBytes+StreamChunkBytes-1)/StreamChunkBytes) {
				return ErrArtifactRetained
			}
			if _, e = tx.ExecContext(ctx, "UPDATE operations SET sha256=?,sealed_fingerprint=? WHERE operation_id=?", hash, seal, op.OperationID); e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, "UPDATE stream_progress SET source_verified=1 WHERE operation_id=?", op.OperationID)
			return e
		})
		if err != nil {
			return err
		}
		op.SHA256 = hash
		op.SealedFingerprint = seal
	}
	// Once locally sealed, retries use server-retained bytes and the durable
	// whole hash. A changed or removed source is not recaptured for this ID.
	status, err = s.streamV2Request(ctx, op, "seal", map[string]any{"seal": map[string]any{"sha256": op.SHA256, "sourceGeneration": remoteDecimal(op.Stream.Source.Generation), "sourceWitnessSha256": fingerprint(op.Stream.Source)}})
	if err != nil {
		return err
	}
	if status.State == "SEALED" || status.State == "PUBLISHING" {
		status, err = s.streamV2Request(ctx, op, "complete", nil)
		if err != nil {
			return err
		}
	}
	return s.ackStream(ctx, op, status.StreamStatus)
}

func (s *IsolatedHTTPSession) streamV2Source(ctx context.Context, op Operation, progress streamV2Progress, acquire func(context.Context) (func(), error)) (hash string, err error) {
	if s.features["scale-transfer-v2"] {
		transportResources.qualifyPipeline(2)
	}
	release, err := acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	source := op.Stream.Source
	observation, err := s.observedStreamSource(ctx, op)
	if err != nil {
		return "", err
	}
	link, err := linkGuard(source.PhysicalPath)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(source.PhysicalPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || statIdentity(before) != source.FileIdentity || before.Size() != source.SizeBytes || before.ModTime().UnixNano() != source.MTimeNS || statCTime(before) != source.CTimeNS {
		return "", ErrCaptureChanged
	}
	known := make(map[int]StreamChunk, len(progress.Acknowledged))
	for _, part := range progress.Acknowledged {
		known[part.Index] = part
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	flights := make([]chan error, 0, 2)
	join := func() error { done := flights[0]; flights[0] = nil; flights = flights[1:]; return <-done }
	defer func() {
		cancel()
		for len(flights) > 0 {
			err = errors.Join(err, join())
		}
	}()
	whole := sha256.New()
	captureSourceReads.Add(1)
	var input any
	if json.Unmarshal(op.Stream.Input, &input) != nil {
		return "", ErrIdentityConflict
	}
	for index, offset := 0, int64(0); offset < op.SizeBytes; index++ {
		if len(flights) == 2 {
			if err = join(); err != nil {
				return "", err
			}
		}
		if err = child.Err(); err != nil {
			return "", err
		}
		n := int(min(int64(StreamChunkBytes), op.SizeBytes-offset))
		// Two bounded frames, with headroom for metadata. Place the frame prefix
		// immediately before payload instead of making another whole-body copy.
		buffer := make([]byte, 4+HTTPMetadataBytes+n)
		payload := buffer[4+HTTPMetadataBytes:]
		read, e := io.ReadFull(file, payload)
		captureSourceBytes.Add(int64(read))
		if e != nil {
			return "", e
		}
		whole.Write(payload)
		chunk := StreamChunk{Index: index, Offset: remoteDecimal(offset), Length: remoteDecimal(int64(n)), SHA256: hashBytes(payload)}
		if prior, ok := known[index]; ok {
			if prior != chunk {
				return "", ErrCaptureChanged
			}
		} else {
			if _, _, e = s.updateStreamV2Progress(child, op, func(p *streamV2Progress) error { return p.reserve(op, chunk) }); e != nil {
				return "", e
			}
			meta, e := httpJSON(map[string]any{"binding": bindingHTTP(op.Stream.Remote.Binding), "input": input, "chunk": chunk})
			if e != nil || len(meta) > HTTPMetadataBytes {
				return "", ErrSourceQuota
			}
			start := HTTPMetadataBytes - len(meta)
			frame := buffer[start:]
			binary.BigEndian.PutUint32(frame, uint32(len(meta)))
			copy(frame[4:], meta)
			done := make(chan error, 1)
			flights = append(flights, done)
			go func() { done <- s.streamV2Chunk(child, op, chunk, frame, len(meta)) }()
			// Creation/exclusive-open of chunk0 must finish before disjoint writes.
			if index == 0 {
				if err = join(); err != nil {
					return "", err
				}
			}
		}
		offset += int64(n)
	}
	for len(flights) > 0 {
		if err = join(); err != nil {
			return "", err
		}
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	current, err := os.Stat(source.PhysicalPath)
	if err != nil {
		return "", err
	}
	afterLink, err := linkGuard(source.PhysicalPath)
	if err != nil {
		return "", err
	}
	if err = s.validateStreamSourceRead(ctx, op, observation); err != nil {
		return "", err
	}
	if !os.SameFile(before, current) || !os.SameFile(before, after) || before.Size() != after.Size() || current.Size() != after.Size() || before.ModTime() != after.ModTime() || current.ModTime() != after.ModTime() || statCTime(current) != statCTime(after) || statCTime(before) != statCTime(after) || link != afterLink {
		return "", ErrCaptureChanged
	}
	return hex.EncodeToString(whole.Sum(nil)), nil
}
