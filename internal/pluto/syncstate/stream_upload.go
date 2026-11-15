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
	"time"

	"pluto/internal/syncproto"
)

func (s *IsolatedHTTPSession) streamRequest(ctx context.Context, op Operation, command string, extra map[string]any) (StreamStatus, error) {
	var zero StreamStatus
	if op.Stream == nil || op.Stream.Schema != "pluto.stream-original/v1" || hashBytes(op.Stream.Input) != op.Stream.InputSHA256 {
		return zero, ErrIdentityConflict
	}
	var input any
	if json.Unmarshal(op.Stream.Input, &input) != nil {
		return zero, ErrInvalidReceipt
	}
	body := map[string]any{"binding": bindingHTTP(op.Stream.Remote.Binding), "input": input}
	for k, v := range extra {
		body[k] = v
	}
	raw, err := s.post(ctx, "stream-uploads/"+command, body)
	if err != nil {
		return zero, err
	}
	return s.acceptStreamStatus(ctx, op, raw)
}
func (s *IsolatedHTTPSession) acceptStreamStatus(ctx context.Context, op Operation, raw []byte) (StreamStatus, error) {
	var st StreamStatus
	if _, err := syncproto.Parse(raw); err != nil {
		return st, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, err
	}
	if st.Schema != "saturn.stream-upload-status.v1" || st.OperationID != op.OperationID || len(st.Chunks) > 64 {
		return st, ErrInvalidReceipt
	}
	if st.State != "RECEIVING" && st.State != "SEALED" && st.State != "PUBLISHING" && st.State != "UNKNOWN" && st.State != "PUBLISHED" {
		return st, ErrInvalidReceipt
	}
	var received int64
	for i, c := range st.Chunks {
		size := min(int64(StreamChunkBytes), op.SizeBytes-received)
		if size <= 0 || c.Index != i || c.Offset != remoteDecimal(received) || c.Length != remoteDecimal(size) || !validHash(c.SHA256) {
			return st, ErrInvalidReceipt
		}
		received += size
	}
	if st.Received != remoteDecimal(received) || received > op.SizeBytes || st.FinalSHA256 != nil && !validHash(*st.FinalSHA256) {
		return st, ErrInvalidReceipt
	}
	if op.SHA256 != "" && st.FinalSHA256 != nil && *st.FinalSHA256 != op.SHA256 {
		return st, ErrInvalidReceipt
	}
	err := s.r.sources.change(ctx, 1<<20, func(tx *sql.Tx) error {
		var prior string
		if e := tx.QueryRowContext(ctx, "SELECT status_json FROM stream_progress WHERE operation_id=?", op.OperationID).Scan(&prior); e != nil {
			return e
		}
		if prior != "" {
			var old StreamStatus
			if json.Unmarshal([]byte(prior), &old) != nil || len(old.Chunks) > len(st.Chunks) {
				return ErrInvalidReceipt
			}
			for i, c := range old.Chunks {
				if st.Chunks[i] != c {
					return ErrInvalidReceipt
				}
			}
		}
		_, e := tx.ExecContext(ctx, "UPDATE stream_progress SET status_json=? WHERE operation_id=?", string(raw), op.OperationID)
		return e
	})
	return st, err
}

// A bounded private memory spool is admitted alongside source/data resources.
// ACKs survive restart. Whole SHA is recomputed by a counted source re-read,
// comparing acknowledged chunks; chunk digests are never concatenated as SHA.
func (s *IsolatedHTTPSession) StreamOriginal(ctx context.Context, op Operation, acquire func(context.Context) (func(), error)) (err error) {
	started := time.Now()
	defer func() {
		if err == nil {
			RecordPublication(op.SizeBytes, time.Since(started))
		}
	}()
	if acquire == nil || op.Stream == nil {
		return ErrRemoteUnqualified
	}
	maximum := int64(MaxFileBytes)
	if op.Stream.Schema == "pluto.stream-original/v2" {
		maximum = s.streamFileLimit()
	}
	if op.IntentFingerprint != fingerprint(op.Intent) || op.RootID != s.root || op.Stream.Remote.Binding != s.binding || op.SizeBytes < 0 || op.SizeBytes > maximum {
		return ErrIdentityConflict
	}
	if err = s.r.store.RetryReady(ctx, op.OperationID); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			var waiting *RetryWait
			if !errors.As(err, &waiting) {
				err = s.r.store.RecordRetry(ctx, op.OperationID, err)
			}
		}
	}()
	if op.Stream.Schema == "pluto.stream-original/v2" {
		if !s.features["scale-transfer-v2"] {
			return ErrRemoteUnqualified
		}
		return s.streamOriginalV2(ctx, op, acquire)
	}
	var prior string
	if err = s.r.store.db.QueryRowContext(ctx, "SELECT status_json FROM stream_progress WHERE operation_id=?", op.OperationID).Scan(&prior); err != nil {
		return err
	}
	command := "status"
	if prior == "" {
		command = "prepare"
	}
	status, err := s.streamRequest(ctx, op, command, nil)
	if err != nil {
		return err
	}
	if status.State == "UNKNOWN" || status.Pending != nil {
		return ErrArtifactRetained
	}
	if status.State == "PUBLISHED" {
		return s.ackStream(ctx, op, status)
	}
	if op.SHA256 != "" && status.State != "RECEIVING" {
		status, err = s.streamRequest(ctx, op, "complete", nil)
		if err != nil {
			return err
		}
		return s.ackStream(ctx, op, status)
	}
	release, err := acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	source := op.Stream.Source
	incarnation, err := ObserveSourceIncarnation(source.SourceRootPath)
	if err != nil || incarnation.object != source.SourceObject {
		return ErrCaptureChanged
	}
	link, err := linkGuard(source.PhysicalPath)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(source.PhysicalPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || statIdentity(before) != source.FileIdentity || before.Size() != source.SizeBytes || before.ModTime().UnixNano() != source.MTimeNS || statCTime(before) != source.CTimeNS {
		return ErrCaptureChanged
	}
	buffer := make([]byte, StreamChunkBytes)
	whole := sha256.New()
	var offset int64
	captureSourceReads.Add(1)
	for index := 0; offset < op.SizeBytes; index++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		n := int(min(int64(len(buffer)), op.SizeBytes-offset))
		read, e := io.ReadFull(file, buffer[:n])
		captureSourceBytes.Add(int64(read))
		if e != nil {
			return e
		}
		whole.Write(buffer[:n])
		chunk := StreamChunk{Index: index, Offset: remoteDecimal(offset), Length: remoteDecimal(int64(n)), SHA256: hashBytes(buffer[:n])}
		if index < len(status.Chunks) {
			if status.Chunks[index] != chunk {
				return ErrCaptureChanged
			}
		} else {
			if _, err = s.r.store.db.ExecContext(ctx, "UPDATE stream_progress SET pending_json=? WHERE operation_id=?", string(mustJSON(chunk)), op.OperationID); err != nil {
				return err
			}
			var input any
			if json.Unmarshal(op.Stream.Input, &input) != nil {
				return ErrInvalidReceipt
			}
			meta, e := httpJSON(map[string]any{"binding": bindingHTTP(op.Stream.Remote.Binding), "input": input, "chunk": chunk})
			if e != nil || len(meta) > HTTPMetadataBytes {
				return ErrSourceQuota
			}
			frame := make([]byte, 4+len(meta)+n)
			binary.BigEndian.PutUint32(frame, uint32(len(meta)))
			copy(frame[4:], meta)
			copy(frame[4+len(meta):], buffer[:n])
			raw, e := s.request(ctx, "PATCH", "stream-uploads/chunk", "application/vnd.saturn.sync-stream.v1", frame, len(meta))
			if e != nil {
				return e
			}
			status, e = s.acceptStreamStatus(ctx, op, raw)
			if e != nil {
				return e
			}
			if len(status.Chunks) != index+1 || status.Chunks[index] != chunk || status.Pending != nil {
				return ErrArtifactRetained
			}
			if _, err = s.r.store.db.ExecContext(ctx, "UPDATE stream_progress SET pending_json='' WHERE operation_id=?", op.OperationID); err != nil {
				return err
			}
		}
		offset += int64(n)
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Stat(source.PhysicalPath)
	if err != nil {
		return err
	}
	afterLink, err := linkGuard(source.PhysicalPath)
	if err != nil {
		return err
	}
	incarnation, err = ObserveSourceIncarnation(source.SourceRootPath)
	if err != nil || incarnation.object != source.SourceObject || !os.SameFile(before, current) || !os.SameFile(before, after) || before.Size() != after.Size() || current.Size() != after.Size() || before.ModTime() != after.ModTime() || current.ModTime() != after.ModTime() || statCTime(current) != statCTime(after) || statCTime(before) != statCTime(after) || link != afterLink {
		return ErrCaptureChanged
	}
	hash := hex.EncodeToString(whole.Sum(nil))
	seal := fingerprint(struct{ IntentFingerprint, SHA256 string }{op.IntentFingerprint, hash})
	err = s.r.sources.change(ctx, 1<<20, func(tx *sql.Tx) error {
		original, e := readOperation(ctx, tx, op.OperationID)
		if e != nil {
			return e
		}
		if original.IntentFingerprint != op.IntentFingerprint || original.SHA256 != "" && original.SHA256 != hash {
			return ErrInvalidReceipt
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
	status, err = s.streamRequest(ctx, op, "seal", map[string]any{"seal": map[string]any{"sha256": hash, "sourceGeneration": remoteDecimal(source.Generation), "sourceWitnessSha256": fingerprint(source)}})
	if err != nil {
		return err
	}
	if status.State == "SEALED" || status.State == "PUBLISHING" {
		status, err = s.streamRequest(ctx, op, "complete", nil)
		if err != nil {
			return err
		}
	}
	return s.ackStream(ctx, op, status)
}
func (s *IsolatedHTTPSession) TryStream(ctx context.Context, w SourceWitness, source SourceEntry, entry string, acquire func(context.Context) (func(), error)) (bool, error) {
	handled, _, err := s.tryStream(ctx, w, source, entry, acquire)
	return handled, err
}

func (s *IsolatedHTTPSession) tryStream(ctx context.Context, w SourceWitness, source SourceEntry, entry string, acquire func(context.Context) (func(), error)) (handled, uploaded bool, err error) {
	op, err := s.planStream(ctx, w, source, entry)
	if errors.Is(err, errStreamSourceProofNeeded) {
		proof, hashErr := hashStableStreamSource(ctx, source, acquire)
		if hashErr != nil {
			return false, false, hashErr
		}
		op, err = s.planStreamWithProof(ctx, w, source, entry, proof)
	}
	if errors.Is(err, errStreamVerifiedNoop) {
		return true, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if op == nil {
		return false, false, nil
	}
	err = s.StreamOriginal(ctx, *op, acquire)
	return true, err == nil, err
}
