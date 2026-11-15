package syncstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func p02StreamV2Operation() Operation {
	return Operation{Intent: Intent{OperationID: "91afdf61-1fc5-47eb-bb13-fd8bc0710f05", SizeBytes: 2 << 30,
		Stream: &StreamBinding{Schema: "pluto.stream-original/v2", Input: json.RawMessage(`{}`), InputSHA256: hashBytes([]byte(`{}`))}}}
}

func TestStreamV2P02ProgressKeepsBoundedPendingAndExactAcknowledgments(t *testing.T) {
	op := p02StreamV2Operation()
	progress := newStreamV2Progress(op)
	page, err := readStreamV2Status(op, mustJSON(p02StreamV2Page(op, -1, 256, true)))
	if err != nil {
		t.Fatal(err)
	}
	if err = progress.reserve(op, page.Chunks[1]); err != nil {
		t.Fatal(err)
	}
	if err = progress.reserve(op, page.Chunks[0]); err != nil {
		t.Fatal(err)
	}
	before := mustJSON(progress)
	if err = progress.reserve(op, page.Chunks[2]); !errors.Is(err, ErrSourceQuota) || !bytes.Equal(before, mustJSON(progress)) {
		t.Fatal("unbounded pending parts", err)
	}
	changed := page.Chunks[0]
	changed.SHA256 = hashBytes([]byte("changed source"))
	if err = progress.reserve(op, changed); !errors.Is(err, ErrCaptureChanged) || !bytes.Equal(before, mustJSON(progress)) {
		t.Fatal("rebound pending part", err)
	}
	if err = progress.acknowledge(op, page); err != nil || len(progress.Pending) != 0 || len(progress.Acknowledged) != 256 {
		t.Fatal("ACK did not retire exact pending parts", err)
	}
	page, err = readStreamV2Status(op, mustJSON(p02StreamV2Page(op, 255, 256, false)))
	if err != nil {
		t.Fatal(err)
	}
	if err = progress.acknowledge(op, page); err != nil {
		t.Fatal(err)
	}
	reopened, err := readStreamV2Progress(string(mustJSON(progress)), op)
	if err != nil || !reflect.DeepEqual(reopened, progress) || len(reopened.Acknowledged) != 512 {
		t.Fatal("bounded proof reopen", err)
	}
	page.Chunks[255].SHA256 = hashBytes([]byte("changed ACK"))
	before = mustJSON(progress)
	if err = progress.acknowledge(op, page); err == nil || !bytes.Equal(before, mustJSON(progress)) {
		t.Fatal("changed ACK accepted")
	}
	other := op
	stream := *op.Stream
	other.Stream = &stream
	other.Stream.InputSHA256 = hashBytes([]byte("other input"))
	if _, err = readStreamV2Progress(string(before), other); err == nil {
		t.Fatal("original input rebound")
	}
}

func p02StreamV2Page(op Operation, after, count int, more bool) map[string]any {
	chunks := make([]StreamChunk, count)
	for i := range chunks {
		index := after + 1 + i
		chunks[i] = StreamChunk{Index: index, Offset: remoteDecimal(int64(index) * StreamChunkBytes),
			Length: remoteDecimal(min(int64(StreamChunkBytes), op.SizeBytes-int64(index)*StreamChunkBytes)), SHA256: hashBytes([]byte{byte(index)})}
	}
	var next any
	if more {
		next = after + count
	}
	return map[string]any{"schema": "saturn.stream-upload-status.v2", "operationId": op.OperationID, "state": "RECEIVING",
		"receivedSizeBytes": remoteDecimal(op.SizeBytes), "chunks": chunks, "pendingChunks": []StreamChunk{}, "afterIndex": after,
		"nextIndex": next, "finalSha256": nil, "publication": nil}
}

func TestStreamV2P02ReadsBoundedPagesForTwoGiB(t *testing.T) {
	op := p02StreamV2Operation()
	for _, after := range []int{-1, 255} {
		status, err := readStreamV2Status(op, mustJSON(p02StreamV2Page(op, after, 256, after == -1)))
		if err != nil || status.AfterIndex != after || len(status.Chunks) != 256 || status.Received != remoteDecimal(op.SizeBytes) {
			t.Fatal("valid bounded ACK page", after, err)
		}
	}
}

func TestStreamV2P02RejectsMalformedOrReboundPages(t *testing.T) {
	op := p02StreamV2Operation()
	cases := map[string]func(map[string]any){
		"other-original":           func(v map[string]any) { v["operationId"] = "a6bc4059-e7fe-4bfc-95e2-b15bd66b6125" },
		"wrong-schema":             func(v map[string]any) { v["schema"] = "saturn.stream-upload-status.v1" },
		"unknown-field":            func(v map[string]any) { v["authority"] = true },
		"too-many-acks":            func(v map[string]any) { v["chunks"] = append(v["chunks"].([]StreamChunk), StreamChunk{}) },
		"wrong-offset":             func(v map[string]any) { v["chunks"].([]StreamChunk)[255].Offset = "0" },
		"wrong-length":             func(v map[string]any) { v["chunks"].([]StreamChunk)[255].Length = "1" },
		"duplicate-ack":            func(v map[string]any) { v["chunks"].([]StreamChunk)[255] = v["chunks"].([]StreamChunk)[254] },
		"wrong-cursor":             func(v map[string]any) { v["nextIndex"] = 256 },
		"nonintegral-cursor":       func(v map[string]any) { v["afterIndex"] = json.Number("-1.0") },
		"received-too-small":       func(v map[string]any) { v["receivedSizeBytes"] = "1" },
		"received-too-large":       func(v map[string]any) { v["receivedSizeBytes"] = remoteDecimal(op.SizeBytes + 1) },
		"pending-duplicate-ack":    func(v map[string]any) { v["pendingChunks"] = []StreamChunk{v["chunks"].([]StreamChunk)[0]} },
		"too-many-pending":         func(v map[string]any) { v["pendingChunks"] = make([]StreamChunk, 5) },
		"published-without-seal":   func(v map[string]any) { v["state"] = "PUBLISHED" },
		"receiving-with-seal":      func(v map[string]any) { v["finalSha256"] = hashBytes(nil) },
		"publication-without-seal": func(v map[string]any) { v["publication"] = map[string]any{} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v := p02StreamV2Page(op, -1, 256, true)
			change(v)
			if _, err := readStreamV2Status(op, mustJSON(v)); err == nil {
				t.Fatal("malformed stream page accepted")
			}
		})
	}
	raw := mustJSON(p02StreamV2Page(op, -1, 256, true))
	raw = bytes.Replace(raw, []byte(`"afterIndex":-1`), []byte(`"afterIndex":-1,"afterIndex":-1`), 1)
	if _, err := readStreamV2Status(op, raw); err == nil {
		t.Fatal("duplicate JSON field accepted")
	}
}
