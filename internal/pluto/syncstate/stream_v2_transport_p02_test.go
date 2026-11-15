package syncstate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type p02V2Server struct {
	t               *testing.T
	s               *IsolatedHTTPSession
	op              Operation
	mu              sync.Mutex
	parts           map[int]StreamChunk
	calls           map[int]int
	active, maximum int
	loss            bool
	sealHashes      []string
	secondPart      chan struct{}
	secondOnce      sync.Once
}

func (f *p02V2Server) reply(request *http.Request, after int) *http.Response {
	f.mu.Lock()
	defer f.mu.Unlock()
	indices := []int{}
	var received int64
	for index := range f.parts {
		received += min(int64(StreamChunkBytes), f.op.SizeBytes-int64(index)*StreamChunkBytes)
		if index > after {
			indices = append(indices, index)
		}
	}
	sort.Ints(indices)
	chunks := []StreamChunk{}
	for _, index := range indices {
		chunks = append(chunks, f.parts[index])
	}
	raw := mustJSON(map[string]any{"schema": "saturn.stream-upload-status.v2", "operationId": f.op.OperationID, "state": "RECEIVING", "receivedSizeBytes": remoteDecimal(received), "chunks": chunks, "pendingChunks": []StreamChunk{}, "afterIndex": after, "nextIndex": nil, "finalSha256": nil, "publication": nil})
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Request: request}
}
func (f *p02V2Server) RoundTrip(request *http.Request) (*http.Response, error) {
	defer request.Body.Close()
	if request.Header.Get("Authorization") != "Bearer owned-p02-token" || request.GetBody != nil {
		f.t.Error("transport identity/replay contract changed")
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 4+HTTPMetadataBytes+StreamChunkBytes+1))
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(request.URL.Path, "/chunk") {
		if len(raw) < 5 {
			return nil, ErrInvalidReceipt
		}
		n := int(binary.BigEndian.Uint32(raw))
		if n < 1 || n > HTTPMetadataBytes || len(raw) <= 4+n {
			return nil, ErrInvalidReceipt
		}
		var body struct {
			Chunk StreamChunk `json:"chunk"`
		}
		if json.Unmarshal(raw[4:4+n], &body) != nil {
			return nil, ErrInvalidReceipt
		}
		part := body.Chunk
		if part.SHA256 != hashBytes(raw[4+n:]) || part.Length != remoteDecimal(int64(len(raw)-4-n)) {
			return nil, ErrInvalidReceipt
		}
		// The real durable marker must already exist when the transport sees bytes.
		p, _, e := f.s.updateStreamV2Progress(request.Context(), f.op, nil)
		if e != nil {
			return nil, e
		}
		found := false
		for _, pending := range p.Pending {
			if pending == part {
				found = true
			}
		}
		if !found {
			f.t.Error("network attempt preceded durable pending")
		}
		f.mu.Lock()
		if part.Index > 0 {
			if _, ok := f.parts[0]; !ok {
				f.mu.Unlock()
				return nil, ErrArtifactRetained
			}
		}
		f.active++
		if f.active > f.maximum {
			f.maximum = f.active
		}
		f.calls[part.Index]++
		f.mu.Unlock()
		defer func() { f.mu.Lock(); f.active--; f.mu.Unlock() }()
		if part.Index == 2 {
			f.secondOnce.Do(func() { close(f.secondPart) })
		}
		if part.Index == 1 {
			select {
			case <-f.secondPart:
			case <-request.Context().Done():
				return nil, request.Context().Err()
			case <-time.After(2 * time.Second):
				return nil, errors.New("second stream part did not overlap")
			}
		}
		select {
		case <-request.Context().Done():
			return nil, request.Context().Err()
		case <-time.After(30 * time.Millisecond):
		}
		f.mu.Lock()
		f.parts[part.Index] = part
		lost := f.loss && part.Index == 1
		if lost {
			f.loss = false
		}
		f.mu.Unlock()
		if lost {
			return nil, io.ErrUnexpectedEOF
		}
		return f.reply(request, part.Index-1), nil
	}
	var body struct {
		After int `json:"afterIndex"`
		Seal  struct {
			SHA256 string `json:"sha256"`
		} `json:"seal"`
	}
	body.After = -1
	if err = json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if strings.HasSuffix(request.URL.Path, "/seal") {
		f.mu.Lock()
		f.sealHashes = append(f.sealHashes, body.Seal.SHA256)
		f.mu.Unlock()
		return nil, io.ErrUnexpectedEOF // Stop before fake fixture publication.
	}
	return f.reply(request, body.After), nil
}

func p02V2TransportFixture(t *testing.T) (*IsolatedHTTPSession, Operation, *p02V2Server, []byte) {
	priorBudget := transportResources
	transportResources = &transportBudget{target: 1, finishes: map[string]float64{}, paceSlot: make(chan struct{}, 1)}
	t.Cleanup(func() { transportResources = priorBudget })
	t.Helper()
	r, ops := smallBatchStateFixture(t, 1)
	if err := r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	filename := filepath.Join(directory, "large")
	pattern := []byte("p02-v2-distinct-payload")
	data := bytes.Repeat(pattern, (3*StreamChunkBytes+31)/len(pattern)+1)
	data = data[:3*StreamChunkBytes+31]
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	incarnation, err := ObserveSourceIncarnation(directory)
	if err != nil {
		t.Fatal(err)
	}
	op := ops[0]
	op.OperationID, err = NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	op.LocalGeneration++
	op.Kind = "STREAM_PUT"
	op.SizeBytes = int64(len(data))
	op.SHA256 = ""
	op.SnapshotID = ""
	op.SealedFingerprint = ""
	op.Stream = &StreamBinding{Schema: "pluto.stream-original/v2", Input: json.RawMessage(`{"schema":"saturn.stream-upload.v2"}`), Remote: op.Captured.Witness.Remote}
	op.Stream.Source.PhysicalPath = filename
	op.Stream.Source.SourceRootPath = directory
	op.Stream.Source.SourceObject = incarnation.object
	op.Stream.Source.FileIdentity = statIdentity(info)
	op.Stream.Source.SizeBytes = info.Size()
	op.Stream.Source.MTimeNS = info.ModTime().UnixNano()
	op.Stream.Source.CTimeNS = statCTime(info)
	op.Stream.Source.Generation = 1
	op.Captured = nil
	op.Stream.InputSHA256 = hashBytes(op.Stream.Input)
	op.IntentFingerprint = fingerprint(op.Intent)
	if _, err = r.store.db.Exec("INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,?,?,?,?,?,?,'SUBMITTED')", op.OperationID, op.RootID, op.EntryID, op.LocalGeneration, op.Kind, string(mustJSON(op.Intent)), op.IntentFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err = r.store.db.Exec("INSERT INTO stream_progress(operation_id) VALUES(?)", op.OperationID); err != nil {
		t.Fatal(err)
	}
	s := &IsolatedHTTPSession{r: r, root: op.RootID, origin: "https://p02.invalid", token: "owned-p02-token", binding: op.Stream.Remote.Binding, features: map[string]bool{"scale-transfer-v2": true}}
	f := &p02V2Server{t: t, s: s, op: op, parts: map[int]StreamChunk{}, calls: map[int]int{}, secondPart: make(chan struct{})}
	s.client = &http.Client{Transport: f}
	return s, op, f, data
}
func p02V2Acquire(context.Context) (func(), error) { return func() {}, nil }

func TestStreamV2P02PipelineLossRecoversExactParts(t *testing.T) {
	s, op, f, data := p02V2TransportFixture(t)
	p, _, err := s.updateStreamV2Progress(testContext, op, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.loss = true
	if _, err = s.streamV2Source(testContext, op, p, p02V2Acquire); err == nil {
		t.Fatal("lost ACK accepted")
	}
	status, err := s.streamV2Request(testContext, op, "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, p, err = s.streamV2Pages(testContext, op, status)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := s.streamV2Source(testContext, op, p, p02V2Acquire)
	if err != nil || hash != hashBytes(data) {
		t.Fatalf("resume hash: %s %v", hash, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.maximum != 2 || f.active != 0 || f.calls[0] != 1 || f.calls[1] != 1 {
		t.Fatalf("pipeline or duplicate acknowledged data: maximum%d active%d calls%v", f.maximum, f.active, f.calls)
	}
}

func TestStreamV2P02SealedRecoveryDoesNotReadChangedSource(t *testing.T) {
	s, op, f, data := p02V2TransportFixture(t)
	if err := s.streamOriginalV2(testContext, op, p02V2Acquire); err == nil {
		t.Fatal("lost seal reply accepted")
	}
	saved, err := s.r.store.Operation(testContext, op.OperationID)
	if err != nil || saved.SHA256 != hashBytes(data) {
		t.Fatal("source proof not durable", err)
	}
	if err = os.WriteFile(op.Stream.Source.PhysicalPath, []byte("new generation"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.streamOriginalV2(testContext, saved, func(context.Context) (func(), error) {
		t.Error("sealed original recaptured changed source")
		return nil, ErrCaptureChanged
	}); err == nil {
		t.Fatal("lost seal reply accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sealHashes) != 2 || f.sealHashes[0] != saved.SHA256 || f.sealHashes[1] != saved.SHA256 {
		t.Fatal("immutable seal changed", f.sealHashes)
	}
}

func TestStreamV2P02PendingOriginalRejectsChangedSource(t *testing.T) {
	s, op, f, _ := p02V2TransportFixture(t)
	f.loss = true
	p, _, err := s.updateStreamV2Progress(testContext, op, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.streamV2Source(testContext, op, p, p02V2Acquire); err == nil {
		t.Fatal("lost ACK accepted")
	}
	if err = os.WriteFile(op.Stream.Source.PhysicalPath, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.streamV2Source(testContext, op, p, p02V2Acquire); !errors.Is(err, ErrCaptureChanged) {
		t.Fatalf("changed source resumed: %v", err)
	}
	modified := op
	modified.SizeBytes++
	if _, _, err = s.updateStreamV2Progress(testContext, modified, nil); err == nil {
		t.Fatal("detached caller intent accepted")
	}
}

func TestStreamV2P02OrdinaryDispatcherAndCapabilityLoss(t *testing.T) {
	t.Run("dispatch", func(t *testing.T) {
		s, op, f, data := p02V2TransportFixture(t)
		if err := s.StreamOriginal(testContext, op, p02V2Acquire); err == nil {
			t.Fatal("lost seal reply accepted")
		}
		saved, err := s.r.store.Operation(testContext, op.OperationID)
		if err != nil || saved.SHA256 != hashBytes(data) || len(f.sealHashes) != 1 {
			t.Fatal("ordinary entry did not use v2 transport", err)
		}
	})
	t.Run("capability-loss", func(t *testing.T) {
		s, op, f, _ := p02V2TransportFixture(t)
		s.features["scale-transfer-v2"] = false
		if err := s.StreamOriginal(testContext, op, p02V2Acquire); !errors.Is(err, ErrRemoteUnqualified) {
			t.Fatal(err)
		}
		saved, err := s.r.store.Operation(testContext, op.OperationID)
		if err != nil || saved.IntentFingerprint != op.IntentFingerprint || saved.Stream.Schema != op.Stream.Schema || saved.Stage != "SUBMITTED" || len(f.calls) != 0 {
			t.Fatal("capability loss rewrote or transmitted original", err)
		}
	})
}
