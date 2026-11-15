package syncstate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type batchTrackedSource struct {
	*bytes.Reader
	largest, calls, closes int
}

func (s *batchTrackedSource) Read(p []byte) (int, error) {
	s.calls++
	s.largest = max(s.largest, len(p))
	return s.Reader.Read(p)
}
func (s *batchTrackedSource) Close() error { s.closes++; return nil }
func batchStreamPlan(t *testing.T) (*smallBatchPlan, [][]byte) {
	t.Helper()
	originals, _ := smallBatchWireFixture(t, 4)
	payloads := [][]byte{nil, []byte{0}, bytes.Repeat([]byte{0xE9, 0, 0xFF, 0xF0}, 256), bytes.Repeat([]byte{0xAE}, 256*1024)}
	for n := range originals {
		op := &originals[n]
		op.HTTPBinding = nil
		op.Stage = "SUBMITTED"
		op.SizeBytes = int64(len(payloads[n]))
		op.SHA256 = hashBytes(payloads[n])
		op.Captured.Evidence.SizeBytes = op.SizeBytes
		op.Captured.Evidence.SHA256 = op.SHA256
		resealSmallBatchOperation(op)
	}
	p, err := newSmallBatchPlan("stream-test", "rules-v1", originals)
	if err != nil {
		t.Fatal(err)
	}
	return p, payloads
}
func readBatchInChunks(t *testing.T, r io.Reader, size int) ([]byte, error) {
	t.Helper()
	var output bytes.Buffer
	chunk := make([]byte, size)
	for {
		n, err := r.Read(chunk)
		output.Write(chunk[:n])
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return output.Bytes(), err
		}
		if n == 0 {
			t.Fatal("non-progressing stream")
		}
	}
}
func checkBatchMIME(t *testing.T, raw []byte, kind string, p *smallBatchPlan, payloads [][]byte) {
	t.Helper()
	media, params, err := mime.ParseMediaType(kind)
	if err != nil || media != "multipart/related" {
		t.Fatal(kind, err)
	}
	r := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
	part, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := io.ReadAll(part)
	if err != nil || !bytes.Equal(manifest, p.manifestBytes()) {
		t.Fatal("manifest", err)
	}
	for n, payload := range payloads {
		part, err = r.NextPart()
		if err != nil {
			t.Fatal(n, err)
		}
		given, e := io.ReadAll(part)
		if e != nil || !bytes.Equal(given, payload) || part.Header.Get("Content-ID") != "<pluto-sync-"+p.entries[n].original.OperationID+">" || part.Header.Get("Content-Length") != remoteDecimal(int64(len(payload))) {
			t.Fatal("part", n, e)
		}
	}
	if _, err = r.NextPart(); err != io.EOF {
		t.Fatal("unexpected part", err)
	}
}
func TestSmallBatchTransportMultipartBoundedExactAndCallerOwned(t *testing.T) {
	p, payloads := batchStreamPlan(t)
	aggregate := bytes.Join(payloads, nil)
	for _, size := range []int{1, 17, 1024 * 1024} {
		source := &batchTrackedSource{Reader: bytes.NewReader(aggregate)}
		var data, metadata int64
		stream, err := newSmallBatchStream(testContext, p, source, func(n int, d bool) {
			if d {
				data += int64(n)
			} else {
				metadata += int64(n)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := readBatchInChunks(t, stream, size)
		if err != nil || int64(len(raw)) != stream.length || stream.finished() != nil {
			t.Fatal(err, len(raw), stream.length)
		}
		if source.largest > smallBatchStreamChunk || data != p.dataBytes || metadata+data != stream.length {
			t.Fatal(source.largest, data, metadata)
		}
		checkBatchMIME(t, raw, stream.contentType, p, payloads)
		stream.Close()
		if source.closes != 0 {
			t.Fatal("caller source closed")
		}
		if _, err = source.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("closed stream reused", err)
		}
		if size == 17 && os.Getenv("PLUTO_BATCH_STREAM_FIXTURE") != "" {
			dir := os.Getenv("PLUTO_BATCH_STREAM_FIXTURE")
			if err = os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string][]byte{"body.bin": raw, "content-type.txt": []byte(stream.contentType), "manifest.json": p.manifestBytes()} {
				if err = os.WriteFile(filepath.Join(dir, name), value, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
func TestSmallBatchTransportCorruptSpanWithholdsFollowingDelimiter(t *testing.T) {
	p, payloads := batchStreamPlan(t)
	aggregate := bytes.Join(payloads, nil)
	aggregate[1] ^= 0xFF // third item; preceding zero/one-byte items are complete
	stream, err := newSmallBatchStream(testContext, p, bytes.NewReader(aggregate), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(stream)
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatal(err)
	}
	if bytes.Contains(raw, stream.header(3)) || bytes.Contains(raw, stream.closing()) || stream.finished() == nil {
		t.Fatal("corrupt span acquired a publication delimiter")
	}
	if !bytes.Contains(raw, stream.header(2)) {
		t.Fatal("earlier independent parts lost")
	}
}
func TestSmallBatchTransportLengthPositionCancellationAndGrowth(t *testing.T) {
	p, payloads := batchStreamPlan(t)
	aggregate := bytes.Join(payloads, nil)
	for _, name := range []string{"short", "long", "position", "truncated-later", "epilogue-later", "cancel-before", "cancel-during"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(testContext)
			defer cancel()
			source := bytes.NewReader(aggregate)
			switch name {
			case "short":
				source.Reset(aggregate[:len(aggregate)-1])
			case "long":
				source.Reset(append(bytes.Clone(aggregate), 0))
			case "position":
				source.Seek(1, io.SeekStart)
			case "cancel-before":
				cancel()
			}
			stream, err := newSmallBatchStream(ctx, p, source, nil)
			if name == "short" || name == "long" || name == "position" || name == "cancel-before" {
				if err == nil {
					t.Fatal("invalid input accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "truncated-later":
				source.Reset(aggregate[:len(aggregate)-1])
			case "epilogue-later":
				source.Reset(append(bytes.Clone(aggregate), 0))
			case "cancel-during":
				if _, err = stream.Read(make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				cancel()
			}
			raw, err := io.ReadAll(stream)
			if err == nil || bytes.Contains(raw, stream.closing()) {
				t.Fatal("invalid aggregate completed", err)
			}
		})
	}
}

type batchRoundTrip func(*http.Request) (*http.Response, error)

func (f batchRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSmallBatchTransportHTTPExactScopeStatusLimitsAndNoReplay(t *testing.T) {
	originals, f := smallBatchWireFixture(t, 2)
	identity := *originals[0].Captured.Transport
	identity.RequestPath = ""
	identity.InputBinding = RemoteBinding{}
	s := &IsolatedHTTPSession{root: originals[0].RootID, origin: identity.Origin, token: "fixture-token", identity: identity, binding: f.binding}
	p, err := newSmallBatchPlan("http-transport", "rules", originals)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	command := ""
	status := http.StatusAccepted
	kind := "application/json"
	response := mustJSON(smallBatchWireResult(p, f))
	stopEarly := false
	lose := false
	s.client = &http.Client{Transport: batchRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.GetBody != nil || r.Header.Get("Idempotency-Key") != "" || r.Header.Get("Authorization") != "Bearer fixture-token" || r.URL.String() != s.origin+"/sync/v1/roots/"+s.binding.RootID+"/small-batches/"+command {
			t.Error("request escaped pinned transport")
		}
		if r.Body != nil {
			defer r.Body.Close()
			if !stopEarly {
				raw, e := io.ReadAll(r.Body)
				if e != nil {
					return nil, e
				}
				if int64(len(raw)) != r.ContentLength {
					t.Error("wrong content length")
				}
				if command == "data" {
					checkBatchMIME(t, raw, r.Header.Get("Content-Type"), p, [][]byte{[]byte("one"), []byte("one")})
				}
			}
		}
		if lose {
			return nil, io.ErrUnexpectedEOF
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{kind}}, Body: io.NopCloser(bytes.NewReader(response)), ContentLength: -1, Request: r}, nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, value := range []string{"prepare", "status", "data"} {
		command = value
		status = http.StatusAccepted
		if command == "status" {
			status = http.StatusOK
		}
		var outcomes []smallBatchItemOutcome
		if value == "data" {
			outcomes, err = s.sendSmallBatch(testContext, p, bytes.NewReader([]byte("oneone")))
		} else {
			outcomes, err = s.smallBatchJSON(testContext, p, value)
		}
		if err != nil || len(outcomes) != 2 || outcomes[0].status.publication == nil {
			t.Fatal(value, err)
		}
	}
	if calls != 3 || s.Metrics().DataBytes != 6 {
		t.Fatal(calls, s.Metrics())
	}
	for _, field := range []string{"root", "origin", "device", "backend", "receipt", "binding"} {
		t.Run(field, func(t *testing.T) {
			copySession := &IsolatedHTTPSession{root: s.root, origin: s.origin, identity: s.identity, binding: s.binding, client: s.client, token: s.token}
			switch field {
			case "root":
				copySession.root = "foreign"
			case "origin":
				copySession.identity.Origin = "http://127.0.0.1:1"
			case "device":
				copySession.identity.DeviceID = remoteVersion(989)
			case "backend":
				copySession.identity.BackendIdentity = "foreign"
			case "receipt":
				copySession.identity.ContractReceiptSHA256 = strings.Repeat("0", 64)
			case "binding":
				copySession.binding.ServerEpoch = remoteVersion(989)
			}
			before := calls
			if _, err := copySession.smallBatchJSON(testContext, p, "prepare"); !errors.Is(err, ErrIdentityConflict) || calls != before {
				t.Fatal(err, calls, before)
			}
		})
	}
	command = "data"
	status = http.StatusAccepted
	stopEarly = true
	if _, err = s.sendSmallBatch(testContext, p, bytes.NewReader([]byte("oneone"))); !errors.Is(err, ErrArtifactRetained) {
		t.Fatal("early response accepted incomplete sender", err)
	}
	stopEarly = false
	lose = true
	before := calls
	if _, err = s.sendSmallBatch(testContext, p, bytes.NewReader([]byte("oneone"))); err == nil || calls != before+1 {
		t.Fatal("implicit replay", err, calls-before)
	}
	lose = false
	command = "status"
	status = http.StatusOK
	for _, name := range []string{"response-limit", "media", "charset", "duplicate-json", "wrong-status", "foreign-outcome"} {
		t.Run(name, func(t *testing.T) {
			response = mustJSON(smallBatchWireResult(p, f))
			kind = "application/json"
			status = http.StatusOK
			switch name {
			case "response-limit":
				response = bytes.Repeat([]byte{' '}, smallBatchMaximumMetadataBytes+1)
			case "media":
				kind = "application/jsonx"
			case "charset":
				kind = "application/json; charset=utf-16"
			case "duplicate-json":
				response = []byte(`{"a":1,"a":2}`)
			case "wrong-status":
				status = http.StatusAccepted
			case "foreign-outcome":
				m := smallBatchWireResult(p, f)
				m["batch_id"] = "foreign"
				response = mustJSON(m)
			}
			if _, err = s.smallBatchJSON(testContext, p, "status"); err == nil {
				t.Fatal("bad response accepted")
			}
		})
	}
	command = "capabilities"
	status = http.StatusOK
	kind = "application/json"
	response = mustJSON(map[string]any{"schema": "saturn.small-file-batch-capabilities.v1", "transport": smallBatchSchema, "binding": bindingHTTP(p.binding), "device_id": s.identity.DeviceID, "backend_identity": s.identity.BackendIdentity, "qualification_receipt_sha256": s.identity.ContractReceiptSHA256, "limits": map[string]any{"items": 500, "file_bytes": "262144", "data_bytes": "33554432", "manifest_bytes": "4194304"}})
	cap, err := s.readSmallBatchCapability(testContext)
	if err != nil || !cap.admits(p) {
		t.Fatal(err)
	}
	status = http.StatusNotFound
	response = []byte(`{"code":"batch_missing"}`)
	command = "status"
	_, err = s.smallBatchJSON(testContext, p, "status")
	var failure *guardedHTTPFailure
	if !errors.As(err, &failure) || failure.status != 404 || failure.code != "batch_missing" {
		t.Fatal(err)
	}
}

func TestSmallBatchTransportLoopbackCancellationJoinsReader(t *testing.T) {
	originals, f := smallBatchWireFixture(t, 1)
	var received atomic.Int64
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	op := cloneSmallBatchOperation(t, originals[0])
	op.HTTPBinding = nil
	op.Captured.Transport.Origin = server.URL
	resealSmallBatchOperation(&op)
	p, err := newSmallBatchPlan("cancel-network", "rules", []Operation{op})
	if err != nil {
		t.Fatal(err)
	}
	identity := *op.Captured.Transport
	identity.RequestPath = ""
	identity.InputBinding = RemoteBinding{}
	s := &IsolatedHTTPSession{root: op.RootID, origin: server.URL, token: "fixture-token", identity: identity, binding: f.binding, client: &http.Client{Timeout: time.Second * 5, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	defer s.Close()
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	done := make(chan error, 1)
	source := &batchTrackedSource{Reader: bytes.NewReader([]byte("one"))}
	go func() { _, err := s.sendSmallBatch(ctx, p, source); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request absent")
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not join")
	}
	if received.Load() != 1 || source.closes != 0 {
		t.Fatal(received.Load(), source.closes)
	}
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		t.Fatal("caller handle lost", err)
	}
}
