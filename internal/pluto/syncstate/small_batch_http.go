package syncstate

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"pluto/internal/network"
	"strings"

	"pluto/internal/syncproto"
)

// These internal transport operations do not enable a batcher, change state,
// create a baseline, or acknowledge a source generation. Their caller must
// durably retain original operations and the aggregate before attempting data.
func (s *IsolatedHTTPSession) requireSmallBatch(p *smallBatchPlan) error {
	if p == nil || p.binding != s.binding {
		return ErrIdentityConflict
	}
	for _, entry := range p.entries {
		op := entry.original
		identity := *op.Captured.Transport
		identity.InputBinding = RemoteBinding{}
		identity.RequestPath = ""
		if op.RootID != s.root || identity != s.identity || op.Captured.Transport.InputBinding != s.binding {
			return ErrIdentityConflict
		}
	}
	return nil
}
func (s *IsolatedHTTPSession) smallBatchRequest(ctx context.Context, command, kind string, body io.ReadCloser, length int64, limit int) (result []byte, resultErr error) {
	return s.smallTransferRequest(ctx, "small-batches", command, kind, body, length, limit)
}
func (s *IsolatedHTTPSession) smallTransferRequest(ctx context.Context, prefix, command, kind string, body io.ReadCloser, length int64, limit int) (result []byte, resultErr error) {
	if prefix != "small-batches" && prefix != "small-jobs" {
		return nil, syncproto.ErrContract
	}
	if s.denied.Load() {
		return nil, &guardedHTTPFailure{status: 403, code: "authorization_revoked"}
	}
	if s.sessionContext != nil {
		child, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(s.sessionContext, cancel)
		defer func() { stop(); cancel() }()
		ctx = child
	}
	defer func() {
		if resultErr != nil {
			transportResources.failed(resultErr)
		}
	}()
	method, status := http.MethodPost, http.StatusAccepted
	switch command {
	case "capabilities", "pipeline-capabilities", "single-request-capabilities":
		method, status = http.MethodGet, http.StatusOK
	case "status":
		status = http.StatusOK
	case "prepare", "data", "execute":
	default:
		return nil, syncproto.ErrContract
	}
	if limit < 1 || limit > smallBatchMaximumMetadataBytes || length < 0 {
		return nil, ErrSourceQuota
	}
	if body != nil {
		defer body.Close()
	}
	dataRequest := command == "data" || command == "execute"
	if dataRequest {
		if e := transportResources.pace(ctx, length, s.requested.BandwidthBytesPerSecond); e != nil {
			return nil, e
		}
	}
	admission, cancelAdmission := context.WithTimeout(ctx, network.ControlTimeout)
	release, admissionErr := transportResources.acquire(admission, dataRequest, length)
	cancelAdmission()
	if admissionErr != nil {
		return nil, admissionErr
	}
	defer release()
	compressed := false
	if kind == "application/json" && length > 16384 && s.features["metadata-gzip-v1"] {
		if length > int64(limit) {
			return nil, ErrSourceQuota
		}
		raw, e := io.ReadAll(io.LimitReader(body, int64(limit)+1))
		if e != nil {
			return nil, e
		}
		if len(raw) > limit || int64(len(raw)) != length {
			return nil, ErrSourceQuota
		}
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		if _, e = writer.Write(raw); e != nil {
			return nil, e
		}
		if e = writer.Close(); e != nil {
			return nil, e
		}
		if buffer.Len() > limit {
			return nil, ErrSourceQuota
		}
		body = io.NopCloser(bytes.NewReader(buffer.Bytes()))
		length = int64(buffer.Len())
		compressed = true
	}
	request, err := http.NewRequestWithContext(ctx, method, s.origin+"/sync/v1/roots/"+s.binding.RootID+"/"+prefix+"/"+command, body)
	if err != nil {
		return nil, err
	}
	request.ContentLength = length
	// Never install GetBody or an idempotency header. A failed attempt is
	// reconciled with explicit status against the same immutable originals.
	request.Header.Set("Authorization", "Bearer "+s.token)
	request.Header.Set("Accept", "application/json")
	if compressed {
		request.Header.Set("Content-Encoding", "gzip")
	}
	if s.features["metadata-gzip-v1"] {
		request.Header.Set("Accept-Encoding", "gzip")
	}
	if kind != "" {
		request.Header.Set("Content-Type", kind)
	}
	s.requests.Add(1)
	response, err := network.Do(s.client, request, network.GuardedDeadlines(dataRequest))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		return nil, s.readHTTPFailure(ctx, response, prefix+"/"+command)
	}
	if response.ContentLength > int64(limit) {
		return nil, syncproto.ErrLimit
	}
	raw, err := readMetadataResponse(response.Body, response.Header.Get("Content-Encoding"), limit, s.features["metadata-gzip-v1"])
	s.responses.Add(int64(len(raw)))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, syncproto.ErrLimit
	}
	media, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(media, "application/json") || parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") {
		return nil, syncproto.ErrContract
	}
	if _, err = syncproto.Parse(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
func (s *IsolatedHTTPSession) readSmallBatchCapability(ctx context.Context) (*smallBatchCapability, error) {
	raw, err := s.smallBatchRequest(ctx, "capabilities", "", nil, 0, 16*1024)
	if err != nil {
		return nil, err
	}
	return readSmallBatchCapability(raw, s.binding, s.identity.DeviceID, s.identity.BackendIdentity, s.identity.ContractReceiptSHA256)
}

func (s *IsolatedHTTPSession) smallCapabilityMissing(err error, path string) bool {
	var failure *guardedHTTPFailure
	return errors.As(err, &failure) && failure.status == 404 && failure.path == path && failure.binding == s.binding && failure.transportPin == s.transportPin
}

func (s *IsolatedHTTPSession) readSmallJobCapability(ctx context.Context) (*smallBatchCapability, error) {
	for _, command := range []string{"single-request-capabilities", "pipeline-capabilities", "capabilities"} {
		raw, err := s.smallTransferRequest(ctx, "small-jobs", command, "", nil, 0, 16*1024)
		if s.smallCapabilityMissing(err, "small-jobs/"+command) {
			continue
		}
		if err != nil {
			return nil, err
		}
		c, err := readSmallBatchCapability(raw, s.binding, s.identity.DeviceID, s.identity.BackendIdentity, s.identity.ContractReceiptSHA256)
		if err != nil {
			return nil, err
		}
		if !c.executionJob || command == "single-request-capabilities" && !c.singleRequest || command == "pipeline-capabilities" && (c.singleRequest || c.jobs != 2) || command == "capabilities" && (c.singleRequest || c.jobs != 1) {
			return nil, ErrRemoteUnqualified
		}
		return c, nil
	}
	return nil, nil
}
func (s *IsolatedHTTPSession) smallBatchJSON(ctx context.Context, plan *smallBatchPlan, command string) ([]smallBatchItemOutcome, error) {
	if err := s.requireSmallBatch(plan); err != nil {
		return nil, err
	}
	var raw []byte
	var err error
	switch command {
	case "prepare":
		raw, err = plan.prepareBytes()
	case "status":
		if plan.executionJob {
			raw, err = plan.prepareBytes()
		} else {
			raw, err = plan.statusBytes()
		}
	default:
		return nil, syncproto.ErrContract
	}
	if err != nil {
		return nil, err
	}
	s.metadata.Add(int64(len(raw)))
	prefix := "small-batches"
	if plan.executionJob {
		prefix = "small-jobs"
	}
	response, err := s.smallTransferRequest(ctx, prefix, command, "application/json", io.NopCloser(bytes.NewReader(raw)), int64(len(raw)), smallBatchMaximumMetadataBytes)
	if err != nil {
		return nil, err
	}
	return plan.readOutcome(response)
}
func (s *IsolatedHTTPSession) sendSmallBatch(ctx context.Context, plan *smallBatchPlan, aggregate io.ReadSeeker) ([]smallBatchItemOutcome, error) {
	return s.sendSmallTransfer(ctx, plan, aggregate, "data")
}
func (s *IsolatedHTTPSession) sendSmallTransfer(ctx context.Context, plan *smallBatchPlan, aggregate io.ReadSeeker, command string) ([]smallBatchItemOutcome, error) {
	if command != "data" && (command != "execute" || !plan.executionJob) {
		return nil, ErrIdentityConflict
	}
	if err := s.requireSmallBatch(plan); err != nil {
		return nil, err
	}
	stream, err := newSmallBatchStream(ctx, plan, aggregate, func(n int, data bool) {
		if data {
			s.data.Add(int64(n))
		} else {
			s.metadata.Add(int64(n))
		}
	})
	if err != nil {
		return nil, err
	}
	prefix := "small-batches"
	if plan.executionJob {
		prefix = "small-jobs"
	}
	response, err := s.smallTransferRequest(ctx, prefix, command, stream.contentType, stream, stream.length, smallBatchMaximumMetadataBytes)
	if err != nil {
		return nil, err
	}
	if err = stream.finished(); err != nil {
		return nil, err
	}
	return plan.readOutcome(response)
}
