package syncstate

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"pluto/internal/network"
	"pluto/internal/syncproto"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Trusted isolated composition declaration, read from protected local config.
// Receipt identity means the operator qualified this exact own server; it is
// explicitly not a response Boolean or a production capability advertisement.
type IsolatedHTTPConfig struct {
	Domain                     string              `json:"domain"`
	Origin                     string              `json:"origin"`
	AllowedAddresses           []string            `json:"allowed_addresses"`
	Binding                    map[string]any      `json:"binding"`
	DeviceID                   string              `json:"device_id"`
	BackendIdentity            string              `json:"backend_identity"`
	QualificationReceiptSHA256 string              `json:"qualification_receipt_sha256"`
	Token                      string              `json:"token"`
	Features                   []string            `json:"features,omitempty"`
	NameCodec                  string              `json:"name_codec,omitempty"`
	PolicyHash                 string              `json:"policy_hash,omitempty"`
	BandwidthBytesPerSecond    int64               `json:"bandwidth_bytes_per_second,omitempty"`
	Proxy                      network.ProxyConfig `json:"proxy,omitempty"`
}
type HTTPMetrics struct{ Requests, MetadataBytes, DataBytes, ResponseBytes int64 }
type IsolatedHTTPSession struct {
	r                                   *RemoteImport
	root, origin, token                 string
	binding                             RemoteBinding
	identity                            CapturedHTTPIdentity
	transportPin                        string
	rebootstrapRuns                     int
	continuityBlocked                   bool
	client                              *http.Client
	recoveryReader                      func(context.Context) (func(), error)
	mu                                  sync.Mutex
	freshAt                             time.Time
	requests, metadata, data, responses atomic.Int64
	features                            map[string]bool
	streamFileBytes                     int64
	namespace                           map[string]any
	requested                           IsolatedHTTPConfig
	folderMu                            sync.Mutex
	folderFlights                       map[string]*folderFlight
	folderQueue                         []*folderFlight
	folderSending                       bool
	mutationMu                          sync.Mutex
	mutationFlights                     map[string]*mutationFlight
	mutationQueue                       []*mutationFlight
	mutationSending                     bool
	sessionContext                      context.Context
	sessionCancel                       context.CancelFunc
	denied                              atomic.Bool
}

func (s *IsolatedHTTPSession) Metrics() HTTPMetrics {
	return HTTPMetrics{s.requests.Load(), s.metadata.Load(), s.data.Load(), s.responses.Load()}
}

// A refreshed cut can be observed after the scan caller obtained its clock.
// Obtain execution time after Authority; this does not extend proof lifetime.
func (s *IsolatedHTTPSession) ExecutionTime() time.Time { return time.Now() }

// Configure before work, using the existing process-wide reader admission.
func (s *IsolatedHTTPSession) SetRecoveryReader(reader func(context.Context) (func(), error)) {
	s.recoveryReader = reader
}

func NewIsolatedHTTPSession(ctx context.Context, r *RemoteImport, root string, c IsolatedHTTPConfig) (*IsolatedHTTPSession, error) {
	if c.Domain != IsolatedHTTPContract {
		return nil, ErrRemoteUnqualified
	}
	return newHTTPSession(ctx, r, root, c, false)
}
func NewDaemonHTTPSession(ctx context.Context, r *RemoteImport, root string, c IsolatedHTTPConfig) (*IsolatedHTTPSession, error) {
	if c.Domain != DaemonHTTPContract {
		return nil, ErrRemoteUnqualified
	}
	s, e := newHTTPSession(ctx, r, root, c, true)
	if e != nil {
		return nil, e
	}
	s.requested = c
	if e = s.Negotiate(ctx); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func newHTTPSession(ctx context.Context, r *RemoteImport, root string, c IsolatedHTTPConfig, daemon bool) (*IsolatedHTTPSession, error) {
	if r == nil || !validHTTPDomain(c.Domain) || !validHash(c.QualificationReceiptSHA256) || !httpUUID(c.DeviceID) || !validHTTPBackend(c.BackendIdentity) || len(c.Token) == 0 || len(c.Token) > 4096 || strings.ContainsAny(c.Token, "\r\n") || !daemon && len(c.AllowedAddresses) < 1 || len(c.AllowedAddresses) > 4 {
		return nil, ErrRemoteUnqualified
	}
	u, e := url.Parse(c.Origin)
	if e != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" || u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrRemoteUnqualified
	}
	if daemon && u.Scheme != "https" {
		return nil, ErrRemoteUnqualified
	}
	b, e := syncproto.ReadBinding(c.Binding)
	if e != nil {
		return nil, e
	}
	if !httpUUID(b.RootID) || !httpUUID(b.ServerEpoch) || !httpUUID(b.BindingVersion) {
		return nil, ErrRemoteUnqualified
	}
	local, e := r.store.Root(ctx, root)
	if e != nil || local.RemoteRootID != b.RootID || local.ServerIdentity != b.ServerIdentity || local.DeviceID != c.DeviceID {
		return nil, ErrIdentityConflict
	}
	allowed := map[string]bool{}
	for _, a := range c.AllowedAddresses {
		ip := net.ParseIP(a)
		if ip == nil || !daemon && !ip.IsLoopback() && !ip.IsPrivate() {
			return nil, ErrRemoteUnqualified
		}
		allowed[ip.String()] = true
	}
	if e = r.enableHTTPBindings(ctx); e != nil {
		return nil, e
	}
	origin := strings.TrimSuffix(c.Origin, "/")
	identity := CapturedHTTPIdentity{Domain: c.Domain, Origin: origin, DeviceID: c.DeviceID, BackendIdentity: c.BackendIdentity, ContractReceiptSHA256: c.QualificationReceiptSHA256}
	transport := &http.Transport{DisableCompression: true, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 35 * time.Second}
	transport.DialContext, e = guardedDial(u, allowed, daemon, c.Proxy, net.DefaultResolver.LookupIPAddr, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
	if e != nil {
		return nil, e
	}
	sessionContext, sessionCancel := context.WithCancel(ctx)
	return &IsolatedHTTPSession{r: r, root: root, origin: origin, token: c.Token, binding: b, identity: identity, transportPin: httpTransportPin(identity, b, allowed, c.Token), sessionContext: sessionContext, sessionCancel: sessionCancel, requested: c, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (s *IsolatedHTTPSession) Close() {
	if s.sessionCancel != nil {
		s.sessionCancel()
	}
	if t, ok := s.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
func (s *IsolatedHTTPSession) request(ctx context.Context, method, path, kind string, body []byte, metadata int) (result []byte, resultErr error) {
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
	limit := HTTPMetadataBytes
	if path == "directories/batch" || path == "mutations/batch" {
		limit = 4 << 20
	}
	if metadata < 0 || metadata > limit || len(body) > 4+limit+HTTPChunkBytes {
		return nil, ErrSourceQuota
	}
	dataRequest := kind == HTTPFrameType || kind == "application/vnd.saturn.sync-stream.v1"
	dataBytes := int64(0)
	if dataRequest {
		dataBytes = int64(len(body) - metadata - 4)
		if dataBytes < 0 {
			return nil, ErrSourceQuota
		}
		if e := transportResources.pace(ctx, dataBytes, s.requested.BandwidthBytesPerSecond); e != nil {
			return nil, e
		}
	}
	admission, cancelAdmission := context.WithTimeout(ctx, network.ControlTimeout)
	release, e := transportResources.acquire(admission, dataRequest, int64(len(body)))
	cancelAdmission()
	if e != nil {
		return nil, e
	}
	defer release()
	wire := body
	compressed := false
	if kind == "application/json" && len(body) > 16384 && s.features["metadata-gzip-v1"] {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		if _, e := writer.Write(body); e != nil {
			return nil, e
		}
		if e := writer.Close(); e != nil {
			return nil, e
		}
		if buffer.Len() > 4<<20 {
			return nil, ErrSourceQuota
		}
		wire = buffer.Bytes()
		compressed = true
	}
	req, e := http.NewRequestWithContext(ctx, method, s.origin+"/sync/v1/roots/"+s.binding.RootID+"/"+path, bytes.NewReader(wire))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", kind)
	req.Header.Set("Accept", "application/json")
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if s.features["metadata-gzip-v1"] {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	s.requests.Add(1)
	s.metadata.Add(int64(metadata))
	if kind == HTTPFrameType || kind == "application/vnd.saturn.sync-stream.v1" {
		s.data.Add(int64(len(body) - metadata - 4))
	}
	resp, e := network.Do(s.client, req, network.GuardedDeadlines(dataRequest))
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, s.readHTTPFailure(ctx, resp, path)
	}
	if resp.ContentLength > syncproto.MaxBytes {
		return nil, syncproto.ErrLimit
	}
	raw, e := readMetadataResponse(resp.Body, resp.Header.Get("Content-Encoding"), syncproto.MaxBytes, s.features["metadata-gzip-v1"])
	s.responses.Add(int64(len(raw)))
	if e != nil {
		return nil, e
	}
	if len(raw) > syncproto.MaxBytes {
		return nil, syncproto.ErrLimit
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return nil, syncproto.ErrContract
	}
	if _, e = syncproto.Parse(raw); e != nil {
		return nil, e
	}
	return raw, nil
}
func (s *IsolatedHTTPSession) post(ctx context.Context, path string, v any) ([]byte, error) {
	raw, e := httpJSON(v)
	if e != nil {
		return nil, e
	}
	return s.request(ctx, http.MethodPost, path, "application/json", raw, len(raw))
}

// Refresh imports current R through a bounded feed. It never uses a historical
// publication descriptor as current R and performs no per-file HEAD.
func (s *IsolatedHTTPSession) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refresh(ctx)
}
func (s *IsolatedHTTPSession) refresh(ctx context.Context) error {
	// An explicitly failed fresh read cannot leave a prior cached authority in
	// effect. Only a newly completed bounded feed restores the observation time.
	s.freshAt = time.Time{}
	if s.continuityBlocked {
		return ErrHTTPRebootstrapLimit
	}
	for page := 0; page < 8192; page++ {
		c, e := s.r.Candidate(ctx, s.root)
		awaiting := e == nil && c.HTTPRebootstrap != nil && validHTTPCheckpoint(c, s.transportPin) && c.HTTPRebootstrap.Phase == httpBootstrapAwaitFeed
		if e != nil || !c.Valid && !awaiting || c.Binding != s.binding {
			return ErrRemoteUnqualified
		}
		if c.HTTPRebootstrap != nil && (!validHTTPCheckpoint(c, s.transportPin) || c.HTTPRebootstrap.Phase != httpBootstrapAwaitFeed) {
			return ErrRemoteUnqualified
		}
		raw, e := s.readChanges(ctx, c.Cursor)
		if e != nil {
			if s.eligibleRebootstrapFailure(e) {
				s.freshAt = time.Time{}
				return s.rebootstrap(ctx, c, e)
			}
			return e
		}
		feed, e := syncproto.ReadFeed(raw, c.Binding, remoteDecimal(c.Position))
		if e != nil {
			return e
		}
		next, e := s.r.importFeed(ctx, c.RemoteWitness, raw, c.HTTPRebootstrap)
		if e != nil {
			return e
		}
		if !feed.HasMore {
			if e = s.finishRebootstrap(ctx, next); e != nil {
				return e
			}
			s.freshAt = time.Now()
			return nil
		}
	}
	return ErrSourceQuota
}
func (s *IsolatedHTTPSession) Authority(ctx context.Context) (*RemoteAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.continuityBlocked {
		return nil, ErrHTTPRebootstrapLimit
	}
	if s.freshAt.IsZero() || time.Since(s.freshAt) > 10*time.Second {
		if e := s.refresh(ctx); e != nil {
			return nil, e
		}
	}
	c, e := s.r.Candidate(ctx, s.root)
	if e != nil || !c.Valid || c.Binding != s.binding || c.HTTPRebootstrap != nil {
		return nil, ErrRemoteUnqualified
	}
	anchor, e := readJSON[RemoteEntry](ctx, s.r.store.db, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", s.root, c.Generation, c.Binding.RootID)
	if e != nil || anchor.ParentID != "" || anchor.Kind != "folder" || anchor.Presence != "PRESENT" || anchor.Availability != "AVAILABLE" || anchor.RemoteBinding == nil || *anchor.RemoteBinding != s.binding {
		return nil, ErrRemoteUnqualified
	}
	now := time.Now()
	identity := s.identity
	return &RemoteAuthority{witness: c.RemoteWitness, qualifiedAtMS: now.UnixMilli(), expiresMS: now.Add(30 * time.Second).UnixMilli(), transport: &identity}, nil
}

func (s *IsolatedHTTPSession) upload(ctx context.Context, command string, op Operation) (catalogHTTPStatus, error) {
	current, e := s.r.store.Operation(ctx, op.OperationID)
	if e != nil || current.IntentFingerprint != op.IntentFingerprint || current.SealedFingerprint != op.SealedFingerprint {
		return catalogHTTPStatus{}, errors.Join(ErrInvalidReceipt, e)
	}
	op = current
	input, e := originalCatalogInput(op)
	if e != nil {
		return catalogHTTPStatus{}, e
	}
	if op.Captured.Transport.Origin != s.origin {
		return catalogHTTPStatus{}, ErrIdentityConflict
	}
	body := map[string]any{"binding": bindingHTTP(s.binding), "input": input.body}
	if op.HTTPBinding == nil {
		// A lost prepare has no known server UUID. Recover the original key;
		// never pass a locally allocated UUID as the server's originalUploadId.
		command = "prepare"
	} else {
		body["upload_id"] = op.HTTPBinding.ServerUploadID
	}
	raw, e := s.post(ctx, "catalog-uploads/"+command, body)
	if e != nil {
		return catalogHTTPStatus{}, e
	}
	status, e := readCatalogHTTPStatus(raw, op, input)
	if e != nil {
		return catalogHTTPStatus{}, e
	}
	bound, e := s.r.BindHTTPUpload(ctx, op, status.binding.ServerUploadID, input.hash)
	if e != nil {
		return catalogHTTPStatus{}, e
	}
	status.binding = bound.HTTPBinding
	return status, nil
}
func (s *IsolatedHTTPSession) Publish(ctx context.Context, op Operation, reader io.Reader) (CapturedPublication, error) {
	if op.Mutation != nil {
		return s.publishMutation(ctx, op, reader)
	}
	var zero CapturedPublication
	status, e := s.upload(ctx, "prepare", op)
	if e != nil {
		return zero, e
	}
	op.HTTPBinding = status.binding
	if status.publication != nil {
		if _, e = io.CopyN(io.Discard, reader, op.SizeBytes); e != nil {
			return zero, e
		}
		if e = s.Refresh(ctx); e != nil {
			return zero, e
		}
		return *status.publication, nil
	}
	if status.transferPending || status.phase == "physical_pending" || status.phase == "reconciliation_required" || status.phase == "not_published" {
		return zero, ErrArtifactRetained
	}
	if _, e = io.CopyN(io.Discard, reader, status.received); e != nil {
		return zero, e
	}
	input, e := originalCatalogInput(op)
	if e != nil {
		return zero, e
	}
	buffer := make([]byte, HTTPChunkBytes)
	for status.received < op.SizeBytes {
		if status.phase != "transport" {
			return zero, ErrArtifactRetained
		}
		next := min(int64(len(buffer)), op.SizeBytes-status.received)
		if _, e = io.ReadFull(reader, buffer[:next]); e != nil {
			return zero, e
		}
		meta, e := httpJSON(map[string]any{"binding": bindingHTTP(s.binding), "input": input.body, "upload_id": op.HTTPBinding.ServerUploadID, "offset": remoteDecimal(status.received)})
		if e != nil || len(meta) > HTTPMetadataBytes {
			return zero, ErrSourceQuota
		}
		frame := make([]byte, 4+len(meta)+int(next))
		binary.BigEndian.PutUint32(frame, uint32(len(meta)))
		copy(frame[4:], meta)
		copy(frame[4+len(meta):], buffer[:next])
		raw, e := s.request(ctx, http.MethodPatch, "catalog-uploads/append", HTTPFrameType, frame, len(meta))
		if e != nil {
			return zero, e
		}
		updated, e := readCatalogHTTPStatus(raw, op, input)
		if e != nil {
			return zero, e
		}
		if updated.transferPending || updated.received != status.received+next || updated.publication != nil {
			return zero, ErrArtifactRetained
		}
		status = updated
	}
	status, e = s.upload(ctx, "complete", op)
	if e != nil {
		return zero, e
	}
	if status.publication == nil {
		return zero, ErrArtifactRetained
	}
	if e = s.Refresh(ctx); e != nil {
		return zero, e
	}
	return *status.publication, nil
}
func (s *IsolatedHTTPSession) Recover(ctx context.Context, op Operation) (*CapturedPublication, error) {
	if op.Mutation != nil {
		return s.mutation(ctx, op, true)
	}
	status, e := s.upload(ctx, "inspect", op)
	if e != nil {
		return nil, e
	}
	if status.publication == nil && !status.transferPending && (status.phase == "verified" || status.phase == "transport") && status.received == op.SizeBytes {
		status, e = s.upload(ctx, "complete", op)
		if e != nil {
			return nil, e
		}
	}
	if status.publication == nil && !status.transferPending && status.phase == "transport" && status.received < op.SizeBytes {
		if s.recoveryReader == nil {
			return nil, ErrArtifactUnreconciled
		}
		var publication CapturedPublication
		e = s.r.store.artifacts.WithRecoveryReader(ctx, op, s.recoveryReader, func(reader io.Reader) error { var err error; publication, err = s.Publish(ctx, op, reader); return err })
		if e != nil {
			return nil, e
		}
		return &publication, nil
	}
	if status.publication == nil {
		return nil, nil
	}
	if e = s.Refresh(ctx); e != nil {
		return nil, e
	}
	return status.publication, nil
}

// InitializeRemote reads an original persisted snapshot UUID or commits one
// before the first request. On an already imported candidate it refreshes feed.
func (s *IsolatedHTTPSession) InitializeRemote(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.continuityBlocked {
		return ErrHTTPRebootstrapLimit
	}
	if c, e := s.r.Candidate(ctx, s.root); e == nil && c.Valid && c.Binding == s.binding {
		if c.HTTPRebootstrap != nil {
			return s.rebootstrap(ctx, c, nil)
		}
		return s.refresh(ctx)
	} else if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	} else if e == nil && c.HTTPRebootstrap != nil {
		return s.rebootstrap(ctx, c, nil)
	}
	if err := s.retireExpiredInitialImport(ctx); err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		err := s.initializeFirstSnapshot(ctx)
		if !s.expiredRecoveryStart(err) {
			return err
		}
		if attempt != 0 {
			return ErrHTTPRebootstrapLimit
		}
		if err = s.retireExpiredInitialSnapshot(ctx); err != nil {
			return err
		}
	}
	return ErrHTTPRebootstrapLimit
}

func (s *IsolatedHTTPSession) initializeFirstSnapshot(ctx context.Context) error {
	id, e := s.r.pendingHTTPSnapshot(s.binding)
	if e != nil {
		return e
	}
	body := map[string]any{"binding": bindingHTTP(s.binding), "snapshot_id": id}
	progress, e := s.post(ctx, "snapshots/start", body)
	if e != nil {
		return e
	}
	for step := 0; step < 16384; step++ {
		v, e := syncproto.Parse(progress)
		if e != nil {
			return e
		}
		m, e := strictHTTPObject(v, "snapshotId", "state", "startSeq", "appliedSeq", "cutSeq", "entries", "documentBytes")
		if e != nil || m["snapshotId"] != id {
			return ErrIdentityConflict
		}
		for _, k := range []string{"startSeq", "appliedSeq", "entries", "documentBytes"} {
			if _, e := syncproto.Integer64(m[k]); e != nil {
				return e
			}
		}
		if m["state"] == "READY" {
			break
		}
		if m["state"] != "BASE" && m["state"] != "OVERLAY" {
			return ErrRemoteUnqualified
		}
		progress, e = s.post(ctx, "snapshots/step", body)
		if e != nil {
			return e
		}
		if step == 16383 {
			return ErrSourceQuota
		}
	}
	raw, e := s.post(ctx, "snapshots/ready", body)
	if e != nil {
		return e
	}
	snapshot, e := syncproto.ReadSnapshot(raw)
	if e != nil || snapshot.Binding != s.binding || snapshot.SnapshotID != id {
		return ErrIdentityConflict
	}
	root, e := s.r.store.Root(ctx, s.root)
	if e != nil {
		return e
	}
	p, e := s.r.PrepareSnapshot(ctx, s.root, root.TrustGeneration, raw, time.Now())
	if e != nil {
		return e
	}
	for page := 0; !p.Complete && page < 8192; page++ {
		raw, e = s.post(ctx, "entries", map[string]any{"binding": bindingHTTP(s.binding), "cursor": p.Cursor})
		if e != nil {
			return e
		}
		p, e = s.r.ImportSnapshotPage(ctx, s.root, p.Cursor, raw, time.Now())
		if e != nil {
			return e
		}
	}
	if !p.Complete {
		return ErrSourceQuota
	}
	if _, e = s.r.PublishSnapshot(ctx, s.root, p, time.Now()); e != nil {
		return e
	}
	return s.refresh(ctx)
}
