package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"pluto/internal/syncproto"
)

// Actual loopback transport and actual transactional SQLite. Only the server's
// lease/fault behavior is injected; the client does not receive signing secrets.
type rebootstrapHTTPFixture struct {
	f                                   *guardedHTTPFixture
	expire                              int
	status                              int
	code, errorRaw, errorType, losePath string
	wrongBinding, unavailableAnchor     bool
	wrongFeed                           bool
	starts                              []string
	pageSize                            int
	legacySnapshot                      string
	expireStarts                        int
	expireReadPath                      string
}

func (g *rebootstrapHTTPFixture) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/sync/v1/roots/"+g.f.binding.RootID+"/")
	if path != "changes" && path != "entries" && !strings.HasPrefix(path, "snapshots/") {
		g.f.ServeHTTP(w, req)
		return
	}
	g.f.mu.Lock()
	if path == "changes" && g.expire == 0 {
		if g.wrongFeed {
			defer g.f.mu.Unlock()
			c, err := g.f.r.Candidate(req.Context(), "root")
			if err != nil {
				w.WriteHeader(500)
				return
			}
			c.Binding.ServerEpoch = remoteVersion(99998)
			g.f.json(w, jsonRawValue(wireFeed(c.RemoteWitness, nil, "wrong-feed")))
			return
		}
		g.f.mu.Unlock()
		g.f.ServeHTTP(w, req)
		return
	}
	defer g.f.mu.Unlock()
	g.f.requests[path]++
	if req.Header.Get("Authorization") != "Bearer fixture-token" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		w.Write([]byte(`{"code":"cursor_expired"}`))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, HTTPMetadataBytes+1))
	value, parseErr := syncproto.Parse(raw)
	m, ok := value.(map[string]any)
	if err != nil || parseErr != nil || !ok {
		w.WriteHeader(400)
		return
	}
	b, err := syncproto.ReadBinding(m["binding"].(map[string]any))
	if err != nil || b != g.f.binding {
		w.WriteHeader(409)
		return
	}
	if path == "changes" {
		g.expire--
		status := g.status
		if status == 0 {
			status = 410
		}
		code := g.code
		if code == "" {
			code = "cursor_expired"
		}
		contentType := g.errorType
		if contentType == "" {
			contentType = "application/json"
		}
		body := g.errorRaw
		if body == "" {
			body = fmt.Sprintf(`{"code":%q}`, code)
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		w.Write([]byte(body))
		return
	}
	// Historical initializer replays its original initial snapshot UUID.
	if g.legacySnapshot != "" {
		if m["snapshot_id"] != g.legacySnapshot {
			w.WriteHeader(409)
			return
		}
		switch path {
		case "snapshots/start", "snapshots/step":
			g.f.json(w, map[string]any{"snapshotId": g.legacySnapshot, "state": "READY", "startSeq": "0", "appliedSeq": "0", "cutSeq": "0", "entries": "1", "documentBytes": "0"})
		case "snapshots/ready":
			g.f.json(w, jsonRawValue(wireReady(g.f.binding, g.legacySnapshot, "0")))
		default:
			w.WriteHeader(409)
		}
		return
	}
	c, err := g.f.r.Candidate(req.Context(), "root")
	if err != nil || c.HTTPRebootstrap == nil {
		g.f.t.Error("snapshot request without durable recovery checkpoint", err)
		w.WriteHeader(500)
		return
	}
	checkpoint := c.HTTPRebootstrap
	if path == "snapshots/start" || path == "snapshots/step" || path == "snapshots/ready" {
		if m["snapshot_id"] != checkpoint.SnapshotID {
			g.f.t.Error("read snapshot identity reminted")
			w.WriteHeader(409)
			return
		}
	}
	if path == "snapshots/start" {
		g.starts = append(g.starts, checkpoint.SnapshotID)
	}
	expiryPath := g.expireReadPath
	if expiryPath == "" {
		expiryPath = "snapshots/start"
	}
	if path == expiryPath {
		if g.expireStarts > 0 {
			g.expireStarts--
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(410)
			w.Write([]byte(`{"code":"cursor_expired"}`))
			return
		}
	}
	if g.losePath == path {
		g.losePath = ""
		g.f.lose(w)
		return
	}
	switch path {
	case "snapshots/start", "snapshots/step":
		state := "READY"
		if path == "snapshots/start" && expiryPath == "snapshots/step" && g.expireStarts > 0 {
			state = "BASE"
		}
		g.f.json(w, map[string]any{"snapshotId": checkpoint.SnapshotID, "state": state, "startSeq": remoteDecimal(g.f.seq), "appliedSeq": remoteDecimal(g.f.seq), "cutSeq": remoteDecimal(g.f.seq), "entries": remoteDecimal(int64(len(g.f.nodes))), "documentBytes": "0"})
	case "snapshots/ready":
		binding := g.f.binding
		if g.wrongBinding {
			binding.ServerEpoch = remoteVersion(99999)
		}
		g.f.json(w, jsonRawValue(wireReady(binding, checkpoint.SnapshotID, remoteDecimal(g.f.seq))))
	case "entries":
		p, err := g.f.r.Preparation(req.Context(), "root")
		if err != nil || m["cursor"] != p.Cursor {
			g.f.t.Error("nonpersisted page cursor", err)
			w.WriteHeader(409)
			return
		}
		values := make([]syncproto.Descriptor, 0, len(g.f.nodes))
		for _, d := range g.f.nodes {
			if p.AfterNodeID == nil || d.NodeID > *p.AfterNodeID {
				if g.unavailableAnchor && d.NodeID == g.f.binding.RootID {
					d.Availability = "UNKNOWN"
				}
				values = append(values, d)
			}
		}
		sort.Slice(values, func(i, j int) bool { return values[i].NodeID < values[j].NodeID })
		limit := g.pageSize
		if limit == 0 {
			limit = MaxRemotePage
		}
		more := len(values) > limit
		if more {
			values = values[:limit]
		}
		next := "end-" + checkpoint.SnapshotID
		if more {
			next = "after-" + values[len(values)-1].NodeID
		}
		g.f.json(w, jsonRawValue(wirePage(p, values, next, more)))
	default:
		w.WriteHeader(404)
	}
}

func rebootstrapFixture(t *testing.T, files int) (*RemoteImport, *Sources, SourceWitness, *IsolatedHTTPSession, *rebootstrapHTTPFixture, string) {
	t.Helper()
	r, sources, witness, old, f, dir := actualHTTPFixture(t, files)
	old.Close()
	g := &rebootstrapHTTPFixture{f: f}
	server := httptest.NewServer(g)
	t.Cleanup(server.Close)
	s := rebootstrapSession(t, r, old, server.URL, nil)
	if err := s.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	return r, sources, witness, s, g, dir
}

func rebootstrapSession(t *testing.T, r *RemoteImport, old *IsolatedHTTPSession, origin string, alter func(*IsolatedHTTPConfig)) *IsolatedHTTPSession {
	t.Helper()
	config := IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(old.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"}
	if alter != nil {
		alter(&config)
	}
	s, err := NewIsolatedHTTPSession(testContext, r, "root", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.SetRecoveryReader(artifactTestReader)
	return s
}

func retainedRecoveryDigest(t *testing.T, r *RemoteImport) string {
	t.Helper()
	// Complete original intents/receipts/actual ID bindings, B, artifacts and dirty
	// debt must survive observation recovery. R candidate/pages are intentionally
	// omitted, and no subsequent original-publication recovery has run yet.
	var records []string
	for _, query := range []string{
		"SELECT operation_id||'|'||intent_json||'|'||intent_fingerprint||'|'||COALESCE(sealed_fingerprint,'')||'|'||stage||'|'||COALESCE(receipt_json,'')||'|'||COALESCE(http_binding_json,'') FROM operations ORDER BY operation_id",
		"SELECT root_id||'|'||entry_id||'|'||descriptor_json FROM baselines ORDER BY root_id,entry_id",
		"SELECT artifact_id||'|'||phase||'|'||filename||'|'||expected_bytes||'|'||size_bytes||'|'||file_identity||'|'||sha256||'|'||snapshot_id||'|'||COALESCE(operation_id,'')||'|'||capture_json FROM local_artifacts ORDER BY artifact_id",
		"SELECT root_id||'|'||entry_id||'|'||observed_generation||'|'||remote_seq||'|'||reasons FROM dirty_entries ORDER BY root_id,entry_id",
	} {
		rows, err := r.store.db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			records = append(records, raw)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	return fingerprint(records)
}

func TestHTTPRebootstrapExpiredAndGapRetainOriginalAndRecover(t *testing.T) {
	for _, code := range []string{"cursor_expired", "journal_gap", "invalid_cursor"} {
		t.Run(code, func(t *testing.T) {
			r, sources, w, s, g, dir := rebootstrapFixture(t, 1)
			if report, err := runActualHTTPFixture(t, r, w, s); err != nil || report.Uploaded != 1 {
				t.Fatal(report, err)
			}
			if err := os.WriteFile(filepath.Join(dir, "file-000"), []byte("two"), 0600); err != nil {
				t.Fatal(err)
			}
			g.f.lostPrepare = true
			if report, err := runActualHTTPFixture(t, r, w, s); err == nil || report.Failed != 1 {
				t.Fatal(report, err)
			}
			original, err := r.store.PendingPage(testContext, "root", "", 10)
			if err != nil || len(original) != 1 || original[0].HTTPBinding != nil {
				t.Fatal(original, err)
			}
			before := retainedRecoveryDigest(t, r)
			prior, _ := r.Candidate(testContext, "root")
			g.expire, g.code = 1, code
			if code == "journal_gap" {
				g.status = 409
			}
			if code == "invalid_cursor" {
				g.status = 400
			}
			if err = s.Refresh(testContext); err != nil {
				t.Fatal(err)
			}
			after, err := r.Candidate(testContext, "root")
			if err != nil || after.Generation != prior.Generation+1 || after.TrustGeneration != prior.TrustGeneration || !after.Valid || after.HTTPRebootstrap != nil || len(g.starts) != 1 || before != retainedRecoveryDigest(t, r) {
				t.Fatal("observation recovery lost immutable state", prior, after, err)
			}
			if _, err = s.Authority(testContext); err != nil {
				t.Fatal(err)
			}
			if _, err = r.store.artifacts.Reconcile(testContext, artifactTestReader); err != nil {
				t.Fatal(err)
			}
			next, err := sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "after-gap")
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := runActualHTTPFixture(t, r, next, s)
			if err != nil || recovered.Recovered != 1 || recovered.Uploaded != 0 {
				t.Fatal(recovered, err)
			}
			ack, err := r.store.Operation(testContext, original[0].OperationID)
			if err != nil || ack.Stage != "CLIENT_ACKED" || !reflect.DeepEqual(ack.Intent, original[0].Intent) || ack.IntentFingerprint != original[0].IntentFingerprint || ack.SealedFingerprint != original[0].SealedFingerprint || len(g.f.uploads) != 2 {
				t.Fatal("reminted original", ack, err)
			}
		})
	}
}

func TestHTTPRebootstrapStrictErrorsNeverMintSnapshot(t *testing.T) {
	cases := []struct {
		name             string
		status           int
		raw, contentType string
	}{
		{"other410", 410, `{"code":"root_unavailable"}`, "application/json"},
		{"stage410", 410, `{"code":"stage_unavailable"}`, "application/json"},
		{"unauthorized", 401, `{"code":"cursor_expired"}`, "application/json"},
		{"wrongstatus", 409, `{"code":"cursor_expired"}`, "application/json"},
		{"extra", 410, `{"code":"cursor_expired","root":"x"}`, "application/json"},
		{"duplicate", 410, `{"code":"cursor_expired","code":"cursor_expired"}`, "application/json"},
		{"array", 410, `{"code":["cursor_expired"]}`, "application/json"},
		{"empty", 410, `{"code":""}`, "application/json"},
		{"malformed", 410, `{"code":`, "application/json"},
		{"html", 410, `{"code":"cursor_expired"}`, "text/html"},
		{"charset", 410, `{"code":"cursor_expired"}`, "application/json;charset=iso-8859-1"},
		{"oversize", 410, `{"code":"cursor_expired"}` + strings.Repeat(" ", 16384), "application/json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, _, s, g, _ := rebootstrapFixture(t, 0)
			before, _ := r.Candidate(testContext, "root")
			g.expire, g.status, g.errorRaw, g.errorType = 1, tc.status, tc.raw, tc.contentType
			if err := s.Refresh(testContext); err == nil {
				t.Fatal("unqualified error accepted")
			}
			after, _ := r.Candidate(testContext, "root")
			if !reflect.DeepEqual(before, after) || len(g.starts) != 0 {
				t.Fatal("error mutated candidate", before, after)
			}
		})
	}
}

func TestHTTPRebootstrapCommitAndPageFaultsReuseUUIDAfterRealRestart(t *testing.T) {
	for _, point := range []string{"http_rebootstrap.after_commit", "lost-start", "snapshot.before_cursor", "snapshot.before_publish", "http_rebootstrap.before_qualified"} {
		t.Run(point, func(t *testing.T) {
			r, _, w, s, g, _ := rebootstrapFixture(t, 1)
			g.f.lostComplete = true
			if report, err := runActualHTTPFixture(t, r, w, s); err == nil || report.Failed != 1 {
				t.Fatal(report, err)
			}
			pending, _ := r.store.PendingPage(testContext, "root", "", 10)
			before := retainedRecoveryDigest(t, r)
			g.expire = 1
			if point == "lost-start" {
				g.losePath = "snapshots/start"
			} else {
				r.testPoint = func(p string) error {
					if p == point {
						return context.Canceled
					}
					return nil
				}
			}
			if err := s.Refresh(testContext); err == nil {
				t.Fatal("fault not reached", point)
			}
			c, err := r.Candidate(testContext, "root")
			if err != nil || c.HTTPRebootstrap == nil || before != retainedRecoveryDigest(t, r) {
				t.Fatal("state lost", c, err)
			}
			id := c.HTTPRebootstrap.SnapshotID
			if c.Valid {
				t.Fatal("interrupted recovery visible to old reader")
			}
			r.testPoint = nil
			// Do not let cached authority bypass a concurrently persisted checkpoint.
			s.freshAt = time.Now()
			if _, err = s.Authority(testContext); err == nil {
				t.Fatal("cached authority bypassed recovery")
			}
			next, nextW, nextS := restartHTTPBindingFixture(t, r, s, g.f)
			final, err := next.Candidate(testContext, "root")
			if err != nil || !final.Valid || final.HTTPRebootstrap != nil || final.SnapshotID != id || before != retainedRecoveryDigest(t, next) {
				t.Fatal(final, err)
			}
			for _, started := range g.starts {
				if started != id {
					t.Fatal("restart changed read snapshot UUID", g.starts)
				}
			}
			recovered, err := runActualHTTPFixture(t, next, nextW, nextS)
			if err != nil || recovered.Recovered != 1 || recovered.Uploaded != 0 {
				t.Fatal(recovered, err)
			}
			ack, err := next.store.Operation(testContext, pending[0].OperationID)
			if err != nil || ack.Stage != "CLIENT_ACKED" || !reflect.DeepEqual(ack.Intent, pending[0].Intent) || len(g.f.uploads) != 1 {
				t.Fatal(ack, err)
			}
		})
	}
}

func TestHTTPRebootstrapBeforeCommitCASAndTransportDrift(t *testing.T) {
	for _, alter := range []string{"before-commit", "stale", "backend", "receipt", "token", "allowlist"} {
		t.Run(alter, func(t *testing.T) {
			r, _, w, s, g, _ := rebootstrapFixture(t, 1)
			g.f.lostPrepare = true
			if report, err := runActualHTTPFixture(t, r, w, s); err == nil || report.Failed != 1 {
				t.Fatal(report, err)
			}
			before, _ := r.Candidate(testContext, "root")
			digest := retainedRecoveryDigest(t, r)
			cause := s.httpFailure(410, "changes", "application/json", []byte(`{"code":"cursor_expired"}`))
			if alter == "before-commit" {
				r.testPoint = func(p string) error {
					if p == "http_rebootstrap.before_commit" {
						return context.Canceled
					}
					return nil
				}
				if _, err := s.beginHTTPRebootstrap(testContext, before, cause); err == nil {
					t.Fatal("commit fault missed")
				}
				after, _ := r.Candidate(testContext, "root")
				if !reflect.DeepEqual(before, after) {
					t.Fatal("rollback failed")
				}
			} else if alter == "stale" {
				if err := s.Refresh(testContext); err != nil {
					t.Fatal(err)
				}
				if _, err := s.beginHTTPRebootstrap(testContext, before, cause); !errors.Is(err, ErrStaleGeneration) {
					t.Fatal(err)
				}
			} else {
				_, err := s.beginHTTPRebootstrap(testContext, before, cause)
				if err != nil {
					t.Fatal(err)
				}
				changed := rebootstrapSession(t, r, s, s.origin, func(c *IsolatedHTTPConfig) {
					switch alter {
					case "backend":
						c.BackendIdentity = "backend-other"
					case "receipt":
						c.QualificationReceiptSHA256 = hashBytes([]byte("other"))
					case "token":
						c.Token = "wrong"
					case "allowlist":
						c.AllowedAddresses = []string{"127.0.0.1", "127.0.0.2"}
					}
				})
				requests := changed.Metrics()
				if err = changed.InitializeRemote(testContext); err == nil || changed.Metrics() != requests {
					t.Fatal("pin mismatch contacted server", err)
				}
			}
			if digest != retainedRecoveryDigest(t, r) || len(g.starts) != 0 {
				t.Fatal("drift lost retained original")
			}
		})
	}
}

func TestHTTPRebootstrapWrongReadyAnchorAndImmediateExpiryRefuse(t *testing.T) {
	for _, mode := range []string{"wrong-epoch", "unknown-anchor", "wrong-feed", "immediate-expiry", "generic-invalidation"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, s, g, _ := rebootstrapFixture(t, 0)
			before, _ := r.Candidate(testContext, "root")
			g.expire = 1
			switch mode {
			case "wrong-epoch":
				g.wrongBinding = true
			case "unknown-anchor":
				g.unavailableAnchor = true
			case "wrong-feed":
				g.wrongFeed = true
			case "immediate-expiry":
				g.expire = 2
			case "generic-invalidation":
				if err := r.InvalidateRemote(testContext, before.RemoteWitness); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "generic-invalidation" {
				if _, err := r.PrepareSnapshot(testContext, "root", before.TrustGeneration+1, wireReady(before.Binding, remoteVersion(8888), remoteDecimal(before.Position)), time.Now()); err == nil {
					t.Fatal("generic invalidated binding revived")
				}
			} else if err := s.InitializeRemote(testContext); err == nil {
				t.Fatal("invalid recovery qualified", mode)
			} else if mode == "immediate-expiry" && !errors.Is(err, ErrHTTPRebootstrapLimit) {
				t.Fatal(err)
			}
			after, _ := r.Candidate(testContext, "root")
			if mode == "generic-invalidation" {
				if after.HTTPRebootstrap != nil || len(g.starts) != 0 {
					t.Fatal("generic invalidation revived")
				}
			} else if after.HTTPRebootstrap == nil || after.Valid || len(g.starts) != 1 {
				t.Fatal(after, len(g.starts))
			}
			if _, err := s.Authority(testContext); err == nil {
				t.Fatal("invalid authority")
			}
		})
	}
}

func TestHTTPRebootstrapPagedAtomicRAndOldJSON(t *testing.T) {
	r, _, _, s, g, _ := rebootstrapFixture(t, 0)
	old, _ := r.Candidate(testContext, "root")
	g.f.seq = 9007199254740993
	for n := 0; n < 1001; n++ {
		d := folderRemote(remoteVersion(10000+n), g.f.binding.RootID, fmt.Sprintf("directory-%d", n))
		g.f.nodes[d.NodeID] = d
	}
	g.expire = 1
	if err := s.Refresh(testContext); err != nil {
		t.Fatal(err)
	}
	current, _ := r.Candidate(testContext, "root")
	var count int
	if err := r.store.db.QueryRow("SELECT COUNT(*) FROM remote_entries WHERE root_id='root' AND generation=?", current.Generation).Scan(&count); err != nil || count != 1002 {
		t.Fatal(count, err)
	}
	if current.Generation != old.Generation+1 || current.TrustGeneration != old.TrustGeneration || current.Position != 9007199254740993 || g.f.requests["entries"] != 4 {
		t.Fatal(current, g.f.requests)
	}
	raw, err := json.Marshal(current)
	if err != nil || strings.Contains(string(raw), "HTTPRebootstrap") {
		t.Fatal(string(raw), err)
	}
	var legacy RemoteCandidate
	if err = json.Unmarshal(raw, &legacy); err != nil || !reflect.DeepEqual(legacy, current) {
		t.Fatal(legacy, err)
	}
	if _, err = r.Preparation(testContext, "root"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("prepared marker retained after atomic install", err)
	}
}

func TestHTTPRebootstrapExplicitReadFailureInvalidatesCachedAuthority(t *testing.T) {
	r, _, _, s, g, _ := rebootstrapFixture(t, 0)
	before, _ := r.Candidate(testContext, "root")
	if s.freshAt.IsZero() {
		t.Fatal("fixture lacks previously qualified cache")
	}
	g.expire = 2
	g.code = "stage_unavailable"
	requests := s.Metrics().Requests
	if err := s.Refresh(testContext); err == nil {
		t.Fatal("read failure not injected")
	}
	if _, err := s.Authority(testContext); err == nil {
		t.Fatal("cached authority survived explicit remote read failure")
	}
	after, _ := r.Candidate(testContext, "root")
	if before.RemoteWitness != after.RemoteWitness || after.HTTPRebootstrap != nil || len(g.starts) != 0 || s.Metrics().Requests != requests+2 || s.Metrics().DataBytes != 0 {
		t.Fatal("cached-error path changed R or bypassed fresh read", after, s.Metrics())
	}
}
