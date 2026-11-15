package syncstate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"pluto/internal/syncproto"
	"strings"
	"testing"
	"time"
)

func TestCompletionActualSaturnCallers(t *testing.T) { completionActualSaturn(t, "", "") }
func TestCompletionActualSaturnRecovery(t *testing.T) {
	for _, phase := range []string{"mutations/batch", "stream-uploads/prepare", "stream-uploads/chunk", "stream-uploads/seal"} {
		t.Run(strings.ReplaceAll(phase, "/", "-"), func(t *testing.T) { completionActualSaturn(t, phase, "lost-ack-offline") })
	}
}
func completionActualSaturn(t *testing.T, faultTail, faultKind string) {
	file := os.Getenv("COMPLETION_CONFIG")
	if file == "" {
		t.Fatal("COMPLETION_CONFIG must identify own live API fixture")
	}
	rawConfig, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var configs []struct {
		Origin, FaultOrigin, BackendIdentity, Receipt, Authorization, DeviceID string
		Binding                                                                map[string]any
		Namespace                                                              struct{ Codec, PolicyHash string }
	}
	if err = json.Unmarshal(rawConfig, &configs); err != nil {
		t.Fatal(err)
	}
	c := configs[1]
	// The runner supplies its owned Windows gateway; preserve the WSL default.
	host := os.Getenv("COMPLETION_HOST_IP")
	if host == "" {
		host = "172.18.48.1"
	}
	c.Origin = strings.Replace(c.Origin, "127.0.0.1", host, 1)
	c.FaultOrigin = strings.Replace(c.FaultOrigin, "127.0.0.1", host, 1)
	work := t.TempDir()
	selected, err := NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, selected, "nested")
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	emptyCount := 40
	if faultTail != "" {
		emptyCount = 8
	}
	for n := 0; n < emptyCount; n++ {
		if err = os.WriteFile(filepath.Join(dir, fmt.Sprintf("empty-%03d.md", n)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data := make([]byte, 2*StreamChunkBytes+17)
	for n := range data {
		data[n] = byte(n % 251)
	}
	if err = os.WriteFile(filepath.Join(dir, "stream.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(testContext, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := store.Close(); e != nil {
			t.Error(e)
		}
	})
	sources, err := store.EnableSources(testContext, DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	set, err := sources.BindSourceSet(testContext, "set", hashBytes([]byte("completion")), 0, []SourceSpec{{ID: "source", SelectedPath: selected, WorkingDirectory: work}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := syncproto.ReadBinding(c.Binding)
	if err != nil {
		t.Fatal(err)
	}
	binding := RemoteBinding(wire)
	root := RootBinding{RootID: "root", MappingID: "mapping", ServerIdentity: binding.ServerIdentity, RemoteRootID: binding.RootID, DeviceID: c.DeviceID, SourceIdentity: "set"}
	if err = store.BindRoot(testContext, root); err != nil {
		t.Fatal(err)
	}
	if err = sources.AttachSourceSet(testContext, set.ID, set.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	w, err := sources.BeginSourceOwner(testContext, set.ID, set.Revision, "owner")
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	r, err := store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: c.Origin, AllowedAddresses: []string{host}, Binding: c.Binding, DeviceID: c.DeviceID, BackendIdentity: c.BackendIdentity, QualificationReceiptSHA256: c.Receipt, Token: strings.TrimPrefix(c.Authorization, "Bearer "), Features: []string{"namespace-mutations-v1", "folder-batch-v1", "stream-upload-v1", "metadata-gzip-v1", "changes-wait-v1"}, NameCodec: c.Namespace.Codec, PolicyHash: c.Namespace.PolicyHash})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.SetRecoveryReader(artifactTestReader)
	if err = s.Negotiate(testContext); err != nil {
		t.Fatal("capability", err)
	}
	if err = s.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Dir(store.filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err = r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	run := func() (CapturedScanReport, error) {
		return r.RunCapturedScan(testContext, CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: s, AcquireRecovery: artifactTestReader, AcquireStream: artifactTestReader, Capture: func(ctx context.Context, w SourceWitness, e SourceEntry) (*VerifiedSnapshot, error) {
			return CaptureGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
		}})
	}
	if err = store.CheckPolicy(testContext, "root", c.Namespace.Codec, c.Namespace.PolicyHash, 1, []byte(`{}`)); err != nil {
		t.Fatal("policy", err)
	}
	control := func(endpoint string, body any) {
		raw, _ := json.Marshal(body)
		resp, e := http.Post(c.FaultOrigin+"__completion/"+endpoint, "application/json", bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
	}
	if faultTail != "" {
		control("fault", map[string]any{"tail": faultTail, "kind": faultKind})
		t.Cleanup(func() { control("restore", map[string]any{}) })
	}
	traceCount := func() []struct {
		Path, Fault string
		Status      int
	} {
		resp, e := http.Get(c.FaultOrigin + "__completion/trace")
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		var rows []struct {
			Path, Fault string
			Status      int
		}
		if e = json.NewDecoder(resp.Body).Decode(&rows); e != nil {
			t.Fatal(e)
		}
		return rows
	}
	beforeTrace := len(traceCount())
	restored := false
	var originals map[string]string
	var first CapturedScanReport
	var attempts []CapturedScanReport
	for n := 0; n < 30; n++ {
		first, err = run()
		attempts = append(attempts, first)
		observed := false
		if faultTail != "" && !restored {
			for _, row := range traceCount()[beforeTrace:] {
				if strings.HasSuffix(row.Path, faultTail) && row.Fault == faultKind && row.Status == 200 {
					observed = true
				}
			}
		}
		if observed {
			restored = true
			originals = map[string]string{}
			rows, e := store.db.Query("SELECT operation_id,intent_fingerprint FROM operations WHERE stage<>'CLIENT_ACKED'")
			if e != nil {
				t.Fatal(e)
			}
			for rows.Next() {
				var id, h string
				if e = rows.Scan(&id, &h); e != nil {
					t.Fatal(e)
				}
				originals[id] = h
			}
			rows.Close()
			if len(originals) == 0 {
				t.Fatal("fault left no durable original")
			}
			s.Close()
			control("restore", map[string]any{})
			s, e = NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: c.Origin, AllowedAddresses: []string{host}, Binding: c.Binding, DeviceID: c.DeviceID, BackendIdentity: c.BackendIdentity, QualificationReceiptSHA256: c.Receipt, Token: strings.TrimPrefix(c.Authorization, "Bearer "), Features: []string{"namespace-mutations-v1", "folder-batch-v1", "stream-upload-v1", "metadata-gzip-v1", "changes-wait-v1"}, NameCodec: c.Namespace.Codec, PolicyHash: c.Namespace.PolicyHash})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(s.Close)
			s.SetRecoveryReader(artifactTestReader)
			if e = s.Negotiate(testContext); e != nil {
				t.Fatal(e)
			}
			if e = s.InitializeRemote(testContext); e != nil {
				t.Fatal("reopen authority", e)
			}
		}
		if err == nil && first.Complete && (faultTail == "" || restored) {
			break
		}
		if n == 29 {
			t.Fatal("recovery did not converge", first, err)
		}
		// Respect durable retry scheduling; never rewrite the stored deadline.
		time.Sleep(time.Second)
	}
	var acknowledged int
	if err = store.db.QueryRow("SELECT count(*) FROM operations WHERE kind IN('PUT','STREAM_PUT') AND stage='CLIENT_ACKED'").Scan(&acknowledged); err != nil || acknowledged != emptyCount+1 {
		t.Fatal(acknowledged, err)
	}
	before := s.Metrics()
	second, err := run()
	if err != nil || second.Adopted != int64(emptyCount+1) {
		t.Fatal("repeat", second, err)
	}
	if s.Metrics().DataBytes != before.DataBytes {
		t.Fatal("unchanged bytes resent")
	}
	state, err := store.PreviewAdoption(testContext, root, binding, s.identity, c.Namespace.Codec, false)
	if err != nil || state.Pending != 0 || !state.Compatible {
		t.Fatal("adoption fence", state, err)
	}
	if faultTail == "stream-uploads/seal" {
		for _, kind := range []string{"407", "429"} {
			control("fault", map[string]any{"tail": "changes", "kind": kind})
			err = s.Refresh(testContext)
			if err == nil {
				t.Fatal("injected control failure accepted", kind)
			}
			expected := 407
			if kind == "429" {
				expected = 429
			}
			if HTTPStatus(err) != expected {
				t.Fatal("status lost", kind, err)
			}
			if err = s.Refresh(testContext); err != nil {
				t.Fatal("route restoration", err)
			}
		}
		requests := s.Metrics().Requests
		control("fault", map[string]any{"tail": "changes", "kind": "close"})
		if err = s.Refresh(testContext); err != nil || s.Metrics().Requests != requests+2 {
			t.Fatal("read did not recover through one bounded retry", s.Metrics().Requests-requests, err)
		}
		requests = s.Metrics().Requests
		control("fault", map[string]any{"tail": "changes", "kind": "close", "count": 3})
		if err = s.Refresh(testContext); err == nil || s.Metrics().Requests != requests+3 {
			t.Fatal("exhausted read retry was not bounded", s.Metrics().Requests-requests, err)
		}
		if err = s.Refresh(testContext); err != nil {
			t.Fatal("route restoration after exhausted retry", err)
		}
		control("fault", map[string]any{"tail": "changes", "kind": "slow", "milliseconds": 100})
		if err = s.Refresh(testContext); err != nil {
			t.Fatal("progress response", err)
		}
		// Guarded control has a 45s whole-request budget and the production
		// HTTP transport has a tighter 35s response-header timeout.
		control("fault", map[string]any{"tail": "changes", "kind": "stall", "milliseconds": 40000})
		started := time.Now()
		requests = s.Metrics().Requests
		err = s.Refresh(testContext)
		if err != nil || s.Metrics().Requests != requests+2 || time.Since(started) < 34*time.Second || time.Since(started) > 39*time.Second {
			t.Fatal("control response-header deadline", time.Since(started), err)
		}
		if err = s.Refresh(testContext); err != nil {
			t.Fatal("pool after stall", err)
		}
		started = time.Now()
		if err = s.WaitChanges(testContext); err != nil {
			t.Fatal("actual long poll", err)
		}
		if time.Since(started) < 24*time.Second || time.Since(started) > 44*time.Second {
			t.Fatal("long poll budget", time.Since(started))
		}
	}
	for id, h := range originals {
		var got, stage string
		if e := store.db.QueryRow("SELECT intent_fingerprint,stage FROM operations WHERE operation_id=?", id).Scan(&got, &stage); e != nil || got != h || stage != "CLIENT_ACKED" {
			t.Fatal("original changed or unacknowledged", id, stage, e)
		}
	}
	result, _ := json.MarshalIndent(map[string]any{"first": first, "attempts": attempts, "second": second, "metrics": s.Metrics(), "adoption": state}, "", "  ")
	if err = os.WriteFile(filepath.Join(filepath.Dir(file), "pluto-interop-"+strings.ReplaceAll(faultTail, "/", "-")+".json"), result, 0600); err != nil {
		t.Fatal(err)
	}
}
