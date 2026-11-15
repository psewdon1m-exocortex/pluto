//go:build linux

package pluto

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompletionNativeBulkReadbackPauseRestartNoCopies(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("COMPLETION_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	var configs []struct {
		Origin, Authorization, DeviceID, BackendIdentity, Receipt string
		Binding                                                   map[string]any
		Namespace                                                 struct{ Codec, PolicyHash string }
	}
	if err = json.Unmarshal(raw, &configs); err != nil {
		t.Fatal(err)
	}
	c := configs[1]
	host := os.Getenv("COMPLETION_HOST_IP")
	if host == "" {
		t.Fatal("explicit owned host required")
	}
	origin, err := url.Parse(strings.ReplaceAll(c.Origin, "127.0.0.1", host))
	if err != nil {
		t.Fatal(err)
	}
	tier, _ := strconv.Atoi(os.Getenv("ENDURANCE_TIER"))
	var offline, lostReply atomic.Bool
	var completed atomic.Int32
	var faultAfter atomic.Int32
	faultAfter.Store(16)
	var heartbeatProbes atomic.Int32
	var responseMu sync.Mutex
	responseCounts := map[string]int{}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	proxy.ModifyResponse = func(r *http.Response) error {
		if r.StatusCode >= 400 {
			key := fmt.Sprintf("%d %s", r.StatusCode, r.Request.URL.Path)
			responseMu.Lock()
			responseCounts[key]++
			n := responseCounts[key]
			responseMu.Unlock()
			if n <= 3 {
				t.Logf("owned route response: %s occurrence=%d", key, n)
			}
		}
		if tier >= 7 && faultAfter.Load() > 0 && r.StatusCode == 200 && strings.HasSuffix(r.Request.URL.Path, "catalog-uploads/complete") && completed.Add(1) == faultAfter.Load() {
			offline.Store(true)
			lostReply.Store(true)
			return fmt.Errorf("owned fixture lost committed acknowledgement")
		}
		return nil
	}
	f := cNativeWithHandler(t, func(_ http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if offline.Load() {
				http.Error(w, "owned temporary route outage", http.StatusServiceUnavailable)
				return
			}
			if r.URL.Path == "/api/v1/pluto/check-in" {
				// This isolated receiver has guarded routes, not enrolled-device
				// check-in storage. Probe its actual authenticated capability route
				// instead of returning a synthetic success or a permanent 404.
				// A 401/outage still reaches the native connectivity state machine.
				// This does not test production heartbeat persistence/statistics.
				probe := r.Clone(r.Context())
				probe.Method = http.MethodGet
				probe.URL.Path = "/sync/v1/roots/" + c.Binding["root_id"].(string) + "/capabilities"
				probe.URL.RawPath = ""
				probe.Body = nil
				probe.ContentLength = 0
				probe.TransferEncoding = nil
				probe.Header.Del("Content-Length")
				heartbeatProbes.Add(1)
				proxy.ServeHTTP(w, probe)
				return
			}
			proxy.ServeHTTP(w, r)
		})
	})
	retainedRepair := os.Getenv("COMPLETION_REUSE_BASE") != ""
	if !retainedRepair {
		f.source = filepath.Join(f.base, "bulk-"+strconv.FormatInt(time.Now().UnixNano(), 10))
		if err = os.Mkdir(f.source, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.cfg.Sources = []string{f.source}
	f.cfg.Indexed.Profile.Sources[0].SelectedPath = f.source
	f.cfg.AccessToken = strings.TrimPrefix(c.Authorization, "Bearer ")
	f.cfg.Indexed.Policy.Codec = c.Namespace.Codec
	remote := &f.cfg.Indexed.Profile.Remote
	remote.Binding = c.Binding
	remote.DeviceID = c.DeviceID
	remote.BackendIdentity = c.BackendIdentity
	remote.QualificationReceiptSHA256 = c.Receipt
	remote.NameCodec = c.Namespace.Codec
	remote.PolicyHash = c.Namespace.PolicyHash
	if err = SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	count, _ := strconv.Atoi(os.Getenv("ENDURANCE_SYNC_FILES"))
	if count < 8 {
		count = 32
	}
	if count > 4096 {
		t.Fatal("owned dataset limit")
	}
	expected := map[string]string{}
	t.Cleanup(func() {
		if t.Failed() {
			inputs := map[string][]byte{}
			_ = filepath.WalkDir(f.source, func(p string, d os.DirEntry, e error) error {
				if e == nil && !d.IsDir() {
					rel, _ := filepath.Rel(f.source, p)
					inputs[filepath.ToSlash(rel)], _ = os.ReadFile(p)
				}
				return e
			})
			evidence, _ := json.MarshalIndent(map[string]any{"expected": expected, "retainedInputs": inputs}, "", "  ")
			_ = os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "pluto-bulk-failure-inputs.json"), evidence, 0600)
		}
	})
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	write := func(name string, b []byte) {
		t.Helper()
		p := filepath.Join(f.source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if retainedRepair {
			// Initial failed fixtures must resume the exact originals, not be
			// rewritten with new timestamps or rebuilt under a new source path.
			existing, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(existing, b) {
				t.Fatalf("retained original differs before repair: %s (%v)", name, err)
			}
		} else if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		expected[name] = hash(b)
	}
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("дерево-%d/level/файл-%05d.bin", i%8, i)
		if i == 0 {
			name = "example.md"
		}
		if i == 1 {
			name = "example (2).md"
		}
		b := []byte(fmt.Sprintf("%05d: native deterministic bytes", i))
		if i == 2 {
			b = nil
		}
		write(name, b)
	}
	if err = os.MkdirAll(filepath.Join(f.source, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Path, ID, Version, Sha256, CatalogSha256, CatalogSize string
		Size                                                  int64
		VersionCount                                          int
	}
	type snapshot struct {
		Files   []entry
		Folders []string
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	readbackMode := func(metadataOnly bool) snapshot {
		t.Helper()
		// Pluto preserves the selected source path below its backup root.
		input, _ := json.Marshal(map[string]any{"kind": "pluto", "folder": strings.TrimLeft(filepath.ToSlash(f.source), "/"), "metadataOnly": metadataOnly})
		r, e := client.Post(origin.String()+"__completion/readback", "application/json", bytes.NewReader(input))
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		var s snapshot
		if r.StatusCode != 200 {
			b, _ := io.ReadAll(r.Body)
			t.Fatalf("readback %d %s", r.StatusCode, b)
		}
		if e = json.NewDecoder(r.Body).Decode(&s); e != nil {
			t.Fatal(e)
		}
		return s
	}
	readback := func() snapshot { return readbackMode(false) }
	var dependencySeq int64
	lastDependencyCheck := time.Time{}
	respectDependency := func(deadline time.Time) time.Time {
		proofPath := os.Getenv("COMPLETION_DEPENDENCY_PROGRESS")
		if proofPath == "" || time.Since(lastDependencyCheck) < 5*time.Second {
			return deadline
		}
		lastDependencyCheck = time.Now()
		var proof struct {
			At           time.Time `json:"at"`
			RootID       string    `json:"rootId"`
			PublishedSeq int64     `json:"publishedSeq"`
		}
		b, e := os.ReadFile(proofPath)
		if e != nil || json.Unmarshal(b, &proof) != nil || time.Since(proof.At) < 0 || time.Since(proof.At) >= 20*time.Second || proof.RootID != c.Binding["root_id"] || proof.PublishedSeq <= dependencySeq {
			return deadline
		}
		dependencySeq = proof.PublishedSeq
		message := f.status().Observation.Error
		if strings.Contains(message, "HTTP status 409 (reconciliation_required)") || strings.Contains(message, "HTTP status 429 (admission_full)") {
			t.Logf("shared-root admission queued: own committed=%d; dependency published_seq=%d", completed.Load(), proof.PublishedSeq)
			return time.Now().Add(5 * time.Minute)
		}
		return deadline
	}
	// A retained durable retry may deliberately wait fifteen minutes after
	// repeated transient failures. Respect its original deadline without
	// changing attempts, source generations, or the retry policy itself.
	respectRetry := func(deadline time.Time) time.Time {
		dbPath := filepath.Join(f.state, "indexed", "sync-state.sqlite")
		u := url.URL{Scheme: "file", Path: dbPath}
		u.RawQuery = "mode=ro"
		db, e := sql.Open("sqlite", u.String())
		if e != nil {
			return deadline
		}
		defer db.Close()
		var next sql.NullInt64
		e = db.QueryRow("SELECT MIN(next_ms) FROM operation_retry WHERE next_ms>?", time.Now().UnixMilli()).Scan(&next)
		if e != nil || !next.Valid {
			return deadline
		}
		at := time.UnixMilli(next.Int64)
		if at.After(time.Now().Add(16 * time.Minute)) {
			return deadline
		}
		if candidate := at.Add(5 * time.Minute); candidate.After(deadline) {
			t.Logf("respect original durable retry: next=%s; no counter reset", at.UTC().Format(time.RFC3339Nano))
			return candidate
		}
		return deadline
	}
	local := func() {
		t.Helper()
		actual := map[string]string{}
		err := filepath.WalkDir(f.source, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if !d.IsDir() {
				b, e := os.ReadFile(p)
				if e != nil {
					return e
				}
				rel, _ := filepath.Rel(f.source, p)
				actual[filepath.ToSlash(rel)] = hash(b)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(expected)
		if !bytes.Equal(a, b) {
			t.Fatalf("unexpected local mutation: count %d != %d", len(actual), len(expected))
		}
	}
	converge := func(stage string) snapshot {
		t.Helper()
		deadline := time.Now().Add(5 * time.Minute)
		last := -1
		lastStatus := ""
		for {
			status, _ := json.Marshal(f.status())
			var observation Status
			_ = json.Unmarshal(status, &observation)
			key := observation.Observation.Error
			if key != "" && key != lastStatus {
				lastStatus = key
				log, e := os.OpenFile(filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "pluto-bulk-status-errors.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if e == nil {
					_, _ = log.Write(append(status, '\n'))
					_ = log.Close()
				}
			}
			s := readbackMode(true)
			matched := 0
			for _, e := range s.Files {
				if expected[e.Path] == e.CatalogSha256 {
					matched++
				}
			}
			if matched == len(expected) && len(s.Files) == len(expected) {
				// Poll catalog convergence cheaply, then verify every physical
				// backend byte once. Metadata alone never grants success.
				full := readback()
				if len(full.Files) != len(expected) {
					t.Fatal("full readback count differs")
				}
				for _, e := range full.Files {
					if expected[e.Path] != e.Sha256 || e.Sha256 != e.CatalogSha256 || strconv.FormatInt(e.Size, 10) != e.CatalogSize {
						t.Fatalf("independent readback mismatch: %s", e.Path)
					}
				}
				local()
				return full
			}
			if matched != last {
				t.Logf("%s confirmed=%d/%d", stage, matched, len(expected))
				if matched > last {
					deadline = time.Now().Add(5 * time.Minute)
				}
				last = matched
			}
			deadline = respectDependency(deadline)
			if time.Now().After(deadline) {
				deadline = respectRetry(deadline)
				if time.Now().Before(deadline) {
					continue
				}
				status, _ := json.Marshal(f.status().Observation)
				_ = os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "pluto-bulk-timeout-status.json"), status, 0600)
				t.Fatalf("%s no convergence, %d/%d", stage, matched, len(expected))
			}
			time.Sleep(time.Second)
		}
	}
	if retainedRepair && tier >= 7 {
		// A retained run may already have published every original before its
		// later pause/restart assertion failed. Requiring sixteen NEW completes
		// would incorrectly demand duplicate publications from a correct client.
		// This observation only sizes the fault barrier. Full physical SHA and
		// original version-count checks below still decide correctness.
		prior := readbackMode(true)
		seen := map[string]bool{}
		for _, e := range prior.Files {
			if e.CatalogSha256 == expected[e.Path] && !seen[e.Path] {
				seen[e.Path] = true
			}
		}
		faultAfter.Store(int32(min(16, len(expected)-len(seen))))
		t.Logf("retained publication barrier: already present=%d; new commits before fault=%d; no prior fault claimed for this attempt", len(seen), faultAfter.Load())
	}
	bulkBackup := qualifyNativeBulkCheckpoint(t, f, origin.String())
	stop := f.start()
	if tier >= 7 && faultAfter.Load() > 0 {
		// Forty-five seconds is a control-listener startup bound, not a valid
		// deadline for sixteen publications across twenty concurrent jobs.
		// Bound lack of useful publication progress instead of total duration.
		deadline, last := time.Now().Add(5*time.Minute), int32(-1)
		for !lostReply.Load() {
			if n := completed.Load(); n > last {
				last = n
				deadline = time.Now().Add(5 * time.Minute)
				t.Logf("fault barrier committed=%d/%d", n, faultAfter.Load())
			}
			// Other admitted writers can legitimately close the shared root's
			// snapshot gate. Only a fresh, independently observed publication
			// increase may extend the wait, and only for that exact refusal.
			// A clock heartbeat or an unrelated network error is not progress.
			deadline = respectDependency(deadline)
			if time.Now().After(deadline) {
				deadline = respectRetry(deadline)
				if time.Now().Before(deadline) {
					continue
				}
				t.Fatalf("lost-ACK barrier made no publication progress for five minutes: %d/%d", last, faultAfter.Load())
			}
			time.Sleep(100 * time.Millisecond)
		}
		before, _ := json.MarshalIndent(f.status().Observation, "", "  ")
		_ = os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "pluto-bulk-offline-status.json"), before, 0600)
		stop(true)
		local()
		stop = f.start()
		offline.Store(false) // No file-system event: recovery must use durable work.
		t.Log("committed ACK lost during bulk; native daemon crashed offline, restarted, route restored")
	}
	initial := converge("initial")
	retainedRepair = false // Later deliberate test edits are now permitted.
	initialEvidence, _ := json.MarshalIndent(initial, "", "  ")
	_ = os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "pluto-bulk-initial.json"), initialEvidence, 0600)
	for _, e := range initial.Files {
		if e.VersionCount != 1 {
			t.Fatalf("initial/recovered file %s has %d publications", e.Path, e.VersionCount)
		}
	}
	if raw, err = f.command("pause"); err != nil {
		t.Fatal(string(raw), err)
	}
	cAwait(t, func() bool { return !f.status().Running })
	if raw, err = f.command("resume"); err != nil {
		t.Fatal(string(raw), err)
	}
	// A retained 60-second schedule plus a large recovery scan can exceed a
	// blanket 100-second wait. Bound lack of actual progress instead; never use
	// elapsed time or a periodic status response as evidence of useful work.
	awaitObserving := func(stage string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Minute)
		var mostRead, mostCaptured, mostRecovered int64
		lastLog := time.Time{}
		for {
			s := f.status()
			e := s.Observation.Engine
			if s.Running && e != nil && e.Phase == "observing" {
				return
			}
			if e != nil {
				if e.Capture.SourceReads > mostRead || e.Captured > mostCaptured || e.Recovered > mostRecovered {
					mostRead = max(mostRead, e.Capture.SourceReads)
					mostCaptured = max(mostCaptured, e.Captured)
					mostRecovered = max(mostRecovered, e.Recovered)
					deadline = time.Now().Add(5 * time.Minute)
					if time.Since(lastLog) >= 15*time.Second {
						t.Logf("%s phase=%s reads=%d captured=%d recovered=%d", stage, e.Phase, mostRead, mostCaptured, mostRecovered)
						lastLog = time.Now()
					}
				}
			}
			deadline = respectDependency(deadline)
			if time.Now().After(deadline) {
				deadline = respectRetry(deadline)
				if time.Now().Before(deadline) {
					continue
				}
				raw, _ := json.MarshalIndent(s, "", "  ")
				_ = os.WriteFile(filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "pluto-bulk-"+stage+"-timeout.json"), raw, 0600)
				t.Fatalf("%s no progress for five minutes: %s", stage, raw)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	awaitObserving("same-process-resume")
	sameProcess := readback()
	initialJSON, _ := json.Marshal(initial)
	sameProcessJSON, _ := json.Marshal(sameProcess)
	if !bytes.Equal(initialJSON, sameProcessJSON) {
		t.Fatal("same-process resume changed remote versions")
	}
	if raw, err = f.command("pause"); err != nil {
		t.Fatal(string(raw), err)
	}
	stop(false)
	stop = f.start()
	if s := f.status(); s.Observation.Enabled {
		t.Fatal("pause lost across restart")
	}
	local()
	if raw, err = f.command("resume"); err != nil {
		t.Fatal(string(raw), err)
	}
	awaitObserving("restart-resume")
	unchanged := readback()
	a, _ := json.Marshal(initial)
	b, _ := json.Marshal(unchanged)
	if !bytes.Equal(a, b) {
		t.Fatal("no-change restart changed remote versions")
	}
	local()
	write("example.md", []byte("edited after pause restart"))
	final := converge("edited")
	stop(false)
	bulkBackup.recordFinal(t, f, expected, lostReply.Load(), count)
	out := filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "pluto-bulk.json")
	evidence, _ := json.MarshalIndent(map[string]any{"status": "PASS", "count": count, "initial": initial, "final": final, "localManifest": expected, "pauseRestart": true, "pauseResumeSameProcess": true, "bulkLostAckCrashRecovery": tier >= 7 && lostReply.Load(), "fixtureHeartbeatCapabilityProbes": heartbeatProbes.Load(), "heartbeatLimitation": "Connectivity/authentication uses actual guarded capabilities; production check-in persistence/statistics are not exercised by this fixture."}, "", "  ")
	if err = os.WriteFile(out, evidence, 0600); err != nil {
		t.Fatal(err)
	}
}
