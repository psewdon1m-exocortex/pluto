package syncstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type engineCLIResult struct {
	OK        bool               `json:"ok"`
	Error     string             `json:"error"`
	Report    CapturedScanReport `json:"report"`
	Capture   CaptureMetrics     `json:"capture"`
	Resources struct {
		ActiveDataJobs, ActiveSourceReaders, ActiveEnumerations  int
		SpoolReservedBytes, RetainedBytes, MetadataReservedBytes int64
	} `json:"batch_resources"`
}

// A real child CLI owns the SQLite writer, capture pipeline and global process
// budget. The receiver sees original intents only through a read-only DB handle.
// This loopback fixture is deliberately separate from Saturn/PG/SFTP acceptance.
func TestSmallBatchEngineActualCLIProcessesMixedAndLostReply(t *testing.T) {
	binary := os.Getenv("PLUTO_BATCH_ENGINE_CLI")
	if binary == "" {
		t.Skip("requires the frozen current CLI executable")
	}
	for _, scenario := range []string{"normal", "lost", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			lost := scenario != "normal"
			sizes := []int{0, 1, 1024, 262144, 262145}
			if lost {
				sizes = []int{0, 1, 7, 1024}
			}
			r, _, _, old, base, dir := actualHTTPFixture(t, len(sizes))
			old.Close()
			for n, size := range sizes {
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%03d", n)), bytes.Repeat([]byte{byte(n + 1)}, size), 0600); err != nil {
					t.Fatal(err)
				}
			}
			work := filepath.Dir(filepath.Dir(dir))
			specs := []SourceSpec{{ID: "source", SelectedPath: "tree", WorkingDirectory: work}}
			if _, err := r.store.db.Exec("UPDATE source_sets SET config_digest=? WHERE set_id='set'", hashBytes(mustJSON(specs))); err != nil {
				t.Fatal(err)
			}
			state := filepath.Dir(r.store.filename)
			if err := os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
			if err := r.store.Close(); err != nil {
				t.Fatal(err)
			}
			u := url.URL{Scheme: "file", Path: filepath.Join(state, "sync-state.sqlite")}
			reader, err := sql.Open("sqlite", u.String()+"?mode=ro")
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			reader.SetMaxOpenConns(1)
			r.store = &Store{db: reader, filename: filepath.Join(state, "sync-state.sqlite")}
			r.store.batches = &smallBatchArtifacts{state: &smallBatchStore{remote: r}}
			f := &dispatchHTTPFixture{base: base, session: &IsolatedHTTPSession{r: r, binding: base.binding, identity: old.identity}, groups: map[string]*smallBatchPlan{}, calls: map[string]int{}, sent: map[string]int{}, loseData: lost}
			server := httptest.NewServer(f)
			defer server.Close()
			cfg := map[string]any{"schema": "pluto.copy-indexed-isolated/v1", "local_root_id": "root", "mapping_id": "mapping", "source_set_id": "set", "small_batch_mode": "bulk", "sources": []any{map[string]any{"id": "source", "selected_path": "tree", "working_directory": work}}, "remote": IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: server.URL, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(base.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"}}
			configPath := filepath.Join(nativeFixtureTempDir(t), "config.json")
			if err = os.WriteFile(configPath, mustJSON(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			checkpoint := qualifyEngineCLIFixtureBackup(t, r, f, old, configPath, state, filepath.Join(work, "tree"), scenario, sizes)
			run := func(phase string, fail bool) engineCLIResult {
				t.Helper()
				ctx, cancel := context.WithTimeout(testContext, 40*time.Second)
				defer cancel()
				owned := runNativeFixtureCLI(t, ctx, "batch-current", binary, configPath, state)
				if owned.LifecycleError != nil {
					t.Fatal(phase, owned.LifecycleError)
				}
				output, e := owned.Stdout, owned.DomainError
				var result engineCLIResult
				if err := json.Unmarshal(output, &result); err != nil || (e != nil) != fail || result.OK == fail {
					t.Fatal(phase, string(output), string(owned.Stderr), e, err)
				}
				if result.Resources.ActiveDataJobs != 0 || result.Resources.ActiveSourceReaders != 0 || result.Resources.ActiveEnumerations != 0 || result.Resources.SpoolReservedBytes != 0 || result.Resources.MetadataReservedBytes != 0 || !fail && result.Resources.RetainedBytes != 0 {
					t.Fatal("unjoined CLI resources", phase, result.Resources)
				}
				t.Logf("actual CLI pid=%d phase=%s captured=%d uploaded=%d recovered=%d retained=%d", owned.PID, phase, result.Capture.SourceReads, result.Report.Uploaded, result.Report.Recovered, result.Resources.RetainedBytes)
				checkpoint.recordResult(t, r, f, phase, owned, result)
				return result
			}
			first := run("initial", lost)
			if first.Capture.SourceReads != int64(len(sizes)) {
				t.Fatal(first)
			}
			if lost {
				originals, e := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
				if e != nil || len(originals) != 4 {
					t.Fatal(originals, e)
				}
				if scenario == "disabled" {
					delete(cfg, "small_batch_mode")
					if err = os.WriteFile(configPath, mustJSON(cfg), 0600); err != nil {
						t.Fatal(err)
					}
				}
				recovered := run("recovery", false)
				if recovered.Capture.SourceReads != 0 || recovered.Report.Recovered != 4 || recovered.Report.Uploaded != 0 {
					t.Fatal(recovered)
				}
				for _, op := range originals {
					current, e := r.store.Operation(testContext, op.OperationID)
					if e != nil || current.Stage != "CLIENT_ACKED" || current.LocalGeneration != op.LocalGeneration || current.SealedFingerprint != op.SealedFingerprint || current.IntentFingerprint != op.IntentFingerprint {
						t.Fatal(current.Stage, e)
					}
				}
			} else if first.Report.Uploaded != 5 || first.Capture.SourceHashBytes != 525314 {
				t.Fatal(first)
			}
			repeat := run("repeat", false)
			if repeat.Report.Uploaded != 0 || repeat.Report.Adopted != int64(len(sizes)) {
				t.Fatal(repeat)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			wantStatus := 0
			if scenario == "lost" {
				wantStatus = 1
			}
			if f.calls["data"] < 1 || lost && (f.calls["data"] != 1 || f.calls["status"] != wantStatus) {
				t.Fatal(f.calls)
			}
			var active int
			if err = r.store.db.QueryRow("SELECT COUNT(*) FROM small_batch_groups WHERE phase<>'GONE'").Scan(&active); err != nil || active != 0 {
				t.Fatal(active, err)
			}
			f.base.mu.Lock()
			defer f.base.mu.Unlock()
			if len(f.base.uploads) != len(sizes) {
				t.Fatal("duplicate publication", len(f.base.uploads))
			}
			for _, upload := range f.base.uploads {
				if int64(len(upload.bytes)) != upload.op.SizeBytes || hashBytes(upload.bytes) != upload.op.SHA256 {
					t.Fatal("published bytes differ")
				}
			}
		})
	}
}
