package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHTTPRebootstrapOriginalPendingEndpointDriftRefusesBeforeCheckpoint(t *testing.T) {
	for _, mode := range []string{"backend", "receipt", "epoch", "device"} {
		t.Run(mode, func(t *testing.T) {
			r, _, w, s, g, _ := rebootstrapFixture(t, 1)
			g.f.lostPrepare = true
			if report, err := runActualHTTPFixture(t, r, w, s); err == nil || report.Failed != 1 {
				t.Fatal(report, err)
			}
			before, _ := r.Candidate(testContext, "root")
			digest := retainedRecoveryDigest(t, r)
			config := IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: s.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(s.binding), DeviceID: s.identity.DeviceID, BackendIdentity: s.identity.BackendIdentity, QualificationReceiptSHA256: s.identity.ContractReceiptSHA256, Token: "fixture-token"}
			switch mode {
			case "backend":
				config.BackendIdentity = "other-backend"
			case "receipt":
				config.QualificationReceiptSHA256 = hashBytes([]byte("other"))
			case "epoch":
				config.Binding["server_epoch"] = remoteVersion(88888)
			case "device":
				config.DeviceID = remoteVersion(88888)
			}
			changed, err := NewIsolatedHTTPSession(testContext, r, "root", config)
			if mode == "device" {
				if err == nil {
					changed.Close()
					t.Fatal("device binding changed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer changed.Close()
			cause := changed.httpFailure(410, "changes", "application/json", []byte(`{"code":"cursor_expired"}`))
			if _, err = changed.beginHTTPRebootstrap(testContext, before, cause); err == nil {
				t.Fatal("original endpoint identity waived")
			}
			after, _ := r.Candidate(testContext, "root")
			if !reflect.DeepEqual(before, after) || digest != retainedRecoveryDigest(t, r) || len(g.starts) != 0 {
				t.Fatal("drift mutated original")
			}
		})
	}
}

// Runs the actual predecessor signed CLI, not an imitation of its decoder.
// A separate reader holds WAL across writer close and child-process invocation.
func TestHTTPRebootstrapHistoricalSignedCLIRefusesBothInterruptedPhases(t *testing.T) {
	binary := os.Getenv("PLUTO_R1E_ACTUAL_CLI")
	if binary == "" {
		t.Skip("requires exact accepted predecessor signed CLI fixture")
	}
	bytes, err := os.ReadFile(binary)
	if err != nil || hashBytes(bytes) != "c2104328598eb367680db033adfee043d76a3b3d90bb11e5f8707373bacf4829" {
		t.Fatal("predecessor binary identity", err)
	}
	for _, point := range []string{"http_rebootstrap.after_commit", "http_rebootstrap.before_qualified"} {
		t.Run(point, func(t *testing.T) {
			r, _, w, s, g, dir := rebootstrapFixture(t, 1)
			work := filepath.Dir(filepath.Dir(dir))
			specs := []SourceSpec{{ID: "source", SelectedPath: "tree", WorkingDirectory: work}}
			// This fixture enrollment must match the real CLI's source config. Set it
			// before observing any file or persisting a captured publication intent.
			rawSpecs, _ := json.Marshal(specs)
			if _, err := r.store.db.Exec("UPDATE source_sets SET config_digest=? WHERE set_id='set'", hashBytes(rawSpecs)); err != nil {
				t.Fatal(err)
			}
			g.f.lostComplete = true
			if report, err := runActualHTTPFixture(t, r, w, s); err == nil || report.Failed != 1 {
				t.Fatal(report, err)
			}
			digest := retainedRecoveryDigest(t, r)
			oldSnapshot, err := r.pendingHTTPSnapshot(s.binding)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := sql.Open("sqlite", r.store.filename)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			readTx, err := reader.BeginTx(testContext, &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer readTx.Rollback()
			var pinned string
			if err = readTx.QueryRow("SELECT descriptor_json FROM remote_candidate_roots WHERE root_id='root'").Scan(&pinned); err != nil {
				t.Fatal(err)
			}
			r.testPoint = func(p string) error {
				if p == point {
					return context.Canceled
				}
				return nil
			}
			g.expire = 1
			if err = s.Refresh(testContext); err == nil {
				t.Fatal("interrupt missed")
			}
			checkpoint, err := r.Candidate(testContext, "root")
			if err != nil || checkpoint.Valid || checkpoint.HTTPRebootstrap == nil {
				t.Fatal(checkpoint, err)
			}
			state := filepath.Dir(r.store.filename)
			if err = os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
			config := map[string]any{"schema": "pluto.copy-indexed-isolated/v1", "local_root_id": "root", "mapping_id": "mapping", "source_set_id": "set", "sources": []any{map[string]any{"id": "source", "selected_path": "tree", "working_directory": work}}, "remote": IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: s.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(s.binding), DeviceID: s.identity.DeviceID, BackendIdentity: s.identity.BackendIdentity, QualificationReceiptSHA256: s.identity.ContractReceiptSHA256, Token: "fixture-token"}}
			configPath := filepath.Join(nativeFixtureTempDir(t), "test-config.json")
			if err = os.WriteFile(configPath, mustJSON(config), 0600); err != nil {
				t.Fatal(err)
			}
			g.f.mu.Lock()
			g.legacySnapshot = oldSnapshot
			g.f.mu.Unlock()
			s.Close()
			if err = r.store.Close(); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filepath.Join(state, "sync-state.sqlite-wal"))
			if err != nil || info.Size() == 0 {
				t.Fatal("WAL not pinned", err)
			}
			ctx, cancel := context.WithTimeout(testContext, 20*time.Second)
			defer cancel()
			owned := runNativeFixtureCLI(t, ctx, "historical-r1e", binary, configPath, state)
			if owned.LifecycleError != nil { t.Fatal(owned.LifecycleError) }
			out, err := owned.Stdout, owned.DomainError
			if err == nil {
				t.Fatal("historical CLI admitted incomplete recovery", string(out))
			}
			var result struct {
				OK     bool                                          `json:"ok"`
				Error  string                                        `json:"error"`
				HTTP   HTTPMetrics                                   `json:"http"`
				Report struct{ Observed, Uploaded, Recovered int64 } `json:"report"`
			}
			if json.Unmarshal(out, &result) != nil || result.OK || !strings.Contains(result.Error, ErrIdentityConflict.Error()) || result.HTTP.Requests != 2 || result.HTTP.DataBytes != 0 || result.Report.Observed != 0 || result.Report.Uploaded != 0 || result.Report.Recovered != 0 {
				t.Fatal("old CLI refused for unrelated reason", string(out), err)
			}
			store, err := Open(testContext, state)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			r.store = store
			current, err := readCandidate(testContext, store.db, "root")
			if err != nil || !reflect.DeepEqual(current, checkpoint) || digest != retainedRecoveryDigest(t, r) {
				t.Fatal("old reader changed retained recovery", current, err)
			}
			if path := os.Getenv("PLUTO_R1F_RESULT_DIR"); path != "" {
				if err = os.WriteFile(filepath.Join(path, "old-cli-"+point+".json"), out, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
