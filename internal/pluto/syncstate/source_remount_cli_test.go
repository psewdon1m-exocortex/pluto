package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The exact historical signed CLI and the final signed successor both use the
// same config, SQLite, sealed original intent and real loopback HTTP fixture.
// The server reads its client's original durable intent through a separate
// read-only connection; it grants no production authority.
func TestOwnerMountActualSignedCLIOriginalRecoveryAndFresh(t *testing.T) {
	old, current := os.Getenv("PLUTO_R1F_ACTUAL_CLI"), os.Getenv("PLUTO_R1G_ACTUAL_CLI")
	if old == "" || current == "" {
		t.Skip("requires exact signed R1f and final successor CLI fixtures")
	}
	bytes, err := os.ReadFile(old)
	if err != nil || hashBytes(bytes) != "fa0c0be253fd9041281f25640fcbdf1af05849c41f1f2cc6a910a590453d33cc" {
		t.Fatal("predecessor CLI identity", err)
	}
	r, _, w, session, server, dir := actualHTTPFixture(t, 3)
	work := filepath.Dir(filepath.Dir(dir))
	specs := []SourceSpec{{ID: "source", SelectedPath: "tree", WorkingDirectory: work}}
	if _, err = r.store.db.Exec("UPDATE source_sets SET config_digest=? WHERE set_id='set'", hashBytes(mustJSON(specs))); err != nil {
		t.Fatal(err)
	}
	server.lostComplete = true
	first, err := runActualHTTPFixture(t, r, w, session)
	if err == nil || first.Failed != 1 {
		t.Fatal(first, err)
	}
	originals, err := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if err != nil || len(originals) != 1 {
		t.Fatal(originals, err)
	}
	b, _ := r.sources.Binding(testContext, w.SetID, "source")
	b.Object.MountID = "900000001"
	writeRemountBinding(t, r.sources, w, b)
	state := filepath.Dir(r.store.filename)
	if err = os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"schema": "pluto.copy-indexed-isolated/v1", "local_root_id": "root", "mapping_id": "mapping", "source_set_id": "set", "sources": []any{map[string]any{"id": "source", "selected_path": "tree", "working_directory": work}}, "remote": IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: session.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(session.binding), DeviceID: session.identity.DeviceID, BackendIdentity: session.identity.BackendIdentity, QualificationReceiptSHA256: session.identity.ContractReceiptSHA256, Token: "fixture-token"}}
	configPath := filepath.Join(nativeFixtureTempDir(t), "config.json")
	configBytes := mustJSON(config)
	if err = os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	session.Close()
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(state, "sync-state.sqlite")}
	reader, err := sql.Open("sqlite", u.String()+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	server.mu.Lock()
	r.store = &Store{db: reader, filename: filepath.Join(state, "sync-state.sqlite")}
	server.mu.Unlock()
	run := func(binary, phase string) struct {
		OK      bool               `json:"ok"`
		Error   string             `json:"error"`
		Report  CapturedScanReport `json:"report"`
		HTTP    HTTPMetrics        `json:"http"`
		Capture struct {
			SourceReads     int64 `json:"source_reads"`
			SourceHashBytes int64 `json:"source_hash_bytes"`
		} `json:"capture"`
	} {
		t.Helper()
		ctx, cancel := context.WithTimeout(testContext, 30*time.Second)
		defer cancel()
		role := "remount-current"
		if phase == "old" { role = "historical-r1f" }
		owned := runNativeFixtureCLI(t, ctx, role, binary, configPath, state)
		if owned.LifecycleError != nil { t.Fatal(phase, owned.LifecycleError) }
		out, e := owned.Stdout, owned.DomainError
		var result struct {
			OK      bool               `json:"ok"`
			Error   string             `json:"error"`
			Report  CapturedScanReport `json:"report"`
			HTTP    HTTPMetrics        `json:"http"`
			Capture struct {
				SourceReads     int64 `json:"source_reads"`
				SourceHashBytes int64 `json:"source_hash_bytes"`
			} `json:"capture"`
		}
		if err := json.Unmarshal(out, &result); err != nil || (phase == "old") != (e != nil) {
			t.Fatal(phase, string(out), e, err)
		}
		if path := os.Getenv("PLUTO_R1G_RESULT_DIR"); path != "" {
			if err := os.WriteFile(filepath.Join(path, "native-remount-"+phase+".json"), out, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	oldResult := run(old, "old")
	if oldResult.OK || !strings.Contains(oldResult.Error, ErrStaleGeneration.Error()) || oldResult.Report.Recovered != 0 || oldResult.HTTP.DataBytes != 0 {
		t.Fatal("frozen R1f did not reproduce mount refusal", oldResult)
	}
	newResult := run(current, "recover")
	if !newResult.OK || newResult.Report.Recovered != 1 || newResult.Report.Verified != 2 || newResult.Report.Uploaded != 0 || newResult.Report.Adopted != 2 || newResult.HTTP.DataBytes != 0 || newResult.Capture.SourceHashBytes != 6 {
		t.Fatal("successor did not recover original", newResult)
	}
	after, err := readOperation(testContext, reader, originals[0].OperationID)
	if err != nil || after.Stage != "CLIENT_ACKED" || after.IntentFingerprint != originals[0].IntentFingerprint || after.SealedFingerprint != originals[0].SealedFingerprint || after.SnapshotID != originals[0].SnapshotID || after.HTTPBinding == nil || originals[0].HTTPBinding == nil || *after.HTTPBinding != *originals[0].HTTPBinding {
		t.Fatal("original intent/server binding changed", after, err)
	}
	fresh := run(current, "fresh")
	if !fresh.OK || fresh.Report.Verified != 3 || fresh.Report.Adopted != 3 || fresh.Report.Recovered != 0 || fresh.Report.Uploaded != 0 || fresh.HTTP.DataBytes != 0 || fresh.Capture.SourceHashBytes != 9 {
		t.Fatal("fresh regression", fresh)
	}
	now, err := os.ReadFile(configPath)
	if err != nil || string(now) != string(configBytes) {
		t.Fatal("config changed", err)
	}
}
