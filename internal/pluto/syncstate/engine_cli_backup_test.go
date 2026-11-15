//go:build linux

package syncstate

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"testing"
	"time"

	"pluto/internal/syncproto"
)

type engineCLIFixtureBackup struct {
	*fixtureBackup
	state, source, config, scenario string
	beforeSource                    []stage3PhysicalEntry
}

func engineCLIWriteRaw(t *testing.T, filename string, raw []byte) {
	t.Helper()
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	syncFixtureDirectory(t, filepath.Dir(filename))
}
func engineCLIPhysical(t *testing.T, state, source string) []stage3PhysicalEntry {
	t.Helper()
	var result []stage3PhysicalEntry
	for _, root := range []string{filepath.Join(state, ArtifactDirectoryName), filepath.Join(state, smallBatchDirectoryName), source} {
		if _, err := os.Lstat(root); os.IsNotExist(err) && root == filepath.Join(state, smallBatchDirectoryName) {
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != uint32(os.Getuid()) {
				return ErrIdentityConflict
			}
			relative, e := filepath.Rel(root, p)
			if e != nil {
				return e
			}
			row := stage3PhysicalEntry{Root: root, Relative: relative, Kind: "directory", Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, Bytes: info.Size(), MTimeNS: info.ModTime().UnixNano(), CTimeNS: statCTime(info)}
			if !info.IsDir() {
				if !info.Mode().IsRegular() || st.Nlink != 1 {
					return ErrIdentityConflict
				}
				row.Kind = "file"
				row.SHA256, e = fileDigest(p)
				if e != nil {
					return e
				}
			}
			result = append(result, row)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}
func engineCLIReopenReader(t *testing.T, r *RemoteImport, state string) {
	t.Helper()
	u := url.URL{Scheme: "file", Path: filepath.Join(state, "sync-state.sqlite")}
	u.RawQuery = "mode=ro"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	r.store.db = db
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
}
func qualifyEngineCLIFixtureBackup(t *testing.T, r *RemoteImport, f *dispatchHTTPFixture, old *IsolatedHTTPSession, config, state, source, scenario string, sizes []int) *engineCLIFixtureBackup {
	t.Helper()
	if scenario != "normal" && scenario != "lost" && scenario != "disabled" {
		t.Fatal("exact original actual CLI scenario")
	}
	if err := r.store.db.Close(); err != nil {
		t.Fatal("quiescent read-only receiver close", err)
	}
	backendRaw := stage3BatchBackendBytes(t, f)
	configRaw, err := os.ReadFile(config)
	if err != nil || len(configRaw) == 0 || len(configRaw) > 1<<20 {
		t.Fatal("exact original current CLI config", err)
	}
	var backend stage3BatchBackend
	if err = json.Unmarshal(backendRaw, &backend); err != nil {
		t.Fatal(err)
	}
	if len(backend.Nodes) != 1 || backend.Seq != 0 || len(backend.Folders) != 0 || len(backend.Uploads) != 0 || len(backend.Groups) != 0 || backend.LoseData != (scenario != "normal") {
		t.Fatal("original empty-capture initial receiver")
	}
	db := stage3ImmutableDB(t, filepath.Join(state, "sync-state.sqlite"))
	var version, operations, artifacts int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM operations").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM local_artifacts").Scan(&artifacts); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil || version != 6 || operations != 0 || artifacts != 0 {
		t.Fatal("original before-CLI schema6/no captures", version, operations, artifacts, err)
	}
	if _, err = os.Lstat(filepath.Join(state, smallBatchDirectoryName)); !os.IsNotExist(err) {
		t.Fatal("initial optional batch namespace must be absent", err)
	}
	input := os.Getenv("PLUTO_FAULT_INPUT_DIR")
	if !filepath.IsAbs(input) || filepath.Clean(input) != input {
		t.Fatal("explicit native retained input root")
	}
	contextRoot, err := os.MkdirTemp(input, "engine-cli-context-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(contextRoot); err != nil {
			t.Error(err)
		}
	})
	engineCLIWriteRaw(t, filepath.Join(contextRoot, "backend.json"), backendRaw)
	engineCLIWriteRaw(t, filepath.Join(contextRoot, "config.json"), configRaw)
	logical, count := stage3DatabaseLogicalDigest(t, filepath.Join(state, "sync-state.sqlite"))
	physical := engineCLIPhysical(t, state, source)
	var sourceBefore []stage3PhysicalEntry
	var sourceBytes int64
	var sourceFiles int
	for _, e := range physical {
		if e.Root == source {
			sourceBefore = append(sourceBefore, e)
			if e.Kind == "file" {
				sourceBytes += e.Bytes
				sourceFiles++
			}
		}
	}
	expectedBytes := int64(0)
	for _, n := range sizes {
		expectedBytes += int64(n)
	}
	if sourceFiles != len(sizes) || sourceBytes != expectedBytes {
		t.Fatal("complete actual original mixed source", sourceFiles, sourceBytes)
	}
	preliminary := qualifyClosedFixtureBackup(t, state, []string{source, contextRoot}, func(copy *Store) {
		filename := copy.filename
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		got, rows := stage3DatabaseLogicalDigest(t, filename)
		if got != logical || rows != count {
			t.Fatal("all original copied SQL rows differ")
		}
	})
	restoreSource := filepath.Join(preliminary.directory, "restored/state/sync-state.sqlite")
	restoreSHA, err := fileDigest(restoreSource)
	if err != nil {
		t.Fatal(err)
	}
	stage3RestoreSQLiteAPI(t, state, restoreSource, restoreSHA)
	product, err := Open(testContext, state)
	if err != nil {
		t.Fatal(err)
	}
	var sourceReads []map[string]any
	var httpProof map[string]any
	func() {
		defer func() {
			if err := product.Close(); err != nil {
				t.Error(err)
			}
		}()
		sources, e := product.EnableSources(testContext, DefaultSourceLimits())
		if e != nil {
			t.Fatal(e)
		}
		bound, e := sources.Binding(testContext, "set", "source")
		if e != nil || bound.PhysicalPath != source {
			t.Fatal("original source binding on actual restored profile", e)
		}
		registry, e := product.EnableArtifacts(testContext, DefaultArtifactLimits())
		if e != nil {
			t.Fatal(e)
		}
		report, e := registry.Reconcile(testContext, artifactTestReader)
		if e != nil || !report.Admitted || report.Files != 0 || report.RecoveryOperations != 0 || report.ReservedBytes != 0 {
			t.Fatal("actual empty restored registry", report, e)
		}
		remote, e := product.EnableRemoteImport(testContext)
		if e != nil {
			t.Fatal(e)
		}
		err := filepath.WalkDir(filepath.Join(preliminary.directory, "restored/source-001"), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return ErrIdentityConflict
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(filepath.Join(preliminary.directory, "restored/source-001"), p)
			if err != nil {
				return err
			}
			original, err := os.ReadFile(filepath.Join(source, relative))
			if err != nil || !bytes.Equal(original, raw) {
				return ErrIdentityConflict
			}
			sourceReads = append(sourceReads, map[string]any{"relative": filepath.ToSlash(relative), "bytes": len(raw), "sha256": hashBytes(raw)})
			return nil
		})
		if err != nil || len(sourceReads) != len(sizes) {
			t.Fatal("actual complete restored original source bytes", err)
		}
		copiedBackend, e := os.ReadFile(filepath.Join(preliminary.directory, "restored/source-002/backend.json"))
		if e != nil || !bytes.Equal(copiedBackend, backendRaw) {
			t.Fatal("actual restored receiver checkpoint", e)
		}
		copiedConfig, e := os.ReadFile(filepath.Join(preliminary.directory, "restored/source-002/config.json"))
		if e != nil || !bytes.Equal(copiedConfig, configRaw) {
			t.Fatal("actual restored exact config", e)
		}
		httpProof = stage3EngineRestoreHTTP(t, copiedBackend, remote, old, preliminary.directory)
		if err = product.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 6 {
			t.Fatal("pre-CLI restored profile retains exact schema6", err)
		}
	}()
	if t.Failed() {
		t.Fatal("actual complete before-CLI restore precondition")
	}
	stage3RestoreSQLiteAPI(t, state, restoreSource, restoreSHA)
	finalLogical, finalCount := stage3DatabaseLogicalDigest(t, filepath.Join(state, "sync-state.sqlite"))
	if finalLogical != logical || finalCount != count || !reflect.DeepEqual(physical, engineCLIPhysical(t, state, source)) || !bytes.Equal(backendRaw, stage3BatchBackendBytes(t, f)) {
		t.Fatal("original SQLite/physical/receiver graph changed before first CLI")
	}
	if _, err = os.Lstat(filepath.Join(state, smallBatchDirectoryName)); !os.IsNotExist(err) {
		t.Fatal("pre-CLI batch namespace absence changed")
	}
	final := qualifyClosedFixtureBackup(t, state, []string{source, contextRoot}, func(copy *Store) {
		filename := copy.filename
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		got, rows := stage3DatabaseLogicalDigest(t, filename)
		if got != logical || rows != count {
			t.Fatal("final original full SQL checkpoint differs")
		}
	})
	stage3PendingProofWrite(t, filepath.Join(final.directory, "engine-cli-restore.json"), map[string]any{"schema": "pluto.engine-cli-before-run-restore.v1", "case": t.Name(), "scenario": scenario, "at": time.Now().UTC().Format(time.RFC3339Nano), "state": state, "source": source, "config": config, "preliminaryDirectory": filepath.Base(preliminary.directory), "preliminaryArchiveSHA256": preliminary.archiveSHA, "finalArchiveSHA256": final.archiveSHA, "backendSHA256": hashBytes(backendRaw), "configSHA256": hashBytes(configRaw), "originalLogicalSHA256": logical, "finalLogicalSHA256": finalLogical, "logicalRows": count, "schemaVersion": 6, "operations": 0, "retainedArtifacts": 0, "batchNamespaceAbsent": true, "restoreCallsBeforeCLI": 2, "restoredOnOriginalPhysicalInodes": true, "manualAuthorityOrRowEdits": false, "originalPhysical": physical, "sourceFiles": sourceFiles, "sourceBytes": sourceBytes, "actualRestoredSourceReads": sourceReads, "restoredHTTP": httpProof, "historicalReader": false, "realSaturnPGSFTPAcceptance": false})
	engineCLIReopenReader(t, r, state)
	t.Logf("ENGINE_CLI_GENUINE_BEFORE_RUN_RESTORE scenario=%s sourceFiles=%d sourceBytes=%d schema=6", scenario, sourceFiles, sourceBytes)
	return &engineCLIFixtureBackup{fixtureBackup: final, state: state, source: source, config: config, scenario: scenario, beforeSource: sourceBefore}
}
func (b *engineCLIFixtureBackup) recordResult(t *testing.T, r *RemoteImport, f *dispatchHTTPFixture, phase string, owned nativeCLIResult, result engineCLIResult) {
	t.Helper()
	if phase != "initial" && phase != "recovery" && phase != "repeat" {
		t.Fatal("exact original CLI phase")
	}
	if owned.PID <= 0 || owned.LifecycleError != nil {
		t.Fatal("actual native owner result required")
	}
	backendRaw := stage3BatchBackendBytes(t, f)
	if err := r.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	product, err := Open(testContext, b.state)
	if err != nil {
		t.Fatal("actual exited native child profile", err)
	}
	sql := stage3BatchExportSQL(t, product, b.directory, phase)
	var version int
	if err = product.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err = product.Close(); err != nil {
		t.Fatal(err)
	}
	physical := engineCLIPhysical(t, b.state, b.source)
	var source []stage3PhysicalEntry
	for _, e := range physical {
		if e.Root == b.source {
			source = append(source, e)
		}
	}
	if !reflect.DeepEqual(source, b.beforeSource) {
		t.Fatal("actual CLI changed original source")
	}
	configRaw, err := os.ReadFile(b.config)
	if err != nil {
		t.Fatal(err)
	}
	engineCLIWriteRaw(t, filepath.Join(b.directory, phase+"-backend.json"), backendRaw)
	engineCLIWriteRaw(t, filepath.Join(b.directory, phase+"-config.json"), configRaw)
	engineCLIWriteRaw(t, filepath.Join(b.directory, phase+"-stdout.log"), owned.Stdout)
	engineCLIWriteRaw(t, filepath.Join(b.directory, phase+"-stderr.log"), owned.Stderr)
	sql["schema"] = "pluto.engine-cli-actual-phase.v1"
	sql["case"] = t.Name()
	sql["scenario"] = b.scenario
	sql["phase"] = phase
	sql["at"] = time.Now().UTC().Format(time.RFC3339Nano)
	sql["actualPID"] = owned.PID
	sql["schemaVersion"] = version
	sql["nativeOwnerLifecycleError"] = false
	sql["domainErrorPresent"] = owned.DomainError != nil
	sql["actualResult"] = json.RawMessage(owned.Stdout)
	sql["parsedResult"] = result
	sql["stdoutSHA256"] = hashBytes(owned.Stdout)
	sql["stderrSHA256"] = hashBytes(owned.Stderr)
	sql["backendSHA256"] = hashBytes(backendRaw)
	sql["configSHA256"] = hashBytes(configRaw)
	sql["originalSourceUnchanged"] = true
	sql["sourcePhysical"] = source
	sql["physicalAfter"] = physical
	sql["historicalReader"] = false
	sql["realSaturnPGSFTPAcceptance"] = false
	stage3PendingProofWrite(t, filepath.Join(b.directory, phase+".json"), sql)
	engineCLIReopenReader(t, r, b.state)
	t.Logf("ENGINE_CLI_ACTUAL_PHASE_RETAINED scenario=%s phase=%s pid=%d schema=%d sourceReads=%d uploaded=%d recovered=%d", b.scenario, phase, owned.PID, version, result.Capture.SourceReads, result.Report.Uploaded, result.Report.Recovered)
}

func stage3EngineRestoreHTTP(t *testing.T, raw []byte, r *RemoteImport, original *IsolatedHTTPSession, directory string) map[string]any {
	t.Helper()
	var b stage3BatchBackend
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if b.Schema != "pluto.batch-owned-http-checkpoint.v1" || len(b.Uploads) != 0 || len(b.Groups) != 0 || len(b.Sent) != 0 || len(b.Nodes) != 1 || len(b.Folders) != 0 || b.Seq != 0 || b.Identity != original.identity {
		t.Fatal("complete original pre-publication owned receiver checkpoint")
	}
	base := &guardedHTTPFixture{t: t, r: r, binding: b.Binding, seq: b.Seq, nodes: b.Nodes, events: b.Events, uploads: map[string]*httpFixtureUpload{}, folders: b.Folders, requests: b.Requests, lostComplete: b.BaseLostComplete, lostAppend: b.BaseLostAppend, lostPrepare: b.BaseLostPrepare, rejectRedirect: b.RejectRedirect, rejectFeedAfterFolder: b.RejectFeedAfterFolder}
	// This restored receiver uses the original already-qualified immutable
	// identity only for its read-only capabilities response. It makes no request
	// through the closed original product session and publishes no data.
	receiver := &dispatchHTTPFixture{base: base, session: original, groups: map[string]*smallBatchPlan{}, calls: b.Calls, sent: b.Sent, losePrepare: b.LosePrepare, loseData: b.LoseData, malformed: b.Malformed, knownMissing: b.KnownMissing, conflict: b.Conflict, partial: b.Partial, jobProtocol: b.JobProtocol}
	if hashBytes(stage3BatchBackendBytes(t, receiver)) != hashBytes(raw) {
		t.Fatal("actual restored receiver fields differ before probe")
	}
	server := httptest.NewServer(receiver)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(command string, body []byte) []byte {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/sync/v1/roots/"+b.Binding.RootID+"/"+command, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer fixture-token")
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != 200 || len(payload) >= 1<<20 {
			t.Fatal("actual restored HTTP metadata", response.StatusCode, readErr, closeErr)
		}
		return payload
	}
	caps := request("small-batches/capabilities", nil)
	var capability map[string]any
	if err := json.Unmarshal(caps, &capability); err != nil || capability["schema"] != "saturn.small-file-batch-capabilities.v1" || !reflect.DeepEqual(capability["binding"], jsonRawValue(mustBatchJSON(t, bindingHTTP(b.Binding)))) || capability["device_id"] != b.Identity.DeviceID || capability["backend_identity"] != b.Identity.BackendIdentity || capability["qualification_receipt_sha256"] != b.Identity.ContractReceiptSHA256 {
		t.Fatal("restored actual receiver capabilities", err)
	}
	candidate, err := r.Candidate(testContext, "root")
	if err != nil || candidate.SnapshotID == "" {
		t.Fatal("actual restored candidate", err)
	}
	body := mustBatchJSON(t, map[string]any{"binding": bindingHTTP(b.Binding), "cursor": "entries-" + candidate.SnapshotID})
	entries := request("entries", body)
	values := make([]syncproto.Descriptor, 0, len(b.Nodes))
	for _, d := range b.Nodes {
		values = append(values, d)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].NodeID < values[j].NodeID })
	expected := wirePage(SnapshotPreparation{Snapshot: syncproto.Snapshot{Binding: b.Binding, SnapshotID: candidate.SnapshotID, CutSeq: remoteDecimal(b.Seq)}}, values, "entries-done", false)
	if !reflect.DeepEqual(jsonRawValue(entries), jsonRawValue(expected)) {
		t.Fatal("actual restored receiver full original directory catalog")
	}
	stage3PendingProofWrite(t, filepath.Join(directory, "restored-http-readback.json"), map[string]any{"schema": "pluto.engine-cli-owned-restored-http-readback.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "checkpointSHA256": hashBytes(raw), "originalIdentity": b.Identity, "actualLoopbackHTTP": true, "originalNodes": b.Nodes, "capabilities": json.RawMessage(caps), "capabilitiesSHA256": hashBytes(caps), "entries": json.RawMessage(entries), "entriesSHA256": hashBytes(entries), "publishedDuringProbe": 0, "historicalReader": false})
	return map[string]any{"actualLoopbackHTTP": true, "catalogEntries": len(b.Nodes), "publishedDuringProbe": 0, "capabilitiesSHA256": hashBytes(caps), "entriesSHA256": hashBytes(entries)}
}
