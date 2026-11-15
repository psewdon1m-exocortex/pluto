package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Reopen the actual SQLite store and HTTP session while retaining the mock
// server's original-key registry. No operation or captured input is reminted.
func restartHTTPBindingFixture(t *testing.T, r *RemoteImport, s *IsolatedHTTPSession, f *guardedHTTPFixture) (*RemoteImport, SourceWitness, *IsolatedHTTPSession) {
	t.Helper()
	f.mu.Lock()
	f.mu.Unlock() // Join any handler finishing after a lost response.
	directory := filepath.Dir(r.store.filename)
	s.Close()
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sources, err := store.EnableSources(testContext, DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	next, err := store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	w, err := sources.BeginSourceOwner(testContext, "set", 1, "after-real-restart")
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.r = next
	f.mu.Unlock()
	current, err := NewIsolatedHTTPSession(testContext, next, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: s.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(f.binding), DeviceID: s.identity.DeviceID, BackendIdentity: s.identity.BackendIdentity, QualificationReceiptSHA256: s.identity.ContractReceiptSHA256, Token: "fixture-token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(current.Close)
	current.SetRecoveryReader(artifactTestReader)
	if err = current.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	return next, w, current
}

func TestHTTPBindingLostPreparePersistenceAndCompleteRestart(t *testing.T) {
	for _, boundary := range []string{"lost-prepare", "before-bind-commit", "after-bind-commit", "lost-complete"} {
		t.Run(boundary, func(t *testing.T) {
			r, _, w, s, f, _ := actualHTTPFixture(t, 1)
			f.lostPrepare = boundary == "lost-prepare"
			f.lostComplete = boundary == "lost-complete"
			point := ""
			if boundary == "before-bind-commit" {
				point = "http_binding.before_commit"
			}
			if boundary == "after-bind-commit" {
				point = "http_binding.after_commit"
			}
			r.testPoint = func(p string) error {
				if p == point {
					return context.Canceled
				}
				return nil
			}
			first, err := runActualHTTPFixture(t, r, w, s)
			f.mu.Lock()
			uploadCount := len(f.uploads)
			f.mu.Unlock()
			if err == nil || first.Failed != 1 || uploadCount != 1 {
				t.Fatal("failure not retained", first, err, uploadCount)
			}
			pending, err := r.store.PendingPage(testContext, "root", "", 10)
			if err != nil || len(pending) != 1 {
				t.Fatal(pending, err)
			}
			original := pending[0]
			shouldBeBound := boundary == "after-bind-commit" || boundary == "lost-complete"
			if (original.HTTPBinding != nil) != shouldBeBound {
				t.Fatal("wrong binding commit boundary", boundary, original.HTTPBinding)
			}
			f.mu.Lock()
			appendCount := f.requests["catalog-uploads/append"]
			var serverID string
			for _, upload := range f.uploads {
				serverID = upload.serverID
			}
			f.mu.Unlock()
			if boundary != "lost-complete" && appendCount != 0 {
				t.Fatal("data before durable binding")
			}
			if serverID == original.OperationID {
				t.Fatal("fixture concealed server allocation defect")
			}
			next, nextW, nextSession := restartHTTPBindingFixture(t, r, s, f)
			recovered, err := runActualHTTPFixture(t, next, nextW, nextSession)
			if err != nil || recovered.Recovered != 1 || recovered.Uploaded != 0 || len(f.uploads) != 1 {
				t.Fatal(recovered, err, len(f.uploads))
			}
			ack, err := next.store.Operation(testContext, original.OperationID)
			if err != nil || ack.Stage != "CLIENT_ACKED" || ack.HTTPBinding == nil || ack.HTTPBinding.ServerUploadID != serverID || string(mustJSON(ack.Intent)) != string(mustJSON(original.Intent)) || ack.IntentFingerprint != original.IntentFingerprint || ack.SealedFingerprint != original.SealedFingerprint {
				t.Fatal("immutable operation changed", ack, err)
			}
			root, err := next.store.Root(testContext, "root")
			if err != nil || root.EngineReady || root.AllowsDelete || root.MaxFileBytes != MaxFileBytes || root.MaxActiveVersions != 10 {
				t.Fatal(root, err)
			}
		})
	}
}

func TestHTTPBindingRejectsRebindServerIDSwapAndReceiptAssociation(t *testing.T) {
	r, _, w, s, f, _ := actualHTTPFixture(t, 1)
	if _, err := runActualHTTPFixture(t, r, w, s); err != nil {
		t.Fatal(err)
	}
	var upload *httpFixtureUpload
	for _, value := range f.uploads {
		upload = value
	}
	op, err := r.store.Operation(testContext, upload.op.OperationID)
	if err != nil || op.HTTPBinding == nil {
		t.Fatal(op, err)
	}
	input, _ := originalCatalogInput(op)
	if _, err = r.BindHTTPUpload(testContext, op, remoteVersion(99999), input.hash); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("rebind allowed", err)
	}
	if _, err = r.BindHTTPUpload(testContext, op, op.HTTPBinding.ServerUploadID, strings.Repeat("0", 64)); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("hash swap allowed", err)
	}
	status, err := readCatalogHTTPStatus(mustJSON(f.status(upload)), op, input)
	if err != nil || status.publication == nil {
		t.Fatal(status, err)
	}
	pub := *status.publication
	pub.HTTPBinding = nil
	if err = r.AckCaptured(testContext, pub); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("unbound receipt allowed", err)
	}
	pub = *status.publication
	wrong := *pub.HTTPBinding
	wrong.ServerOperationID = remoteVersion(99998)
	pub.HTTPBinding = &wrong
	if err = r.AckCaptured(testContext, pub); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("receipt association swap allowed", err)
	}
	for _, key := range []string{"uploadId", "operationId", "rootId", "intentHash", "expectedSizeBytes"} {
		m := f.status(upload)
		m["session"].(map[string]any)[key] = remoteVersion(99997)
		if _, err = readCatalogHTTPStatus(mustJSON(m), op, input); !errors.Is(err, ErrInvalidReceipt) {
			t.Fatal("session swap allowed", key, err)
		}
	}
	for _, malformed := range []string{strings.TrimSuffix(string(mustJSON(*op.HTTPBinding)), "}") + `,"extra":true}`, strings.TrimSuffix(string(mustJSON(*op.HTTPBinding)), "}") + `,"ServerUploadID":"` + op.HTTPBinding.ServerUploadID + `"}`} {
		if _, err = decodeHTTPUploadBinding(malformed, op); !errors.Is(err, ErrInvalidReceipt) {
			t.Fatal("corrupt binding accepted", err)
		}
	}
	changed := op
	changed.SizeBytes++
	forged, _ := originalCatalogInput(changed)
	if _, err = makeHTTPUploadBinding(changed, op.HTTPBinding.ServerUploadID, forged.hash); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("changed immutable intent accepted", err)
	}
}

func TestHTTPFolderACKThenUnavailableFeedRetainsOriginalUniqueIntent(t *testing.T) {
	r, _, w, s, f, _ := actualHTTPFixture(t, 1)
	f.rejectFeedAfterFolder = true
	for attempt := 0; attempt < 2; attempt++ {
		report, err := runActualHTTPFixture(t, r, w, s)
		if err == nil || report.Failed != 1 || strings.Contains(err.Error(), "UNIQUE constraint") {
			t.Fatal(report, err)
		}
		var count int
		if err = r.store.db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&count); err != nil || count != 1 || len(f.folders) != 1 {
			t.Fatal("reminted folder ID", count, len(f.folders), err)
		}
		var baselines int
		r.store.db.QueryRow("SELECT COUNT(*) FROM baselines").Scan(&baselines)
		if baselines != 0 {
			t.Fatal("historical ACK adopted without current R", baselines)
		}
	}
	f.rejectFeedAfterFolder = false
	source, err := r.sources.SourceEntry(testContext, w.SetID, "tree/nested/file-000")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := r.ProjectSourcePath(testContext, w, "root", source)
	if err != nil {
		t.Fatal("recovery projection", err)
	}
	if err = s.PrepareParents(testContext, w, "root", entry); err != nil {
		t.Fatal("recovery original folder/current feed", err)
	}
	if len(f.folders) != 2 {
		t.Fatal("remaining exact parent not prepared", len(f.folders))
	}
	report, err := runActualHTTPFixture(t, r, w, s)
	if err != nil || report.Uploaded != 1 {
		t.Fatal("recovery capture", report, err)
	}
}

func TestHTTPBindingModuleFiveWALBackupAtomicMigrationAndReadonlyPreflight(t *testing.T) {
	r, _, _ := remoteFixture(t)
	var before string
	if _, err := r.store.db.Exec("UPDATE roots SET legacy_checkpoint=? WHERE root_id='root'", `{"wal-proof":"committed legacy config marker"}`); err != nil {
		t.Fatal(err)
	}
	if err := r.store.db.QueryRow("SELECT legacy_checkpoint FROM roots WHERE root_id='root'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	r.testPoint = func(p string) error {
		if p == "http_binding.migration.before_commit" {
			return context.Canceled
		}
		return nil
	}
	if err := r.enableHTTPBindings(testContext); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var version int
	r.store.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 5 {
		t.Fatal("partial migration persisted", version)
	}
	r.testPoint = nil
	if err := r.enableHTTPBindings(testContext); err != nil {
		t.Fatal(err)
	}
	if err := r.enableHTTPBindings(testContext); err != nil {
		t.Fatal("idempotent migration", err)
	}
	rows, err := r.store.db.Query("EXPLAIN QUERY PLAN SELECT operation_id FROM operations WHERE root_id=? AND operation_id>? AND stage<>'CLIENT_ACKED' ORDER BY operation_id LIMIT 128", "root", "")
	if err != nil {
		t.Fatal(err)
	}
	var plans []string
	for rows.Next() {
		var a, b, c int
		var p string
		if err = rows.Scan(&a, &b, &c, &p); err != nil {
			t.Fatal(err)
		}
		plans = append(plans, p)
		if strings.Contains(p, "SCAN ") || strings.Contains(p, "TEMP B-TREE") {
			t.Fatal("unbounded pending root sweep", p)
		}
	}
	rows.Close()
	if !strings.Contains(strings.Join(plans, ";"), "pending_root_operations") {
		t.Fatal(plans)
	}
	var manifest string
	if err := r.store.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=6").Scan(&manifest); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Backup string `json:"backup"`
		SHA    string `json:"backupSHA256"`
	}
	if err := json.Unmarshal([]byte(manifest), &m); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(filepath.Dir(r.store.filename), "sync-state-backups", m.Backup)
	raw, err := os.ReadFile(backupPath)
	if err != nil || hashBytes(raw) != m.SHA {
		t.Fatal("backup bytes", err)
	}
	backup, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	var backupVersion int
	backup.QueryRow("PRAGMA user_version").Scan(&backupVersion)
	var oldRoot string
	err = backup.QueryRow("SELECT legacy_checkpoint FROM roots WHERE root_id='root'").Scan(&oldRoot)
	backup.Close()
	if err != nil || backupVersion != 5 || oldRoot != before {
		t.Fatal("WAL backup omitted committed root", backupVersion, oldRoot, err)
	}
	directory := filepath.Dir(r.store.filename)
	r.store.Close()
	reopened, err := Open(testContext, directory)
	if err != nil {
		t.Fatal("module6 exact-DDL reopen", err)
	}
	if _, err = reopened.db.Exec("DROP INDEX http_server_upload_identity"); err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	path := filepath.Join(directory, "state.sqlite")
	// Use the real filename; no writable repair may recreate a missing index.
	path = r.store.filename
	bytesBefore, _ := os.ReadFile(path)
	if bad, err := Open(testContext, directory); err == nil {
		bad.Close()
		t.Fatal("broken recognized schema accepted")
	}
	bytesAfter, _ := os.ReadFile(path)
	if hashBytes(bytesAfter) != hashBytes(bytesBefore) {
		t.Fatal("readonly preflight changed corrupt schema bytes")
	}
}

func TestHTTPBindingModuleSixActualV5ReaderRefusesWithoutMutation(t *testing.T) {
	reader := os.Getenv("PLUTO_HTTP_V5_READER")
	if reader == "" {
		t.Skip("actual frozen v5 reader qualified in release container")
	}
	r, _, _ := remoteFixture(t)
	if err := r.enableHTTPBindings(testContext); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(r.store.filename)
	r.store.Close()
	before, err := os.ReadFile(r.store.filename)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(reader, directory).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "sync state schema is unsupported") {
		t.Fatal("old reader failed safe refusal", string(out), err)
	}
	after, err := os.ReadFile(r.store.filename)
	if err != nil || hashBytes(before) != hashBytes(after) {
		t.Fatal("old reader mutated v6", err)
	}
	current, err := Open(testContext, directory)
	if err != nil {
		t.Fatal("new reader", err)
	}
	current.Close()
}

func TestHTTPCurrentScanMissingHistoricalSourceRetainsOriginal(t *testing.T) {
	r, _, w, s, f, dir := actualHTTPFixture(t, 1)
	f.lostPrepare = true
	first, err := runActualHTTPFixture(t, r, w, s)
	if err == nil || first.Failed != 1 {
		t.Fatal(first, err)
	}
	f.mu.Lock()
	originalRequests := f.requests["catalog-uploads/prepare"]
	f.mu.Unlock()
	pending, err := r.store.PendingPage(testContext, "root", "", 10)
	if err != nil || len(pending) != 1 {
		t.Fatal(pending, err)
	}
	original := pending[0]
	if err = os.Remove(filepath.Join(dir, "file-000")); err != nil {
		t.Fatal(err)
	}
	before := CaptureMetricSnapshot()
	next, err := runActualHTTPFixture(t, r, w, s)
	if err != nil || !next.Complete || next.Verified != 0 || next.Uploaded != 0 || next.Recovered != 1 || next.Failed != 0 || CaptureMetricSnapshot().Since(before).SourceReads != 0 {
		t.Fatal("sealed historical original did not recover independently of missing source", next, err)
	}
	current, err := r.store.Operation(testContext, original.OperationID)
	if err != nil || current.Stage != "CLIENT_ACKED" || string(mustJSON(current.Intent)) != string(mustJSON(original.Intent)) {
		t.Fatal(current, err)
	}
	var oldWork int
	r.store.db.QueryRow("SELECT COUNT(*) FROM source_verification").Scan(&oldWork)
	if oldWork != 0 { // Capture completed this task before the lost prepare.
		t.Fatal("old verification erased", oldWork)
	}
	f.mu.Lock()
	requests := f.requests["catalog-uploads/prepare"]
	f.mu.Unlock()
	if requests != originalRequests+2 {
		t.Fatal("recovery must use original prepare lookup and replay", requests, originalRequests)
	}
	if _, err := os.Stat(filepath.Join(dir, "file-000")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery recreated the removed local source", err)
	}
	if err = os.WriteFile(filepath.Join(dir, "file-000"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := runActualHTTPFixture(t, r, w, s)
	if err != nil || !restored.Complete || restored.Recovered != 0 || restored.Uploaded != 0 || restored.Adopted != 1 {
		t.Fatal("restored source did not adopt the recovered original", restored, err)
	}
	ack, err := r.store.Operation(testContext, original.OperationID)
	if err != nil || ack.Stage != "CLIENT_ACKED" || string(mustJSON(ack.Intent)) != string(mustJSON(original.Intent)) {
		t.Fatal(ack, err)
	}
	f.mu.Lock()
	uploadCount := len(f.uploads)
	f.mu.Unlock()
	if uploadCount != 1 {
		t.Fatal("restored source minted extra upload", uploadCount)
	}
}

func TestHTTPCurrentScanForeignRootPendingDoesNotBlockSelectedCompletion(t *testing.T) {
	r, _, w, s, f, _ := actualHTTPFixture(t, 1)
	intent := Intent{OperationID: "foreign-retained-operation", RootID: "foreign-root", EntryID: "foreign-entry", Kind: "PUT", LocalGeneration: 1, TrustGeneration: 1, ExpectedAbsent: true, ParentID: "foreign-parent", Name: "foreign-file", NameKey: "foreign-file", FileIdentity: "foreign-file-identity", SizeBytes: 3}
	raw := mustJSON(intent)
	// Represents an existing legacy operation in another root of the same DB.
	// It has no candidate authority or artifact and must remain untouched.
	if _, err := r.store.db.Exec("INSERT INTO roots(root_id,mapping_id,server_identity,remote_root_id,device_id,source_identity,legacy_checkpoint) VALUES(?,?,?,?,?,?,?)", "foreign-root", "foreign-mapping", "foreign-server", "foreign-remote", "foreign-device", "foreign-source", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.db.Exec("INSERT INTO local_entries(root_id,entry_id,name_key,generation,descriptor_json) VALUES(?,?,?,?,?)", "foreign-root", "foreign-entry", "foreign-file", 1, "{}"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.db.Exec("INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,?,?,?,?,?,?,?)", intent.OperationID, intent.RootID, intent.EntryID, intent.LocalGeneration, intent.Kind, string(raw), fingerprint(intent), "PLANNED"); err != nil {
		t.Fatal(err)
	}
	report, err := runActualHTTPFixture(t, r, w, s)
	if err != nil || !report.Complete || report.Uploaded != 1 || report.Failed != 0 {
		t.Fatal("foreign-root pending leaked into selected report", report, err)
	}
	foreign, err := r.store.Operation(testContext, intent.OperationID)
	if err != nil || foreign.Stage != "PLANNED" || string(mustJSON(foreign.Intent)) != string(raw) {
		t.Fatal("foreign pending changed", foreign, err)
	}
	f.mu.Lock()
	uploads := len(f.uploads)
	f.mu.Unlock()
	if uploads != 1 {
		t.Fatal("foreign operation dispatched", uploads)
	}
}
