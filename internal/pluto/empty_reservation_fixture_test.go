//go:build linux

package pluto

import (
	"bytes"
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
	"strings"
	"syscall"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

type emptyOriginal struct {
	Source    string
	Payload   []byte
	Evidence  syncstate.SnapshotEvidence
	Operation syncstate.Operation
}
type emptyBackendImage struct {
	Binding  map[string]any
	Nodes    map[string]map[string]any
	Events   []map[string]any
	Folders  map[string]any
	Uploads  map[string]*cUpload
	Calls    map[string]int
	Sequence int
	Wire     []json.RawMessage
}
type emptyReservationFixture struct {
	base, state, source, root string
	session                   *IndexedSession
	server                    *cServer
	host                      *httptest.Server
	originals                 []emptyOriginal
	noCreate, created         string
	emptyInfo                 os.FileInfo
	backend                   []byte
	physical                  []admissionPhysicalEntry
	liveStore                 *syncstate.Store
	liveAdmission             *ArtifactAdmission
}

func emptyReservationID(t *testing.T) string {
	t.Helper()
	id, err := syncstate.NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func emptyCurrentFixture(t *testing.T, ctx context.Context) *emptyReservationFixture {
	t.Helper()
	input := os.Getenv("PLUTO_FAULT_INPUT_DIR")
	if input == "" || !filepath.IsAbs(input) || filepath.Clean(input) != input {
		t.Fatal("explicit private fixture input root required")
	}
	info, err := os.Lstat(input)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private fixture input root", err)
	}
	base, err := os.MkdirTemp(input, "retained-empty-")
	if err != nil {
		t.Fatal(err)
	}
	f := &emptyReservationFixture{base: base, state: filepath.Join(base, "state"), source: filepath.Join(base, "source"), root: emptyReservationID(t)}
	old := copyResources
	copyResources = newCopyBudget(2, 1, MaxFileBytes)
	t.Cleanup(func() {
		if f.session != nil {
			if err := f.session.Close(); err != nil {
				t.Error(err)
			}
		}
		if f.liveStore != nil {
			if err := f.liveStore.Close(); err != nil {
				t.Error(err)
			}
		}
		if f.liveAdmission != nil {
			if err := f.liveAdmission.Detach(); err != nil {
				t.Error(err)
			}
		}
		if f.host != nil {
			f.host.Close()
		}
		copyResources = old
	})
	if err = os.Mkdir(f.source, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		payload := []byte(fmt.Sprintf("current-original-%02d-0123456789abc", i))
		if len(payload) != 33 {
			t.Fatal("four exact33byte originals required")
		}
		name := filepath.Join(f.source, fmt.Sprintf("original-%02d.bin", i))
		if err = os.WriteFile(name, payload, 0600); err != nil {
			t.Fatal(err)
		}
		f.originals = append(f.originals, emptyOriginal{Source: name, Payload: payload})
	}
	remoteRoot := emptyReservationID(t)
	binding := map[string]any{"protocol": syncproto.Protocol, "descriptor_schema": syncproto.DescriptorSchema, "server_identity": "stage3-c", "root_id": remoteRoot, "server_epoch": emptyReservationID(t), "policy_version": "policy", "binding_version": emptyReservationID(t)}
	f.server = &cServer{t: t, binding: binding, nodes: map[string]map[string]any{remoteRoot: cFolder(remoteRoot, "", "backup")}, folders: map[string]any{}, uploads: map[string]*cUpload{}, calls: map[string]int{}}
	// This explicit isolated loopback contract constructs current private-capture
	// authority. It is not a production Saturn/PG/SFTP or daemon TLS qualification.
	f.host = httptest.NewServer(f.server)
	cfg := IndexedCommandConfig{Schema: IndexedProfileSchema, LocalRootID: f.root, MappingID: emptyReservationID(t), SourceSetID: emptyReservationID(t), Sources: []IndexedSourceConfig{{ID: "source", SelectedPath: f.source}}, Remote: syncstate.IsolatedHTTPConfig{Domain: syncstate.IsolatedHTTPContract, Origin: f.host.URL, AllowedAddresses: []string{"127.0.0.1"}, Binding: binding, DeviceID: cUUID(51), BackendIdentity: "backend-c", QualificationReceiptSHA256: cHash([]byte("qualification")), Token: "fixture-canary-credential"}}
	f.session, err = OpenIndexedSession(ctx, cfg, f.state, false)
	if err != nil {
		t.Fatal("actual isolated indexed session", err)
	}
	if err = f.session.Remote.EnableDaemonState(ctx); err != nil {
		t.Fatal("actual additive current schema8", err)
	}
	inspection, err := syncstate.InspectProfile(ctx, f.state)
	if err != nil || inspection.SchemaVersion != 8 {
		t.Fatal("current schema8 required", inspection, err)
	}
	scan := emptyReservationID(t)
	if _, err = f.session.Sources.BeginScan(ctx, f.session.Witness, "source", scan); err != nil {
		t.Fatal(err)
	}
	for {
		claim, e := f.session.Sources.ClaimScanFrontier(ctx, f.session.Witness, scan)
		if errors.Is(e, sql.ErrNoRows) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = f.session.Sources.ScanClaim(ctx, claim, nil); e != nil {
			t.Fatal(e)
		}
	}
	if err = f.session.Sources.CompleteScanScope(ctx, f.session.Witness, scan); err != nil {
		t.Fatal(err)
	}
	for i := range f.originals {
		original := &f.originals[i]
		entry, e := f.session.Sources.SourceEntry(ctx, f.session.Witness.SetID, strings.TrimLeft(filepath.ToSlash(original.Source), "/"))
		if e != nil {
			t.Fatal(e)
		}
		local, e := f.session.Remote.ProjectSourcePath(ctx, f.session.Witness, f.root, entry)
		if e != nil {
			t.Fatal(e)
		}
		value, e := f.session.Admission.Capture(ctx, f.session.Witness, entry)
		if e != nil {
			t.Fatal(e)
		}
		func() {
			retained := false
			defer func() {
				if !retained {
					if e := value.Retain(); e != nil {
						t.Error(e)
					}
				}
			}()
			if e = f.session.Sources.RecordVerifiedSnapshot(ctx, f.session.Witness, value); e != nil {
				t.Fatal("record genuine verified source evidence", e)
			}
			if e = f.session.Remote.ProjectCapturedEntry(ctx, f.session.Witness, f.root, local, value); e != nil {
				t.Fatal(e)
			}
			if e = f.session.HTTP.PrepareParents(ctx, f.session.Witness, f.root, local); e != nil {
				t.Fatal(e)
			}
			authority, e := f.session.HTTP.Authority(ctx)
			if e != nil {
				t.Fatal(e)
			}
			now := f.session.HTTP.ExecutionTime()
			decision, e := f.session.Remote.DecideCaptured(ctx, f.session.Witness, f.root, local, value, authority, now)
			if e != nil || decision.Kind != "CREATE" {
				t.Fatal("actual current CREATE decision", decision, e)
			}
			operation, e := f.session.Remote.PlanCaptured(ctx, f.session.Witness, value, authority, decision, emptyReservationID(t), now)
			if e != nil || operation.Captured == nil || operation.SizeBytes != 33 || operation.SnapshotID == "" {
				t.Fatal("actual current immutable captured operation", operation, e)
			}
			if e = f.session.Admission.Registry().BindOperation(ctx, operation.SnapshotID, operation.OperationID); e != nil {
				t.Fatal(e)
			}
			// Persist the real pre-I/O submission transition required by recovery.
			// This does not send bytes or claim backend acceptance/publication.
			if e = f.session.Remote.SubmittedCaptured(ctx, f.session.Witness, value, authority, operation.OperationID, now); e != nil {
				t.Fatal("actual captured submission before I/O", e)
			}
			operation, e = f.session.Store.Operation(ctx, operation.OperationID)
			if e != nil || operation.Stage != "SUBMITTED" || operation.Captured == nil {
				t.Fatal("actual submitted current captured operation", e)
			}
			original.Evidence = value.Evidence()
			original.Operation = operation
			if e = value.Retain(); e != nil {
				t.Fatal(e)
			}
			retained = true
		}()
	}
	registry := f.session.Admission.Registry()
	reserved, err := registry.Reserve(ctx, 33)
	if err != nil {
		t.Fatal(err)
	}
	f.noCreate = reserved.ID()
	if err = reserved.Relinquish(); err != nil {
		t.Fatal(err)
	}
	created, err := registry.Reserve(ctx, 33)
	if err != nil {
		t.Fatal(err)
	}
	f.created = created.ID()
	file, err := created.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	f.emptyInfo, err = file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = created.Relinquish(); err != nil {
		t.Fatal(err)
	}
	if record, e := registry.Record(ctx, f.noCreate); e != nil || record.Phase != syncstate.ArtifactReserved || record.FileIdentity != "" {
		t.Fatal("genuine Reserve-before-Create", record, e)
	}
	if record, e := registry.Record(ctx, f.created); e != nil || record.Phase != syncstate.ArtifactCapturing || record.FileIdentity == "" || record.SizeBytes != 0 {
		t.Fatal("genuine empty Create checkpoint", record, e)
	}
	charge, err := registry.Charge(ctx)
	if err != nil || charge != 198 {
		t.Fatal("foursealedplus2empty durable reservations", charge, err)
	}
	f.server.mu.Lock()
	f.backend, err = json.Marshal(emptyBackendImage{f.server.binding, f.server.nodes, f.server.events, f.server.folders, f.server.uploads, f.server.calls, f.server.seq, f.server.wire})
	uploads := len(f.server.uploads)
	f.server.mu.Unlock()
	if err != nil || uploads != 0 {
		t.Fatal("fixture creates no data publications", uploads, err)
	}
	if err = os.WriteFile(filepath.Join(f.state, "owned-protocol-backend.json"), f.backend, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.session.Close(); err != nil {
		t.Fatal("joined setup store/session", err)
	}
	f.session = nil
	f.host.Close()
	f.host = nil
	f.physical = emptyProtectedPhysical(t, f)
	return f
}
func emptyProtectedPhysical(t *testing.T, f *emptyReservationFixture) []admissionPhysicalEntry {
	t.Helper()
	all := admissionPhysical(t, f.state, f.source)
	var result []admissionPhysicalEntry
	for _, row := range all {
		if row.Kind != "file" {
			continue
		}
		if row.Path == filepath.Join(f.state, syncstate.ArtifactDirectoryName, f.created+".snapshot") {
			continue
		}
		result = append(result, row)
	}
	if len(result) != 8 {
		t.Fatal("four sources and four sealed originals required", len(result))
	}
	return result
}
func emptyAssertOriginals(t *testing.T, ctx context.Context, f *emptyReservationFixture, store *syncstate.Store, admission *ArtifactAdmission) {
	t.Helper()
	if !reflect.DeepEqual(f.physical, emptyProtectedPhysical(t, f)) {
		t.Fatal("originalsource/retainedinode/bytes/mode/timestamps changed")
	}
	for _, original := range f.originals {
		current, err := store.Operation(ctx, original.Operation.OperationID)
		if err != nil || !reflect.DeepEqual(current, original.Operation) {
			t.Fatal("current captured original identity/intent changed", err)
		}
		recovered, err := admission.Registry().RecoveryOperation(ctx, original.Evidence.SnapshotID)
		if err != nil || !reflect.DeepEqual(recovered, current) {
			t.Fatal("original recovery operation differs", err)
		}
		if err = admission.Registry().WithRecoveryReader(ctx, current, admission.reader, func(reader io.Reader) error {
			raw, e := io.ReadAll(io.LimitReader(reader, 34))
			if e != nil {
				return e
			}
			source, e := os.ReadFile(original.Source)
			if e != nil {
				return e
			}
			if !bytes.Equal(raw, original.Payload) || !bytes.Equal(source, raw) || cHash(raw) != original.Evidence.SHA256 {
				return fmt.Errorf("original recovery plaintext differs")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if copyResources.retainedBytes != 132 || copyResources.spoolBytes != 0 || copyResources.liveArtifactBytes != 0 || len(copyResources.workers) != 0 || len(copyResources.readers) != 0 || len(copyResources.enumerators) != 0 {
		t.Fatal("retained132accountingorjoinedcallbacks", copyResources.retainedBytes)
	}
}

// This backup covers the complete closed profile, four real source files,
// sealed artifacts and the owned loopback protocol state before recovery.
// A restored copy proves bytes/SQL readability, never relocated inode custody.
func qualifyEmptyReservationBackup(t *testing.T, f *emptyReservationFixture) *admissionClosedBackup {
	t.Helper()
	logical, count := admissionLogicalDigest(t, filepath.Join(f.state, "sync-state.sqlite"))
	physical := admissionPhysical(t, f.state, f.source)
	empty := emptyFilePhysical(t, filepath.Join(f.state, syncstate.ArtifactDirectoryName, f.created+".snapshot"))
	backendSHA := cHash(f.backend)
	var restoredNodes int
	backup := qualifyAdmissionClosedBackup(t, f.state, []string{f.source}, func(copy *syncstate.Store, copyState string) {
		for _, original := range f.originals {
			operation, err := copy.Operation(context.Background(), original.Operation.OperationID)
			if err != nil || !reflect.DeepEqual(operation, original.Operation) {
				t.Fatal("restored current captured operation", err)
			}
		}
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		digest, rows := admissionLogicalDigest(t, filepath.Join(copyState, "sync-state.sqlite"))
		if digest != logical || rows != count {
			t.Fatal("complete restored schema8 SQL differs")
		}
		inspection, err := syncstate.InspectProfile(context.Background(), copyState)
		if err != nil || inspection.SchemaVersion != 8 {
			t.Fatal("restored schema8 required", err)
		}
		db := admissionImmutableDB(t, filepath.Join(copyState, "sync-state.sqlite"))
		defer db.Close()
		var records int
		if err = db.QueryRow("SELECT count(*) FROM local_artifacts").Scan(&records); err != nil || records != 6 {
			t.Fatal("six actual artifact records required", err)
		}
		for _, original := range f.originals {
			var name, phase, digest, snapshot, operation string
			var size int64
			err = db.QueryRow("SELECT filename,phase,size_bytes,sha256,snapshot_id,operation_id FROM local_artifacts WHERE artifact_id=?", original.Evidence.SnapshotID).Scan(&name, &phase, &size, &digest, &snapshot, &operation)
			if err != nil || phase != syncstate.ArtifactSealed || size != 33 || digest != original.Evidence.SHA256 || snapshot != original.Evidence.SnapshotID || operation != original.Operation.OperationID || filepath.Base(name) != name {
				t.Fatal("restored actual sealed SQL", err)
			}
			retained, err := os.ReadFile(filepath.Join(copyState, syncstate.ArtifactDirectoryName, name))
			if err != nil {
				t.Fatal(err)
			}
			source, err := os.ReadFile(filepath.Join(filepath.Dir(copyState), "source-001", filepath.Base(original.Source)))
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(filepath.Join(copyState, syncstate.ArtifactDirectoryName, name))
			if err != nil || !bytes.Equal(retained, original.Payload) || !bytes.Equal(source, retained) || cHash(retained) != digest || info.Mode().Perm() != 0400 {
				t.Fatal("restored actual source and sealed plaintext", err)
			}
		}
		emptyPath := filepath.Join(copyState, syncstate.ArtifactDirectoryName, f.created+".snapshot")
		info, err := os.Lstat(emptyPath)
		if err != nil || !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0600 {
			t.Fatal("restored genuine empty inode bytes", err)
		}
		if _, err = os.Lstat(filepath.Join(copyState, syncstate.ArtifactDirectoryName, f.noCreate+".snapshot")); !os.IsNotExist(err) {
			t.Fatal("uncreated reservation must stay absent", err)
		}
		raw, err := os.ReadFile(filepath.Join(copyState, "owned-protocol-backend.json"))
		if err != nil || !bytes.Equal(raw, f.backend) {
			t.Fatal("complete restored owned protocol backend", err)
		}
		var image emptyBackendImage
		if err = json.Unmarshal(raw, &image); err != nil || len(image.Nodes) == 0 || len(image.Uploads) != 0 {
			t.Fatal("restored complete backend image", err)
		}
		restoredNodes = len(image.Nodes)
		handler := &cServer{t: t, binding: image.Binding, nodes: image.Nodes, events: image.Events, folders: image.Folders, uploads: image.Uploads, calls: image.Calls, seq: image.Sequence, wire: image.Wire}
		host := httptest.NewServer(handler)
		defer host.Close()
		request, err := http.NewRequest(http.MethodPost, host.URL+"/sync/v1/roots/"+image.Binding["root_id"].(string)+"/entries", strings.NewReader("{\"cursor\":\"entries-restored\"}"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer fixture-canary-credential")
		client := &http.Client{Timeout: 5 * time.Second}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("actual restored isolated HTTP readback", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		var result struct{ Items []map[string]any }
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil || len(result.Items) != restoredNodes {
			t.Fatal("restored actual protocol entries", response.StatusCode, readErr, closeErr)
		}
		for _, item := range result.Items {
			id, ok := item["node_id"].(string)
			if !ok || !reflect.DeepEqual(item, image.Nodes[id]) {
				t.Fatal("restored actual backend node differs")
			}
		}
	})
	if !reflect.DeepEqual(physical, admissionPhysical(t, f.state, f.source)) {
		t.Fatal("backup altered original physical graph")
	}
	admissionProofWrite(t, filepath.Join(backup.directory, "empty-restore.json"), map[string]any{
		"schema": "pluto.empty-reservation-restore.v1", "case": t.Name(), "at": time.Now().UTC(),
		"state": f.state, "source": f.source, "archiveSHA256": backup.archiveSHA, "logicalSHA256": logical, "logicalRows": count, "schemaVersion": 8,
		"originals": f.originals, "noCreateID": f.noCreate, "createdID": f.created, "originalPhysical": f.physical, "emptyBefore": empty,
		"backendSHA256": backendSHA, "restoredBackendNodes": restoredNodes, "restoredHTTPStatus": 200, "backendScope": "OWNED_LOOPBACK_ISOLATED_HTTP_PROTOCOL_FIXTURE",
		"actualCopiedStoreOpened": true, "allLogicalRowsRestored": true, "actualCopiedSourceAndSealedRead": true,
		"relocatedArtifactCustodyAdmitted": false, "historicalOriginalProbeExecuted": false, "historicalReaderExecuted": false,
	})
	return backup
}
func emptyFilePhysical(t *testing.T, name string) admissionPhysicalEntry {
	t.Helper()
	info, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("owned single-link regular evidence required")
	}
	digest, err := admissionFileDigest(name)
	if err != nil {
		t.Fatal(err)
	}
	return admissionPhysicalEntry{Path: name, Kind: "file", SHA256: digest, Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, Bytes: info.Size(), MTimeNS: info.ModTime().UnixNano(), CTimeNS: st.Ctim.Sec*1e9 + st.Ctim.Nsec}
}
func emptyRecordRecovery(t *testing.T, f *emptyReservationFixture, backup *admissionClosedBackup, reports []syncstate.ArtifactReport, records []syncstate.ArtifactRecord) {
	t.Helper()
	filename := filepath.Join(f.state, "sync-state.sqlite")
	for _, suffix := range []string{"-wal", "-journal"} {
		info, err := os.Stat(filename + suffix)
		if err == nil && info.Size() != 0 {
			t.Fatal("closed final store required")
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filename)
	if err != nil || len(raw) == 0 || len(raw) > 64<<20 {
		t.Fatal("bounded final SQLite required", err)
	}
	out, err := os.OpenFile(filepath.Join(backup.directory, "post-recovery.sqlite"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := out.Write(raw)
	syncErr, closeErr := out.Sync(), out.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	physical := emptyProtectedPhysical(t, f)
	if !reflect.DeepEqual(physical, f.physical) {
		t.Fatal("final protected originals differ")
	}
	logical, count := admissionLogicalDigest(t, filename)
	quarantine := emptyFilePhysical(t, filepath.Join(f.state, "sync-artifacts-quarantine-v1", f.created+".snapshot"))
	admissionProofWrite(t, filepath.Join(backup.directory, "empty-recovery.json"), map[string]any{
		"schema": "pluto.empty-reservation-recovery.v1", "case": t.Name(), "at": time.Now().UTC(), "state": f.state, "source": f.source,
		"archiveSHA256": backup.archiveSHA, "postSQLiteSHA256": cHash(raw), "postSQLiteBytes": len(raw), "postLogicalSHA256": logical, "postLogicalRows": count,
		"schemaVersion": 8, "reports": reports, "originals": f.originals, "records": records, "originalPhysical": physical, "quarantine": quarantine,
		"noCreateID": f.noCreate, "createdID": f.created, "originalInodesPreserved": true, "emptyOriginalInodeQuarantined": true,
		"originalCapturedOperationsPreserved": true, "recoveryPlaintextRead": true, "normalSameProfileReopenRounds": 2,
		"scope":        "current schema8 same-profile joined store reopen; four current captured operations and132retainedbytes; no actual process crash or real Saturn/PG/SFTP",
		"backendScope": "OWNED_LOOPBACK_ISOLATED_HTTP_PROTOCOL_FIXTURE", "historicalOriginalProbeExecuted": false, "historicalReaderExecuted": false,
	})
	t.Logf("EMPTY_RESERVATION_CURRENT_RECOVERY_QUALIFIED operations=4 bytes=132 reopenRounds=2 directory=%s", backup.directory)
}
