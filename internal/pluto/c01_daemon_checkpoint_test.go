//go:build linux

package pluto

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
)

// C01 keeps its original fault and assertions. This helper admits that fault
// only after a genuine complete checkpoint has been restored and read back.
func c01CheckpointRoot(t *testing.T, f *cDaemonFixture) string {
	t.Helper()
	root := os.Getenv("PLUTO_C01_CHECKPOINT_ROOT")
	if t.Name() != "TestStage3C01OrdinaryDaemonRestartBackupSemantics" || root != "/checkpoint" || f.processes == nil || f.processes.scope.Base != f.base {
		t.Fatal("exact Root-admitted C01 checkpoint scope required")
	}
	return root
}

func c01BackendBytes(t *testing.T, f *cDaemonFixture) []byte {
	t.Helper()
	f.server.mu.Lock()
	defer f.server.mu.Unlock()
	key, err := x509.MarshalPKCS8PrivateKey(f.http.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	image := preparedBackendImage{Binding: f.server.binding, Nodes: f.server.nodes, Events: f.server.events, Folders: f.server.folders, Uploads: f.server.uploads, Calls: f.server.calls, Sequence: f.server.seq, Wire: f.server.wire, Certificate: f.http.Certificate().Raw, PrivateKey: key}
	raw, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func c01Backup(t *testing.T, f *cDaemonFixture) (syncstate.ProfileBackup, []byte) {
	t.Helper()
	raw, err := f.command("checkpoint")
	if err != nil {
		t.Fatal("C01 checkpoint", string(raw), err)
	}
	raw, err = f.command("backup")
	if err != nil {
		t.Fatal("C01 actual backup", string(raw), err)
	}
	var backup syncstate.ProfileBackup
	if json.Unmarshal(raw, &backup) != nil || filepath.Base(backup.Filename) != backup.Filename || backup.Filename == "" || len(backup.SHA256) != 64 {
		t.Fatal("C01 actual backup receipt")
	}
	backup.Filename = filepath.Join(f.state, "indexed", "sync-state-backups", backup.Filename)
	data, err := os.ReadFile(backup.Filename)
	if err != nil || len(data) == 0 || len(data) > 64<<20 || cHash(data) != backup.SHA256 {
		t.Fatal("C01 actual backup bytes", err)
	}
	return backup, data
}

func qualifyC01DaemonCheckpoint(t *testing.T, f *cDaemonFixture) {
	t.Helper()
	root := c01CheckpointRoot(t, f)
	if raw, err := f.command("pause"); err != nil {
		t.Fatal("C01 checkpoint pause", string(raw), err)
	}
	backup, _ := c01Backup(t, f)
	backend := c01BackendBytes(t, f)
	var original preparedBackendImage
	if err := json.Unmarshal(backend, &original); err != nil || len(original.Uploads) != 1 {
		t.Fatal("C01 original pending receiver", err)
	}
	for _, upload := range original.Uploads {
		if upload.Result != nil || !bytes.Equal(upload.Bytes, []byte("fixture bytes")) {
			t.Fatal("C01 original pending bytes before fault")
		}
	}
	if err := os.WriteFile(filepath.Join(f.base, "reviewed-backup-backend.json"), backend, 0600); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"schema": "pluto.c01-checkpoint-request.v1", "case": t.Name(), "base": f.base, "backupFile": backup.Filename, "backupSHA256": backup.SHA256, "backendSHA256": cHash(backend), "uploads": 1}
	if err := SaveJSON(filepath.Join(root, "request.json"), request); err != nil {
		t.Fatal(err)
	}
	var ready struct{ Restored, ArchiveSHA256 string }
	if json.Unmarshal(waitPreparedFile(t, filepath.Join(root, "restore-ready.json")), &ready) != nil || ready.Restored != filepath.Join(root, "restored") || len(ready.ArchiveSHA256) != 64 {
		t.Fatal("C01 genuine restored checkpoint receipt")
	}
	restored := ready.Restored
	cfg, err := LoadConfig(filepath.Join(restored, "config.json"))
	if err != nil || cfg.Enabled || cfg.Indexed == nil {
		t.Fatal("C01 restored paused config", err)
	}
	originalInspection, err := syncstate.InspectProfile(context.Background(), filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	restoredInspection, err := syncstate.InspectProfile(context.Background(), filepath.Join(restored, "state", "indexed"))
	if err != nil || !reflect.DeepEqual(originalInspection, restoredInspection) || restoredInspection.SchemaVersion != 8 || restoredInspection.PendingOperations < 1 || restoredInspection.RetainedArtifacts < 1 {
		t.Fatal("C01 actual restored product inspection", err, originalInspection, restoredInspection)
	}
	recoveredRaw, err := os.ReadFile(filepath.Join(restored, "reviewed-backup-backend.json"))
	if err != nil || !bytes.Equal(recoveredRaw, backend) {
		t.Fatal("C01 restored complete receiver", err)
	}
	var recovered preparedBackendImage
	if err = json.Unmarshal(recoveredRaw, &recovered); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(restored, "source", "COMLPT1.md"))
	if err != nil || !bytes.Equal(source, []byte("fixture bytes")) {
		t.Fatal("C01 restored original source", err)
	}
	if stat, err := os.Stat(filepath.Join(restored, "source", "empty")); err != nil || !stat.IsDir() {
		t.Fatal("C01 restored empty directory", err)
	}
	for id, upload := range recovered.Uploads {
		if original.Uploads[id] == nil || upload.Result != nil || !bytes.Equal(upload.Bytes, source) || upload.Input["intent"].(map[string]any)["sha256"] != cHash(source) {
			t.Fatal("C01 restored pending identity and bytes")
		}
	}
	receiver := &cServer{t: t, binding: recovered.Binding, nodes: recovered.Nodes, events: recovered.Events, folders: recovered.Folders, uploads: recovered.Uploads, calls: map[string]int{}, seq: recovered.Sequence, wire: recovered.Wire}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: recovered.Certificate})
	certificate, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: recovered.PrivateKey}))
	if err != nil {
		t.Fatal(err)
	}
	restoredCA, err := os.ReadFile(filepath.Join(restored, "ca.pem"))
	if err != nil || !bytes.Equal(restoredCA, certPEM) {
		t.Fatal("C01 restored CA", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(restoredCA) {
		t.Fatal("C01 restored trust")
	}
	host := httptest.NewUnstartedServer(receiver)
	host.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	host.StartTLS()
	defer host.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	body, _ := json.Marshal(map[string]string{"cursor": "entries-restored"})
	req, err := http.NewRequest("POST", host.URL+"/sync/v1/roots/"+recovered.Binding["root_id"].(string)+"/entries", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("C01 restored authenticated TLS", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 {
		t.Fatal("C01 restored receiver readback", readErr, response.StatusCode)
	}
	var page struct{ Items []map[string]any }
	if err = json.Unmarshal(data, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != len(recovered.Nodes) {
		t.Fatal("C01 restored receiver nodes")
	}
	proof := map[string]any{"schema": "pluto.c01-checkpoint-go-proof.v1", "case": t.Name(), "base": f.base, "archiveSHA256": ready.ArchiveSHA256, "backupSHA256": backup.SHA256, "backendSHA256": cHash(recoveredRaw), "sourceFiles": 1, "sourceBytes": len(source), "uploads": 1, "pendingOperations": restoredInspection.PendingOperations, "retainedArtifacts": restoredInspection.RetainedArtifacts, "schemaVersion": restoredInspection.SchemaVersion, "productStoreOpened": true, "trustedReceiverHttpStatus": response.StatusCode, "receiverNodes": len(page.Items), "relocatedRecoveryAdmitted": false}
	if err = SaveJSON(filepath.Join(root, "restore-go-proof.json"), proof); err != nil {
		t.Fatal(err)
	}
	waitPreparedFile(t, "/native-prepared-backup-receipt.json")
	if raw, err := f.command("resume"); err != nil {
		t.Fatal("C01 resume original before original crash", string(raw), err)
	}
	t.Log("C01 genuine checkpoint restored and read back before original reviewed crash; no relocated custody claim")
}

func preserveC01DaemonOutcome(t *testing.T, f *cDaemonFixture, first, second []byte) {
	t.Helper()
	root := c01CheckpointRoot(t, f)
	backup, data := c01Backup(t, f)
	destination := filepath.Join(root, "postfault.sqlite")
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	backend := c01BackendBytes(t, f)
	if err = os.WriteFile(filepath.Join(root, "postfault-backend.json"), backend, 0600); err != nil {
		t.Fatal(err)
	}
	var image preparedBackendImage
	if err = json.Unmarshal(backend, &image); err != nil || len(image.Uploads) != 2 {
		t.Fatal("C01 final receiver", err)
	}
	for _, u := range image.Uploads {
		if u.Result == nil || u.Input["intent"].(map[string]any)["sha256"] != cHash(u.Bytes) {
			t.Fatal("C01 final real receipt and bytes")
		}
	}
	proof := map[string]any{"schema": "pluto.c01-postfault.v1", "case": t.Name(), "base": f.base, "backup": backup, "sqliteSHA256": cHash(data), "backendSHA256": cHash(backend), "firstSession": json.RawMessage(first), "secondSession": json.RawMessage(second), "uploads": 2, "originalLocalDeleted": true, "remoteOriginalRetained": true, "historicalReader": false}
	if err = SaveJSON(filepath.Join(root, "postfault.json"), proof); err != nil {
		t.Fatal(err)
	}
}
