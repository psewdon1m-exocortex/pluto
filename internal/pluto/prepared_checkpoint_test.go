//go:build linux

package pluto

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

type preparedBackendImage struct {
	Binding     map[string]any
	Nodes       map[string]map[string]any
	Events      []map[string]any
	Folders     map[string]any
	Uploads     map[string]*cUpload
	Calls       map[string]int
	Sequence    int
	Wire        []json.RawMessage
	Certificate []byte
	PrivateKey  []byte
}

func waitPreparedFile(t *testing.T, name string) []byte {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		raw, err := os.ReadFile(name)
		if err == nil {
			return raw
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("prepared checkpoint deadline at %s", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func qualifyPreparedCheckpoint(t *testing.T, f *cDaemonFixture, candidate IndexedCommandConfig, plan AdoptionPlan) {
	t.Helper()
	if t.Name() != "TestStage3C12NativeReviewedPolicyScopesAndRestart" || f.processes == nil || f.processes.scope.Base != f.base {
		t.Fatal("original owner-admitted prepared checkpoint scope required")
	}
	checkpointRoot, backupReceipt, err := f.processes.scope.PreparedCheckpointPaths()
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := f.command("checkpoint"); err != nil {
		t.Fatal("checkpoint", string(raw), err)
	}
	raw, err := f.command("backup")
	if err != nil {
		t.Fatal("backup", string(raw), err)
	}
	var backup syncstate.ProfileBackup
	if json.Unmarshal(raw, &backup) != nil || backup.Filename == "" || len(backup.SHA256) != 64 {
		t.Fatal("native backup receipt")
	}
	if filepath.Base(backup.Filename) != backup.Filename {
		t.Fatal("native backup basename required")
	}
	backup.Filename = filepath.Join(f.state, "indexed", "sync-state-backups", backup.Filename)
	backupRaw, err := os.ReadFile(backup.Filename)
	if err != nil || cHash(backupRaw) != backup.SHA256 {
		t.Fatal("native backup bytes", err)
	}
	f.server.mu.Lock()
	key, err := x509.MarshalPKCS8PrivateKey(f.http.TLS.Certificates[0].PrivateKey)
	if err != nil {
		f.server.mu.Unlock()
		t.Fatal(err)
	}
	image := preparedBackendImage{
		Binding: f.server.binding, Nodes: f.server.nodes, Events: f.server.events,
		Folders: f.server.folders, Uploads: f.server.uploads, Calls: f.server.calls,
		Sequence: f.server.seq, Wire: f.server.wire, Certificate: f.http.Certificate().Raw, PrivateKey: key,
	}
	backend, err := json.Marshal(image)
	f.server.mu.Unlock()
	if err != nil || len(image.Uploads) != 260 {
		t.Fatal("complete stopped receiver", err, len(image.Uploads))
	}
	if err = os.WriteFile(filepath.Join(f.base, "reviewed-backup-backend.json"), backend, 0600); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"schema": "pluto.prepared-checkpoint-request.v1", "case": t.Name(),
		"base": f.base, "backupFile": backup.Filename, "backupSHA256": backup.SHA256,
		"backendSHA256": cHash(backend), "planDigest": plan.Digest, "uploads": 260}
	if err = SaveJSON(filepath.Join(checkpointRoot, "request.json"), request); err != nil {
		t.Fatal(err)
	}
	var ready struct {
		Restored      string
		ArchiveSHA256 string
	}
	if json.Unmarshal(waitPreparedFile(t, filepath.Join(checkpointRoot, "restore-ready.json")), &ready) != nil ||
		ready.Restored != filepath.Join(checkpointRoot, "restored") || len(ready.ArchiveSHA256) != 64 {
		t.Fatal("restored checkpoint receipt")
	}
	restored := ready.Restored
	cfg, err := LoadConfig(filepath.Join(restored, "config.json"))
	if err != nil || cfg.Enabled || cfg.Indexed == nil {
		t.Fatal("restored paused profile", err)
	}
	originalInspection, err := syncstate.InspectProfile(context.Background(), filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	restoredInspection, err := syncstate.InspectProfile(context.Background(), filepath.Join(restored, "state", "indexed"))
	if err != nil || !reflect.DeepEqual(originalInspection, restoredInspection) || restoredInspection.SchemaVersion != 8 {
		t.Fatal("actual restored product store", err, originalInspection, restoredInspection)
	}
	restoredPlan, err := inspectAdoption(context.Background(), filepath.Join(restored, "state"), cfg, candidate)
	if err != nil || restoredPlan.Digest != plan.Digest || restoredPlan.Existing == nil ||
		restoredPlan.Existing.Acknowledged != plan.Existing.Acknowledged || restoredPlan.Existing.Pending != 0 {
		t.Fatal("restored adoption plan and original acknowledgments", err)
	}
	recoveredRaw, err := os.ReadFile(filepath.Join(restored, "reviewed-backup-backend.json"))
	if err != nil || !bytes.Equal(recoveredRaw, backend) {
		t.Fatal("restored backend bytes", err)
	}
	var recovered preparedBackendImage
	if err = json.Unmarshal(recoveredRaw, &recovered); err != nil {
		t.Fatal(err)
	}
	receiver := &cServer{t: t, binding: recovered.Binding, nodes: recovered.Nodes, events: recovered.Events,
		folders: recovered.Folders, uploads: recovered.Uploads, calls: map[string]int{}, seq: recovered.Sequence, wire: recovered.Wire}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: recovered.Certificate})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: recovered.PrivateKey})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal("restored TLS key", err)
	}
	restoredCA, err := os.ReadFile(filepath.Join(restored, "ca.pem"))
	if err != nil || !bytes.Equal(restoredCA, certPEM) {
		t.Fatal("restored trust authority", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(restoredCA) {
		t.Fatal("restored CA")
	}
	host := httptest.NewUnstartedServer(receiver)
	host.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	host.StartTLS()
	defer host.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	url := host.URL + "/sync/v1/roots/" + recovered.Binding["root_id"].(string) + "/entries"
	reqBody, _ := json.Marshal(map[string]string{"cursor": "entries-restored"})
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("restored native trust and receiver", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 {
		t.Fatal("restored backend readback", readErr, response.StatusCode)
	}
	var entries struct{ Items []map[string]any }
	if json.Unmarshal(body, &entries) != nil {
		t.Fatal("restored page")
	}
	files := 0
	for _, entry := range entries.Items {
		if entry["type"] == "file" {
			files++
		}
	}
	if files != 260 || len(recovered.Uploads) != 260 {
		t.Fatal("restored physical originals", files)
	}
	expected := map[string]int{}
	for index := 0; index < 260; index++ {
		dir := "source"
		if index >= 130 {
			dir = filepath.Join("second", ".hidden")
		}
		original, err := os.ReadFile(filepath.Join(restored, dir, fmt.Sprintf("file-%03d", index)))
		if err != nil || !bytes.Equal(original, []byte{byte(index)}) {
			t.Fatal("restored source", index, err)
		}
		expected[cHash(original)]++
	}
	for _, upload := range recovered.Uploads {
		intent := upload.Input["intent"].(map[string]any)
		digest := cHash(upload.Bytes)
		if upload.Result == nil || intent["sha256"] != digest || expected[digest] < 1 {
			t.Fatal("restored uploaded original")
		}
		expected[digest]--
	}
	for _, count := range expected {
		if count != 0 {
			t.Fatal("restored original multiset")
		}
	}
	proof := map[string]any{"schema": "pluto.prepared-checkpoint-go-proof.v1", "case": t.Name(),
		"base": f.base, "planDigest": plan.Digest, "archiveSHA256": ready.ArchiveSHA256,
		"backupSHA256": backup.SHA256, "backendSHA256": cHash(recoveredRaw),
		"sourceFiles": files, "uploads": len(recovered.Uploads), "acknowledged": restoredPlan.Existing.Acknowledged,
		"schemaVersion": restoredInspection.SchemaVersion, "productStoreOpened": true, "trustedReceiverHttpStatus": response.StatusCode}
	if err = SaveJSON(filepath.Join(checkpointRoot, "restore-go-proof.json"), proof); err != nil {
		t.Fatal(err)
	}
	waitPreparedFile(t, backupReceipt)
	t.Log("same-profile checkpoint restored, product store opened and 260 authenticated receiver originals read back")
}
