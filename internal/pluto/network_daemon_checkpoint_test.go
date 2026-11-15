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

type networkDaemonScenario struct {
	Kind, SourceName, Payload string
	Committed                 bool
}

func networkCheckpointScope(t *testing.T, f *cDaemonFixture) (string, networkDaemonScenario) {
	t.Helper()
	root := os.Getenv("PLUTO_NETWORK_CHECKPOINT_ROOT")
	if root != "/checkpoint" || f.processes == nil || f.processes.scope.Base != f.base {
		t.Fatal("exact Root-admitted network checkpoint scope required")
	}
	var scenario networkDaemonScenario
	switch t.Name() {
	case "TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal":
		scenario = networkDaemonScenario{"proxy", "pending.md", "sealed before proxy transition", false}
	case "TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent":
		scenario = networkDaemonScenario{"route", "original.md", "route retained bytes", true}
	default:
		t.Fatal("unreviewed network daemon checkpoint case")
	}
	return root, scenario
}

func checkNetworkBeforeContext(t *testing.T, f *cDaemonFixture, s networkDaemonScenario, context map[string]any) {
	t.Helper()
	if s.Kind == "proxy" {
		first, ok := context["firstProxy"].(string)
		second, ok2 := context["secondProxy"].(string)
		firstHits, ok3 := context["firstHits"].(int64)
		secondHits, ok4 := context["secondHits"].(int64)
		if !ok || !ok2 || !ok3 || !ok4 || first == "" || first == second || first != f.cfg.Proxy.URL || f.cfg.Proxy.Mode != "explicit" || firstHits < 1 || secondHits != 0 {
			t.Fatal("original first-only explicit proxy context required", context)
		}
	} else if context["offline"] != true || context["lost"] != true {
		t.Fatal("original committed reply loss and owned route outage required", context)
	}
}

func qualifyNetworkDaemonCheckpoint(t *testing.T, f *cDaemonFixture, callerContext func() map[string]any) {
	t.Helper()
	root, scenario := networkCheckpointScope(t, f)
	beforeContext := callerContext()
	checkNetworkBeforeContext(t, f, scenario, beforeContext)
	if raw, err := f.command("pause"); err != nil {
		t.Fatal("NETWORK checkpoint pause", string(raw), err)
	}
	backup, _ := c01Backup(t, f)
	backend := c01BackendBytes(t, f)
	var original preparedBackendImage
	if err := json.Unmarshal(backend, &original); err != nil || len(original.Uploads) != 1 {
		t.Fatal("NETWORK original pending receiver", err)
	}
	for _, upload := range original.Uploads {
		if (upload.Result != nil) != scenario.Committed || !bytes.Equal(upload.Bytes, []byte(scenario.Payload)) {
			t.Fatal("NETWORK original pending bytes before fault")
		}
	}
	if err := os.WriteFile(filepath.Join(f.base, "reviewed-backup-backend.json"), backend, 0600); err != nil {
		t.Fatal(err)
	}
	contextRaw, err := json.Marshal(map[string]any{"schema": "pluto.network-checkpoint-context.v1", "case": t.Name(), "scenario": scenario, "caller": beforeContext, "proxy": f.cfg.Proxy})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.base, "network-backup-context.json"), contextRaw, 0600); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"schema": "pluto.network-checkpoint-request.v1", "case": t.Name(), "base": f.base, "backupFile": backup.Filename, "backupSHA256": backup.SHA256, "backendSHA256": cHash(backend), "uploads": 1, "scenario": scenario.Kind, "contextSHA256": cHash(contextRaw)}
	if err := SaveJSON(filepath.Join(root, "request.json"), request); err != nil {
		t.Fatal(err)
	}
	var ready struct{ Restored, ArchiveSHA256 string }
	if json.Unmarshal(waitPreparedFile(t, filepath.Join(root, "restore-ready.json")), &ready) != nil || ready.Restored != filepath.Join(root, "restored") || len(ready.ArchiveSHA256) != 64 {
		t.Fatal("NETWORK genuine restored checkpoint receipt")
	}
	restored := ready.Restored
	cfg, err := LoadConfig(filepath.Join(restored, "config.json"))
	if err != nil || cfg.Enabled || cfg.Indexed == nil || !reflect.DeepEqual(cfg.Proxy, f.cfg.Proxy) {
		t.Fatal("NETWORK restored paused config", err)
	}
	originalInspection, err := syncstate.InspectProfile(context.Background(), filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	restoredInspection, err := syncstate.InspectProfile(context.Background(), filepath.Join(restored, "state", "indexed"))
	if err != nil || !reflect.DeepEqual(originalInspection, restoredInspection) || restoredInspection.SchemaVersion != 8 || restoredInspection.PendingOperations < 1 || restoredInspection.RetainedArtifacts < 1 {
		t.Fatal("NETWORK actual restored product inspection", err, originalInspection, restoredInspection)
	}
	recoveredRaw, err := os.ReadFile(filepath.Join(restored, "reviewed-backup-backend.json"))
	if err != nil || !bytes.Equal(recoveredRaw, backend) {
		t.Fatal("NETWORK restored complete receiver", err)
	}
	var recovered preparedBackendImage
	if err = json.Unmarshal(recoveredRaw, &recovered); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(restored, "source", scenario.SourceName))
	if err != nil || !bytes.Equal(source, []byte(scenario.Payload)) {
		t.Fatal("NETWORK restored original source", err)
	}
	for id, upload := range recovered.Uploads {
		if original.Uploads[id] == nil || (upload.Result != nil) != scenario.Committed || !bytes.Equal(upload.Bytes, source) || upload.Input["intent"].(map[string]any)["sha256"] != cHash(source) {
			t.Fatal("NETWORK restored pending identity and bytes")
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
		t.Fatal("NETWORK restored CA", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(restoredCA) {
		t.Fatal("NETWORK restored trust")
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
		t.Fatal("NETWORK restored authenticated TLS", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 {
		t.Fatal("NETWORK restored receiver readback", readErr, response.StatusCode)
	}
	var page struct{ Items []map[string]any }
	if err = json.Unmarshal(data, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != len(recovered.Nodes) {
		t.Fatal("NETWORK restored receiver nodes")
	}
	proof := map[string]any{"schema": "pluto.network-checkpoint-go-proof.v1", "case": t.Name(), "base": f.base, "archiveSHA256": ready.ArchiveSHA256, "backupSHA256": backup.SHA256, "backendSHA256": cHash(recoveredRaw), "sourceFiles": 1, "sourceBytes": len(source), "uploads": 1, "pendingOperations": restoredInspection.PendingOperations, "retainedArtifacts": restoredInspection.RetainedArtifacts, "schemaVersion": restoredInspection.SchemaVersion, "productStoreOpened": true, "trustedReceiverHttpStatus": response.StatusCode, "receiverNodes": len(page.Items), "relocatedRecoveryAdmitted": false, "scenario": scenario.Kind, "committedBeforeCrash": scenario.Committed, "contextSHA256": cHash(contextRaw)}
	if err = SaveJSON(filepath.Join(root, "restore-go-proof.json"), proof); err != nil {
		t.Fatal(err)
	}
	waitPreparedFile(t, "/native-prepared-backup-receipt.json")
	if raw, err := f.command("resume"); err != nil {
		t.Fatal("NETWORK resume original before original crash", string(raw), err)
	}
	afterContext := callerContext()
	checkNetworkBeforeContext(t, f, scenario, afterContext)
	if err = SaveJSON(filepath.Join(root, "before-fault-context.json"), map[string]any{"case": t.Name(), "scenario": scenario.Kind, "contextSHA256": cHash(contextRaw), "before": beforeContext, "afterResume": afterContext, "originalFaultNotYetExecuted": true}); err != nil {
		t.Fatal(err)
	}
	t.Log("NETWORK genuine checkpoint restored and read back before original reviewed crash; direct trusted receiver probe does not claim relocated proxy/custody restoration")
}

func preserveNetworkDaemonOutcome(t *testing.T, f *cDaemonFixture, callerContext func() map[string]any) {
	t.Helper()
	root, scenario := networkCheckpointScope(t, f)
	if scenario.Kind == "proxy" {
		cAwait(t, func() bool {
			s := f.status()
			return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
		})
		if raw, err := f.command("pause"); err != nil {
			t.Fatal("network final pause", string(raw), err)
		}
	}
	finalContext := callerContext()
	if scenario.Kind == "proxy" {
		old, ok := finalContext["oldHits"].(int64)
		first, ok2 := finalContext["firstHits"].(int64)
		second, ok3 := finalContext["secondHits"].(int64)
		if !ok || !ok2 || !ok3 || old < 1 || first != old || second < 1 {
			t.Fatal("original proxy transition changed", finalContext)
		}
	} else if finalContext["offline"] != false || finalContext["lost"] != true || f.status().Observation.Enabled {
		t.Fatal("route recovery must preserve final paused state", finalContext)
	}
	source := filepath.Join(f.source, scenario.SourceName)
	sourceRaw, sourceErr := os.ReadFile(source)
	sourceFact := map[string]any{"exists": sourceErr == nil}
	if scenario.Kind == "proxy" {
		if !os.IsNotExist(sourceErr) {
			t.Fatal("deleted original must remain absent", sourceErr)
		}
	} else {
		if sourceErr != nil || !bytes.Equal(sourceRaw, []byte(scenario.Payload)) {
			t.Fatal("route original changed", sourceErr)
		}
		sourceFact["bytes"] = len(sourceRaw)
		sourceFact["sha256"] = cHash(sourceRaw)
	}
	backup, data := c01Backup(t, f)
	file, err := os.OpenFile(filepath.Join(root, "postfault.sqlite"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	if err = json.Unmarshal(backend, &image); err != nil || len(image.Uploads) != 1 {
		t.Fatal("one original network publication required", err)
	}
	for _, u := range image.Uploads {
		if u.Result == nil || !bytes.Equal(u.Bytes, []byte(scenario.Payload)) || u.Input["intent"].(map[string]any)["sha256"] != cHash(u.Bytes) {
			t.Fatal("original network publication identity/bytes")
		}
	}
	cfg, err := LoadConfig(f.config)
	if err != nil || cfg.Enabled {
		t.Fatal("final paused native config", err)
	}
	proof := map[string]any{"schema": "pluto.network-postfault.v1", "case": t.Name(), "base": f.base, "scenario": scenario.Kind, "backup": backup, "sqliteSHA256": cHash(data), "backendSHA256": cHash(backend), "uploads": 1, "source": sourceFact, "caller": finalContext, "proxy": cfg.Proxy, "paused": true, "historicalReader": false}
	if err = SaveJSON(filepath.Join(root, "postfault.json"), proof); err != nil {
		t.Fatal(err)
	}
}
