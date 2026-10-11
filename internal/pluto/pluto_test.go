package pluto

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type remoteFixture struct {
	mu      sync.Mutex
	files   map[string][]byte
	folders map[string]bool
	uploads int
	revoked bool
	server  *httptest.Server
}

func fixture(t *testing.T) *remoteFixture {
	t.Helper()
	f := &remoteFixture{files: map[string][]byte{}, folders: map[string]bool{"": true}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/register/resolve" {
			if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("k", 43) {
				w.WriteHeader(401)
				return
			}
			u, _ := url.Parse(f.server.URL)
			json.NewEncoder(w).Encode(map[string]any{"values": map[string]any{"services.saturn.sni": map[string]string{"value": u.Hostname()}, "services.saturn.port": map[string]string{"value": u.Port()}, "repositories.pluto.url": map[string]string{"value": "https://github.com/example/pluto"}}})
			return
		}
		if r.URL.Path == "/api/v1/pluto/enrollments/redeem" {
			json.NewEncoder(w).Encode(map[string]any{"token": strings.Repeat("t", 43), "device": map[string]string{"name": "Outside", "deviceKind": "pluto", "syncFolderName": "Outside"}})
			return
		}
		if f.revoked || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 43) {
			w.WriteHeader(401)
			return
		}
		p := r.URL.Query().Get("path")
		if r.URL.Path == "/api/v1/pluto/check-in" {
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		if r.URL.Path == "/api/v1/pluto/folders" {
			var input struct{ Path string }
			json.NewDecoder(r.Body).Decode(&input)
			f.folders[input.Path] = true
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		if r.Method == "GET" {
			if f.folders[p] {
				json.NewEncoder(w).Encode(Metadata{Type: "folder"})
				return
			}
			data, ok := f.files[p]
			if !ok {
				w.WriteHeader(404)
				return
			}
			h := sha256.Sum256(data)
			json.NewEncoder(w).Encode(Metadata{Type: "file", SHA256: hex.EncodeToString(h[:]), SizeBytes: int64(len(data)), ETag: `"` + hex.EncodeToString(h[:]) + `"`})
			return
		}
		if r.Method == "PUT" {
			data, _ := io.ReadAll(r.Body)
			h := sha256.Sum256(data)
			if r.Header.Get("X-Content-Sha256") != hex.EncodeToString(h[:]) || r.ContentLength != int64(len(data)) {
				w.WriteHeader(400)
				return
			}
			if previous, exists := f.files[p]; exists {
				old := sha256.Sum256(previous)
				if r.Header.Get("If-Match") != `"`+hex.EncodeToString(old[:])+`"` {
					w.WriteHeader(412)
					return
				}
			} else if r.Header.Get("If-None-Match") != "*" {
				w.WriteHeader(428)
				return
			}
			f.files[p] = data
			f.uploads++
			json.NewEncoder(w).Encode(Metadata{Type: "file", SHA256: hex.EncodeToString(h[:]), SizeBytes: int64(len(data))})
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(f.server.Close)
	return f
}
func TestCopiesStructureEmptyFoldersAndOnlyChangedBytes(t *testing.T) {
	f := fixture(t)
	directory := t.TempDir()
	sources := filepath.Join(directory, "sources")
	os.MkdirAll(filepath.Join(sources, "empty"), 0700)
	name := filepath.Join(sources, "settings ü.conf")
	os.WriteFile(name, []byte("first"), 0600)
	remote := Remote{f.server.Client(), f.server.URL, strings.Repeat("t", 43)}
	count, err := Copy(context.Background(), remote, []string{sources, name}, filepath.Join(directory, "spool"))
	if err != nil || count != 1 {
		t.Fatalf("first copy: %d %v", count, err)
	}
	relative := RelativePath(name)
	empty := RelativePath(filepath.Join(sources, "empty"))
	if string(f.files[relative]) != "first" || !f.folders[empty] {
		t.Fatal("source hierarchy or empty folder lost")
	}
	count, err = Copy(context.Background(), remote, []string{sources}, filepath.Join(directory, "spool"))
	if err != nil || count != 0 || f.uploads != 1 {
		t.Fatalf("unchanged file uploaded: %d %v", count, err)
	}
	os.WriteFile(name, []byte("second"), 0600)
	count, err = Copy(context.Background(), remote, []string{sources}, filepath.Join(directory, "spool"))
	if err != nil || count != 1 || string(f.files[relative]) != "second" {
		t.Fatalf("changed file: %d %v", count, err)
	}
	os.Remove(name)
	_, err = Copy(context.Background(), remote, []string{sources}, filepath.Join(directory, "spool"))
	if err != nil || string(f.files[relative]) != "second" {
		t.Fatal("source deletion changed retained backup")
	}
	entries, _ := os.ReadDir(filepath.Join(directory, "spool"))
	if len(entries) != 0 {
		t.Fatal("plaintext spool remains")
	}
}

func TestUnreadableSourceDoesNotPreventHealthyFiles(t *testing.T) {
	f := fixture(t)
	dir := t.TempDir()
	valid := filepath.Join(dir, "valuable.conf")
	if err := os.WriteFile(valid, []byte("healthy"), 0600); err != nil {
		t.Fatal(err)
	}
	remote := Remote{f.server.Client(), f.server.URL, strings.Repeat("t", 43)}
	count, err := Copy(context.Background(), remote, []string{filepath.Join(dir, "missing"), valid}, filepath.Join(dir, "spool"))
	if count != 1 || err == nil || string(f.files[RelativePath(valid)]) != "healthy" {
		t.Fatalf("partial failure lost a healthy source: %d %v", count, err)
	}
	entries, readErr := os.ReadDir(filepath.Join(dir, "spool"))
	if readErr != nil || len(entries) != 0 {
		t.Fatal("spool was not cleaned", readErr)
	}
}

func TestAuditRotationAndPersistenceFailureAreObservable(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(name, make([]byte, 512*1024), 0600); err != nil {
		t.Fatal(err)
	}
	if err := appendAudit(name, "copy.completed", map[string]any{"files": 2}); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(name)
	if err != nil || current.Size() > 1024 {
		t.Fatal("audit rotation failed", err)
	}
	previous, err := os.Stat(name + ".previous")
	if err != nil || previous.Size() != 512*1024 {
		t.Fatal("previous audit missing", err)
	}
	s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigPath = dir
	s.persistConfigLocked()
	if !s.persistDirty || !strings.Contains(s.Status().Observation.Error, "persistence failed") {
		t.Fatal("configuration error is not observable")
	}
}
func TestCopiesEmptyFileWithZeroContentLength(t *testing.T) {
	f := fixture(t)
	dir := t.TempDir()
	filename := filepath.Join(dir, "empty.conf")
	if err := os.WriteFile(filename, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	count, err := Copy(context.Background(), Remote{f.server.Client(), f.server.URL, strings.Repeat("t", 43)}, []string{filename}, filepath.Join(dir, "spool"))
	if err != nil || count != 1 {
		t.Fatalf("empty file: %d %v", count, err)
	}
	if data, ok := f.files[RelativePath(filename)]; !ok || len(data) != 0 {
		t.Fatal("empty file missing")
	}
}

func TestConfigurationRejectsUnsafeSourcesAndOrigins(t *testing.T) {
	for _, origin := range []string{"http://kernel.test", "https://token@kernel.test", "https://kernel.test/path", "https://kernel.test?token=secret"} {
		if _, err := HTTPSOrigin(origin); err == nil {
			t.Fatalf("accepted %s", origin)
		}
	}
	if _, err := ValidateSources([]string{"relative"}); err == nil {
		t.Fatal("accepted relative path")
	}
	if _, err := ValidateSources([]string{string(filepath.Separator)}); err == nil {
		t.Fatal("accepted entire root")
	}
	if runtime.GOOS == "linux" {
		file := filepath.Join(t.TempDir(), "symlink")
		os.Symlink(t.TempDir(), file)
		if _, err := ValidateSources([]string{file}); err == nil {
			t.Fatal("accepted directory symlink")
		}
	}
}
func TestEnrollmentRemainsDisabledAndTokensNeverEnterStatus(t *testing.T) {
	f := fixture(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "config.txt")
	os.WriteFile(source, []byte("contents"), 0600)
	service, err := NewService(filepath.Join(dir, "config.json"), dir, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	service.HTTP = f.server.Client()
	ctx := context.Background()
	for _, control := range []Control{{Action: "connect", KernelURL: f.server.URL, Token: strings.Repeat("k", 43)}, {Action: "sources", Sources: []string{source}}, {Action: "interval", IntervalSeconds: 60}, {Action: "enroll", Code: strings.Repeat("c", 32)}} {
		if err = service.Apply(ctx, control); err != nil {
			t.Fatal(err)
		}
	}
	status := service.Status()
	if !status.Connected || status.Observation.Enabled || status.ConnectionName != "Outside" {
		t.Fatal("enrollment enabled copying or lost name")
	}
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), strings.Repeat("t", 43)) || strings.Contains(string(raw), strings.Repeat("k", 43)) {
		t.Fatal("credentials exposed")
	}
	loaded, _ := LoadConfig(service.ConfigPath)
	if loaded.AccessToken != strings.Repeat("t", 43) || loaded.Enabled {
		t.Fatal("configuration not persisted")
	}
	if err = service.Apply(ctx, Control{Action: "enabled", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if !service.Status().Observation.Enabled {
		t.Fatal("copying not enabled")
	}
	if err = service.Apply(ctx, Control{Action: "interval", IntervalSeconds: 120}); err != nil {
		t.Fatal(err)
	}
	next, err := time.Parse(time.RFC3339Nano, service.Status().Observation.NextRunAt)
	if err != nil || time.Until(next) < 119*time.Second || time.Until(next) > 121*time.Second {
		t.Fatal("changed interval did not update the next run")
	}
	if err = service.Apply(ctx, Control{Action: "enabled", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	f.revoked = true
	if err = service.Apply(ctx, Control{Action: "run"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for service.Status().Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if service.Status().Connected || service.Status().Observation.Enabled || service.Status().Observation.Error == "" {
		t.Fatal("revoke did not disconnect agent")
	}
	if runtime.GOOS == "linux" {
		info, _ := os.Stat(service.ConfigPath)
		if info.Mode().Perm() != 0600 {
			t.Fatal("configuration permissions expose credentials")
		}
	}
}
func TestSignedReleaseRejectsTamperingAndUnknownKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 3072)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	artifact := Artifact{URL: "https://github.com/example/pluto/releases/download/pluto-v0.1.0/pluto-linux-amd64", SHA256: strings.Repeat("a", 64), Size: 100}
	raw, _ := json.Marshal(Release{Schema: 1, Version: "0.1.0", Artifacts: map[string]Artifact{"linux-amd64": artifact, "linux-arm64": artifact}})
	hash := sha256.Sum256(raw)
	signature, _ := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	keyID := sha256.Sum256(pub)
	sig, _ := json.Marshal(map[string]string{"schema": "exocortex.release-signature.v1", "algorithm": "RSA-PSS-SHA256", "key_id": hex.EncodeToString(keyID[:]), "signature": base64.StdEncoding.EncodeToString(signature)})
	if r, err := VerifyRelease(raw, sig, encoded); err != nil || r.Version != "0.1.0" {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(append(raw, ' '), sig, encoded); err == nil {
		t.Fatal("accepted modified manifest")
	}
	if _, err := VerifyRelease(raw, []byte("invalid"), encoded); err == nil {
		t.Fatal("accepted unsigned manifest")
	}
	if _, err := VerifyRelease(raw, sig, ""); err == nil {
		t.Fatal("accepted missing trust anchor")
	}
}
func TestUpdateRestoresPreviousBinaryAfterFailedStart(t *testing.T) {
	if !newerVersion("0.10.0", "0.9.12") || newerVersion("0.1.0", "0.1.0") || newerVersion("0.1.0", "0.2.0") || newerVersion("invalid", "0.1.0") {
		t.Fatal("release comparison permits a downgrade or rejects a newer release")
	}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			directory := t.TempDir()
			executable := filepath.Join(directory, "pluto")
			candidate := filepath.Join(directory, "candidate")
			os.WriteFile(executable, []byte("old"), 0755)
			os.WriteFile(candidate, []byte("new"), 0755)
			starts := 0
			command := func(action string) error {
				if action == "start" {
					starts++
					if fail && starts == 1 {
						return errors.New("failed start")
					}
				}
				return nil
			}
			err := installCandidate(executable, candidate, command, func() bool { return true }, time.Second)
			bytes, _ := os.ReadFile(executable)
			if fail {
				if err == nil || string(bytes) != "old" || starts != 2 {
					t.Fatalf("rollback failed: %v %s %d", err, bytes, starts)
				}
			} else if err != nil || string(bytes) != "new" {
				t.Fatalf("install failed: %v %s", err, bytes)
			}
		})
	}
}

func TestInterruptedUpdateRecoveryRetainsAnInstalledBinary(t *testing.T) {
	for _, stage := range []string{"intent", "backup", "replacement"} {
		t.Run(stage, func(t *testing.T) {
			executable := filepath.Join(t.TempDir(), "pluto")
			if err := os.WriteFile(executable, []byte("old"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(executable+".update-pending", []byte("pluto-replacement-v1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if stage != "intent" {
				if err := os.Link(executable, executable+".previous"); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "replacement" {
				candidate := executable + ".candidate"
				os.WriteFile(candidate, []byte("new"), 0755)
				if err := os.Rename(candidate, executable); err != nil {
					t.Fatal(err)
				}
				if err := recoverInterruptedUpdate(executable, func(string) error { return errors.New("offline systemd") }); err == nil {
					t.Fatal("ignored stop failure")
				}
				if _, err := os.Stat(executable + ".previous"); err != nil {
					t.Fatal("lost rollback after failed stop")
				}
			}
			if _, err := os.Stat(executable); err != nil {
				t.Fatal("installed path missing")
			}
			started := false
			if err := recoverInterruptedUpdate(executable, func(action string) error {
				if action == "start" {
					started = true
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			bytes, _ := os.ReadFile(executable)
			if string(bytes) != "old" || !started {
				t.Fatalf("failed recovery: %s", bytes)
			}
			if _, err := os.Stat(executable + ".update-pending"); !os.IsNotExist(err) {
				t.Fatal("journal not cleared after successful recovery")
			}
		})
	}
}

func TestUnixControlSocketSmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux Unix socket")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "control.sock")
	service, _ := NewService(filepath.Join(dir, "config.json"), dir, "test")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, socket) }()
	defer cancel()
	local := Remote{LocalClient(socket), "http://localhost", ""}
	deadline := time.Now().Add(3 * time.Second)
	var status Status
	for time.Now().Before(deadline) {
		if local.request(ctx, "GET", "/status", nil, -1, nil, &status) == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if status.Version != "test" {
		t.Fatal("socket not available")
	}
	if err := local.json(ctx, "POST", "/control", Control{Action: "interval", IntervalSeconds: 120}, nil); err != nil {
		t.Fatal(err)
	}
	if service.Status().Observation.IntervalSeconds != 120 {
		t.Fatal("control did not update interval")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon failed to shut down")
	}
	info, err := os.Stat(socket)
	if err == nil {
		t.Fatal(fmt.Sprint("socket left behind: ", info))
	}
}
