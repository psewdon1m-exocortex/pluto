package pluto

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestP02HeartbeatRecoveryKeepsLocalNetworkStateOutOfWire(t *testing.T) {
	var received map[string]json.RawMessage
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Version string                     `json:"version"`
			Status  map[string]json.RawMessage `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		received = request.Status
		// Saturn's deployed strict status schema does not accept local network state.
		if _, exists := received["networkState"]; exists {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	observation := Observation{Enabled: true, IntervalSeconds: 60, NetworkState: "WAIT_CONNECTIVITY", Error: "WAIT_CONNECTIVITY; credentials and queued operations retained"}
	s := &Service{HTTP: server.Client(), Version: "0.1.4", Config: Config{SaturnURL: server.URL, AccessToken: "p02-test-token"}, networkWaiting: true, Observation: observation}
	s.heartbeat(context.Background(), heartbeatUpdate{config: s.Config, observation: observation})
	if s.networkWaiting || s.Observation.NetworkState != "RECOVERING_OPERATIONS" || s.Observation.NextRunAt == "" {
		t.Fatalf("strict server prevented recovery: %+v", s.Observation)
	}
	if observation.NetworkState != "WAIT_CONNECTIVITY" || string(received["error"]) != `"WAIT_CONNECTIVITY; credentials and queued operations retained"` || s.Config.AccessToken != "p02-test-token" {
		t.Fatal("changed local observation, error, or credentials")
	}
}

// Exercise the actual periodic worker and scheduler across an unknown HTTP
// outcome. The second response is compressed like the full Saturn AppModule.
func TestP02HeartbeatPeriodicRecoveryWithoutFileEvent(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pluto/check-in" {
			t.Errorf("unexpected probe: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		io.Copy(io.Discard, r.Body)
		if calls.Add(1) == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		z.Write([]byte(`{"ok":true}`))
		z.Close()
	}))
	defer server.Close()
	state := t.TempDir()
	s := &Service{HTTP: server.Client(), StateDir: state, ConfigPath: filepath.Join(state, "config.json"),
		Config:         Config{SaturnURL: server.URL, AccessToken: "p02-owned-test-token", Enabled: true, IntervalSeconds: 60},
		networkWaiting: true, Observation: Observation{NetworkState: "WAIT_CONNECTIVITY", NextRunAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Loop(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(26 * time.Second)
	for time.Now().Before(deadline) {
		if s.Status().Observation.LastAttemptAt != "" {
			if calls.Load() < 2 || s.Config.AccessToken != "p02-owned-test-token" {
				t.Fatal("recovery bypassed probe or changed credentials")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("periodic recovery did not schedule: probes=%d, status=%+v", calls.Load(), s.Status())
}

type p02ResumeTransport struct {
	started chan struct{}
	finish  chan struct{}
	once    sync.Once
}

func (p *p02ResumeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p.once.Do(func() { close(p.started) })
	<-r.Context().Done()
	<-p.finish
	return nil, r.Context().Err()
}

func TestP02ResumeDoesNotInheritCanceledRunDelay(t *testing.T) {
	for _, phase := range []string{"stopping", "stopped"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "file"), []byte("p02"), 0600); err != nil {
				t.Fatal(err)
			}
			transport := &p02ResumeTransport{started: make(chan struct{}), finish: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			var release sync.Once
			finish := func() { release.Do(func() { close(transport.finish) }) }
			s := &Service{ConfigPath: filepath.Join(dir, "config.json"), StateDir: dir,
				Config: Config{SaturnURL: "https://p02.invalid", AccessToken: "owned-token", Sources: []string{source}, Enabled: true, IntervalSeconds: 600},
				HTTP:   &http.Client{Transport: transport}}
			defer func() { cancel(); finish(); s.jobs.Wait() }()
			s.mu.Lock()
			s.startLocked(ctx)
			s.mu.Unlock()
			select {
			case <-transport.started:
			case <-time.After(5 * time.Second):
				t.Fatal("copy did not enter transport")
			}
			if err := s.Apply(ctx, Control{Action: "enabled", Enabled: false}); err != nil {
				t.Fatal(err)
			}
			if phase == "stopped" {
				finish()
				s.jobs.Wait()
			}
			if err := s.Apply(ctx, Control{Action: "enabled", Enabled: true}); err != nil {
				t.Fatal(err)
			}
			finish()
			s.jobs.Wait()
			status := s.Status()
			if next, err := time.Parse(time.RFC3339Nano, status.Observation.NextRunAt); err == nil && next.After(time.Now()) {
				t.Fatalf("resume waits for canceled run's schedule: %s", status.Observation.NextRunAt)
			}
			if !status.Observation.Enabled || status.Running || !status.Connected {
				t.Fatal(status)
			}
			reopened, err := NewService(s.ConfigPath, dir, "test")
			if err != nil || reopened.Status().Observation.NextRunAt != "" {
				t.Fatal("resumed schedule was not persisted", err)
			}
		})
	}
}
