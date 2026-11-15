package pluto

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeartbeatWorkerBoundsConcurrencyAndCoalescesStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 2)
	var active, maximum atomic.Int32
	worker := newHeartbeatWorker(ctx, 80*time.Millisecond, func(ctx context.Context, update heartbeatUpdate) {
		n := active.Add(1)
		if n > maximum.Load() {
			maximum.Store(n)
		}
		defer active.Add(-1)
		started <- update.config.ConnectionName
		<-ctx.Done()
	})
	worker.offer(heartbeatUpdate{config: Config{ConnectionName: "first"}})
	<-started
	for i := 0; i < 100; i++ {
		worker.offer(heartbeatUpdate{config: Config{ConnectionName: "obsolete"}})
	}
	worker.offer(heartbeatUpdate{config: Config{ConnectionName: "latest"}})
	select {
	case value := <-started:
		if value != "latest" {
			t.Fatal(value)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not release worker")
	}
	cancel()
	select {
	case <-worker.done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain worker")
	}
	if maximum.Load() != 1 {
		t.Fatal("concurrent heartbeat")
	}
}

func TestHeartbeatAccessFailuresRetainCredentialsAndQueuedState(t *testing.T) {
	for _, status := range []int{401, 403, 407} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte("intermediary login"))
			}))
			defer server.Close()
			s := &Service{HTTP: server.Client(), Config: Config{SaturnURL: server.URL, AccessToken: "original-token", Enabled: true}, Observation: Observation{NextRunAt: "retained"}}
			s.heartbeat(context.Background(), heartbeatUpdate{config: s.Config})
			if s.Config.AccessToken != "original-token" || !s.Config.Enabled || s.Observation.NextRunAt != "retained" || !s.networkWaiting {
				t.Fatalf("lost binding/queue: %+v", s.Status())
			}
			expected := "SERVER_AUTH_REQUIRED"
			if status == 407 {
				expected = "PROXY_AUTH_REQUIRED"
			}
			if s.Observation.NetworkState != expected {
				t.Fatal(s.Observation.NetworkState)
			}
		})
	}
}

func TestHeartbeatStallDoesNotBlockControlLoop(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Service{HTTP: server.Client(), Config: Config{SaturnURL: server.URL, AccessToken: "original-token", IntervalSeconds: 60}, StateDir: t.TempDir()}
	done := make(chan struct{})
	go func() { s.Loop(ctx); close(done) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat not started")
	}
	// A due run with no sources completes locally. It must start on the next
	// scheduler tick while the first heartbeat still waits for its response.
	s.mu.Lock()
	s.Config.Enabled = true
	s.mu.Unlock()
	deadline := time.Now().Add(2500 * time.Millisecond)
	for s.Status().Observation.LastAttemptAt == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Status().Observation.LastAttemptAt == "" {
		t.Fatal("heartbeat blocked scheduler")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Loop failed to cancel/drain heartbeat")
	}
}
