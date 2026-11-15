//go:build linux

package pluto

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"pluto/internal/network"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal(t *testing.T) {
	f := cNative(t)
	var hits [2]atomic.Int64
	proxy := func(index int) *httptest.Server {
		var handlers sync.WaitGroup
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlers.Add(1)
			defer handlers.Done()
			if r.Method != "CONNECT" || r.Host != f.http.Listener.Addr().String() || r.Header.Get("Authorization") != "" {
				t.Error("proxy origin binding or credentials")
				w.WriteHeader(403)
				return
			}
			upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
			if err != nil {
				w.WriteHeader(502)
				return
			}
			defer upstream.Close()
			client, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer client.Close()
			hits[index].Add(1)
			buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			buffer.Flush()
			done := make(chan struct{})
			go func() { io.Copy(upstream, buffer); upstream.Close(); close(done) }()
			io.Copy(client, upstream)
			client.Close()
			<-done
		}))
		t.Cleanup(func() { server.Close(); handlers.Wait() })
		return server
	}
	first, second := proxy(0), proxy(1)
	f.cfg.Proxy = network.ProxyConfig{Mode: "explicit", URL: first.URL}
	if err := SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(f.source, "pending.md")
	if err := os.WriteFile(source, []byte("sealed before proxy transition"), 0600); err != nil {
		t.Fatal(err)
	}
	f.server.blockComplete = true
	stop := f.start()
	cAwait(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		return f.server.calls["catalog-uploads/complete"] > 0
	})
	f.server.mu.Lock()
	var key string
	for id := range f.server.uploads {
		key = id
	}
	f.server.mu.Unlock()
	if key == "" {
		t.Fatal("no pending original")
	}
	qualifyNetworkDaemonCheckpoint(t, f, func() map[string]any {
		return map[string]any{"firstProxy": first.URL, "secondProxy": second.URL, "firstHits": hits[0].Load(), "secondHits": hits[1].Load()}
	})
	stop(true)
	oldHits := hits[0].Load()
	if oldHits == 0 {
		t.Fatal("P1 bypassed")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	f.cfg.Proxy = network.ProxyConfig{Mode: "explicit", URL: second.URL}
	if err := SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	f.server.mu.Lock()
	f.server.blockComplete = false
	f.server.mu.Unlock()
	stop = f.start()
	defer stop(false)
	cAwait(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		return f.server.uploads[key] != nil && f.server.uploads[key].Result != nil
	})
	if hits[0].Load() != oldHits || hits[1].Load() == 0 {
		t.Fatal("reopen used wrong proxy")
	}
	f.server.mu.Lock()
	if len(f.server.uploads) != 1 || string(f.server.uploads[key].Bytes) != "sealed before proxy transition" {
		t.Error("original replaced or bytes changed")
	}
	f.server.mu.Unlock()
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source restored by sync", err)
	}
	preserveNetworkDaemonOutcome(t, f, func() map[string]any {
		return map[string]any{"firstProxy": first.URL, "secondProxy": second.URL, "oldHits": oldHits, "firstHits": hits[0].Load(), "secondHits": hits[1].Load()}
	})
}

func TestCompletionLegacyQueuedOutageStopsAndResumes(t *testing.T) {
	for _, status := range []int{407, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newPipelineFixture(t)
			_, files := writePipelineFiles(t, []string{"a-healthy", "b-offline", "c-later", "d-later"}, []byte("confirmed bytes"))
			// Workers can dequeue adjacent files before competing for the single
			// transfer slot. Model an outage for every remaining request rather
			// than assuming that one named file wins that scheduling race.
			for _, file := range files[1:] {
				f.fail[RelativePath(file)] = status
			}
			spool := t.TempDir()
			budget := newCopyBudget(1, 1, MaxFileBytes)
			count, err := copyPipeline(context.Background(), f.remote(), []string{files[0], files[0], files[1], files[2], files[3]}, spool, budget)
			var remote *HTTPError
			if count != 1 || !errors.As(err, &remote) || remote.Status != status || networkWaitState(err) == "" {
				t.Fatal(count, err)
			}
			f.mu.Lock()
			if len(f.files) != 1 || string(f.files[RelativePath(files[0])]) != "confirmed bytes" {
				t.Error("success lost or later admission escaped")
			}
			attempts := 0
			for _, file := range files[1:] {
				attempts += f.gets[RelativePath(file)]
				delete(f.fail, RelativePath(file))
			}
			if attempts != 1 {
				t.Errorf("queued request escaped fatal cancellation: %d metadata requests", attempts)
			}
			f.mu.Unlock()
			assertPipelineClean(t, spool, budget)
			count, err = copyPipeline(context.Background(), f.remote(), files, spool, budget)
			if err != nil || count != 3 {
				t.Fatal("resume", count, err)
			}
			f.mu.Lock()
			if len(f.files) != 4 {
				t.Error("queue did not drain")
			}
			f.mu.Unlock()
			assertPipelineClean(t, spool, budget)
		})
	}
}

func TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent(t *testing.T) {
	var offline atomic.Bool
	var lost atomic.Bool
	f := cNativeWithHandler(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if offline.Load() {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					connection.Close()
				}
				return
			}
			if r.URL.Path[len(r.URL.Path)-min(len(r.URL.Path), len("catalog-uploads/complete")):] == "catalog-uploads/complete" && !lost.Swap(true) {
				response := httptest.NewRecorder()
				next.ServeHTTP(response, r)
				if response.Code != 200 {
					t.Error("commit fixture", response.Code)
				}
				offline.Store(true)
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					connection.Close()
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	source := filepath.Join(f.source, "original.md")
	if err := os.WriteFile(source, []byte("route retained bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	stop := f.start()
	cAwait(t, func() bool { return offline.Load() })
	f.server.mu.Lock()
	var id string
	for key, u := range f.server.uploads {
		if u.Result != nil {
			id = key
		}
	}
	f.server.mu.Unlock()
	if id == "" {
		t.Fatal("fault did not follow commit")
	}
	qualifyNetworkDaemonCheckpoint(t, f, func() map[string]any { return map[string]any{"offline": offline.Load(), "lost": lost.Load()} })
	stop(true)
	offline.Store(false)
	stop = f.start()
	defer stop(false)
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
	})
	f.server.mu.Lock()
	if len(f.server.uploads) != 1 || f.server.uploads[id] == nil || f.server.uploads[id].Result == nil {
		t.Error("restart replaced original")
	}
	f.server.mu.Unlock()
	if raw, err := f.command("pause"); err != nil {
		t.Fatal(string(raw), err)
	}
	offline.Store(true)
	time.Sleep(100 * time.Millisecond)
	offline.Store(false)
	if f.status().Observation.Enabled {
		t.Fatal("route restoration enabled paused daemon")
	}
	if data, err := os.ReadFile(source); err != nil || string(data) != "route retained bytes" {
		t.Fatal("source changed", err)
	}
	preserveNetworkDaemonOutcome(t, f, func() map[string]any { return map[string]any{"offline": offline.Load(), "lost": lost.Load()} })
}
