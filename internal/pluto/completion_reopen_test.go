//go:build linux

package pluto

import (
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompletionDaemonReopensSameProcess(t *testing.T) {
	for _, mode := range []string{"pause-resume", "route-recovery"} {
		t.Run(mode, func(t *testing.T) {
			var offline atomic.Bool
			f := cNativeWithHandler(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if offline.Load() {
						http.Error(w, "owned route unavailable", 503)
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			await := func(condition func() bool) {
				t.Helper()
				until := time.Now().Add(100 * time.Second)
				for !condition() {
					if time.Now().After(until) {
						t.Fatalf("same-process recovery watchdog: %+v", f.status())
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			name := filepath.Join(f.source, "example.md")
			if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			stop := f.start()
			defer stop(false)
			await(func() bool {
				s := f.status()
				return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
			})
			if mode == "pause-resume" {
				if raw, err := f.command("pause"); err != nil {
					t.Fatal(string(raw), err)
				}
			} else {
				offline.Store(true)
			}
			await(func() bool { return !f.status().Running })
			// A new file arrives while stopped/offline; restoration supplies no new FS event.
			second := filepath.Join(f.source, "example (2).md")
			if err := os.WriteFile(second, []byte("legitimate numbered name"), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "pause-resume" {
				if raw, err := f.command("resume"); err != nil {
					t.Fatal(string(raw), err)
				}
			} else {
				offline.Store(false)
			}
			await(func() bool {
				s := f.status()
				f.server.mu.Lock()
				defer f.server.mu.Unlock()
				return s.Running && s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing" && len(f.server.uploads) == 2
			})
			stop(false)
			f.server.mu.Lock()
			defer f.server.mu.Unlock()
			for _, upload := range f.server.uploads {
				if upload.Result == nil {
					t.Fatal("unpublished file after recovery")
				}
			}
			entries, err := os.ReadDir(f.source)
			if err != nil || len(entries) != 2 {
				t.Fatal("unexpected local copies", entries, err)
			}
			for p, want := range map[string]string{name: "original", second: "legitimate numbered name"} {
				if raw, err := os.ReadFile(p); err != nil || string(raw) != want {
					t.Fatal("local bytes changed", err)
				}
			}
		})
	}
}
