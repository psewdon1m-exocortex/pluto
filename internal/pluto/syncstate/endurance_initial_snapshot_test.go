package syncstate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEnduranceInitialExpiredSnapshotRecovery(t *testing.T) {
	for _, route := range []string{"snapshots/start", "snapshots/ready"} {
		t.Run(route, func(t *testing.T) {
			for _, kind := range []string{"expired", "lost-response", "unauthorized", "malformed", "repeated-expiry"} {
				t.Run(kind, func(t *testing.T) {
					r, _, _, old, f, _ := actualHTTPFixtureInitialization(t, 1, false)
					original, err := r.pendingHTTPSnapshot(old.binding)
					if err != nil {
						t.Fatal(err)
					}
					var requests atomic.Int64
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						if strings.HasSuffix(req.URL.Path, "/"+route) {
							requestCount := requests.Add(1)
							if requestCount == 1 || kind == "repeated-expiry" {
								if kind == "lost-response" {
									f.lose(w)
									return
								}
								w.Header().Set("Content-Type", "application/json")
								status := 410
								if kind == "unauthorized" {
									status = 401
								}
								w.WriteHeader(status)
								if kind == "malformed" {
									w.Write([]byte(`{"code":"cursor_expired","extra":true}`))
								} else {
									w.Write([]byte(`{"code":"cursor_expired"}`))
								}
								return
							}
						}
						f.ServeHTTP(w, req)
					}))
					defer server.Close()
					s := rebootstrapSession(t, r, old, server.URL, nil)
					before := retainedRecoveryDigest(t, r)
					err = s.InitializeRemote(testContext)
					next, readErr := r.pendingHTTPSnapshot(s.binding)
					requestCount := requests.Load()
					if readErr != nil {
						t.Fatal(readErr)
					}
					if kind == "expired" {
						if err != nil || next == original || requestCount != 2 {
							t.Fatalf("recovery: %v requests=%d same=%v", err, requestCount, next == original)
						}
					} else if kind == "repeated-expiry" {
						if !errors.Is(err, ErrHTTPRebootstrapLimit) || requestCount != 2 {
							t.Fatalf("unbounded expiry: %v requests=%d", err, requestCount)
						}
					} else {
						if err == nil || next != original || requestCount != 1 {
							t.Fatalf("unqualified rotation: %v requests=%d", err, requestCount)
						}
					}
					if before != retainedRecoveryDigest(t, r) {
						t.Fatal("snapshot recovery changed original intents/baselines/artifacts")
					}
					archives, _ := filepath.Glob(filepath.Join(filepath.Dir(r.store.filename), "http-snapshot-*.expired-*"))
					want := 0
					if kind == "expired" || kind == "repeated-expiry" {
						want = 1
					}
					if len(archives) != want {
						t.Fatal("original read UUID evidence missing", len(archives), want)
					}
				})
			}
		})
	}
}
