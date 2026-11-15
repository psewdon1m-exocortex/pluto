package syncstate

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"pluto/internal/network"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompletionGzipTrailerAndCancelledCommitDrainEachRequestPath(t *testing.T) {
	for _, path := range []string{"snapshots/start", "catalog-uploads/prepare", "catalog-uploads/append", "catalog-uploads/complete", "mutations/batch", "stream-uploads/chunk", "small-batches/data"} {
		t.Run(path, func(t *testing.T) {
			var packed bytes.Buffer
			z := gzip.NewWriter(&packed)
			z.Write([]byte(`{"accepted":true}`))
			z.Close()
			payload := packed.Bytes()
			var fail atomic.Bool
			fail.Store(true)
			var commits atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				commits.Add(1)
				if fail.Load() {
					w.Write(payload[:len(payload)-4])
				} else {
					w.Write(payload)
				}
			}))
			defer server.Close()
			s := &IsolatedHTTPSession{origin: server.URL, client: server.Client(), features: map[string]bool{"metadata-gzip-v1": true}}
			for cycle := 0; cycle < 12; cycle++ {
				fail.Store(true)
				_, err := s.request(context.Background(), "POST", path, "application/json", []byte(`{}`), 2)
				if state, ok := RetryClass(err); !ok || state != "WAIT_CONNECTIVITY" {
					t.Fatal("trailer cause lost", state, err)
				}
				fail.Store(false)
				raw, err := s.request(context.Background(), "POST", path, "application/json", []byte(`{}`), 2)
				if err != nil || string(raw) != `{"accepted":true}` {
					t.Fatal("pool did not recover", err)
				}
			}
			if commits.Load() != 24 {
				t.Fatal("generic mutation replay", commits.Load())
			}
		})
	}
	t.Run("cancel-after-commit", func(t *testing.T) {
		committed := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(committed)
			<-r.Context().Done()
		}))
		defer server.Close()
		s := &IsolatedHTTPSession{origin: server.URL, client: server.Client()}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := s.request(ctx, "POST", "catalog-uploads/complete", "application/json", []byte(`{}`), 2)
			done <- err
		}()
		<-committed
		cancel()
		err := <-done
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if state, ok := RetryClass(err); ok || state != "" {
			t.Fatal("user cancellation retried", state)
		}
	})
}

func TestCompletionManySlowDNSCandidatesShareOneConnectBudget(t *testing.T) {
	origin, _ := url.Parse("https://saturn.test")
	allowed := map[string]bool{}
	candidates := []net.IPAddr{}
	for n := 1; n <= 16; n++ {
		ip := net.IPv4(127, 0, 0, byte(n))
		allowed[ip.String()] = true
		candidates = append(candidates, net.IPAddr{IP: ip})
	}
	attempts := 0
	connect, err := guardedDial(origin, allowed, true, network.ProxyConfig{Mode: "direct"}, func(context.Context, string) ([]net.IPAddr, error) { return candidates, nil }, func(ctx context.Context, _, _ string) (net.Conn, error) {
		attempts++
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = connect(context.Background(), "tcp", "saturn.test:443")
	if err == nil || time.Since(started) > 11*time.Second || attempts < 2 || attempts > 16 {
		t.Fatal("multiplied connection budget", attempts, time.Since(started), err)
	}
}

func TestCompletionOriginCertificateIsNotBypassed(t *testing.T) {
	originServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted origin reached application") }))
	defer originServer.Close()
	origin, _ := url.Parse(originServer.URL)
	dialer := &net.Dialer{}
	dial, err := guardedDial(origin, map[string]bool{"127.0.0.1": true}, true, network.ProxyConfig{Mode: "direct"}, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	_, err = client.Get(origin.String())
	var certificate *tls.CertificateVerificationError
	if !errors.As(err, &certificate) {
		t.Fatal("origin certificate verification missing", err)
	}
}

func TestCompletionTwelveOriginalRecoveryCycles(t *testing.T) {
	for cycle := 0; cycle < 12; cycle++ {
		t.Run(time.Duration(cycle).String(), func(t *testing.T) {
			t.Run("catalog", TestGuardedHTTPLostPublicationAndAppendRecoverOriginalIdentity)
			t.Run("restart", TestHTTPBindingLostPreparePersistenceAndCompleteRestart)
			t.Run("folder", TestHTTPFolderLostAckOriginalAndConflictHistory)
			t.Run("mixed-batch", TestCompletionMixedSixOriginalsAfterLostResponse)
		})
	}
}
