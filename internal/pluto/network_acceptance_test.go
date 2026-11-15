package pluto

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"pluto/internal/network"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNetworkAcceptanceN10TruncatedResponseRetainsTransportCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"partial":`)
	}))
	defer server.Close()
	var result any
	err := (Remote{HTTP: server.Client(), Origin: server.URL}).request(context.Background(), "GET", "/", nil, -1, nil, &result)
	var networkError *RemoteNetworkError
	if !errors.As(err, &networkError) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost body transport cause: %T %v", err, err)
	}
}

func TestNetworkAcceptanceN11StaleHeartbeatCannotChangeNewBinding(t *testing.T) {
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-release
		w.WriteHeader(401)
	}))
	defer server.Close()
	service := &Service{HTTP: server.Client(), Config: Config{SaturnURL: server.URL, AccessToken: "old-fixture"}, Observation: Observation{NextRunAt: "original-queue"}}
	original := service.Config
	go func() { service.heartbeat(context.Background(), heartbeatUpdate{config: original}); close(done) }()
	<-started
	service.mu.Lock()
	service.Config.AccessToken = "new-fixture"
	service.mu.Unlock()
	close(release)
	<-done
	if service.networkWaiting || service.Observation.NetworkState != "" || service.Config.AccessToken != "new-fixture" || service.Observation.NextRunAt != "original-queue" {
		t.Fatal("stale heartbeat changed binding or schedule")
	}
}

func TestNetworkAcceptanceN10ErrorFormsRetryMetadataAndCancel(t *testing.T) {
	for _, status := range []int{401, 403, 407, 429, 503} {
		for _, body := range []string{"", "<html>login</html>", "truncated"} {
			t.Run(strconv.Itoa(status)+"/"+body, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Retry-After", "2")
					if body == "truncated" {
						w.Header().Set("Content-Length", "100")
					}
					w.WriteHeader(status)
					_, _ = io.WriteString(w, body)
				}))
				defer server.Close()
				err := (Remote{server.Client(), server.URL, "fixture"}).request(context.Background(), "GET", "/", nil, -1, nil, nil)
				var rejected *HTTPError
				if !errors.As(err, &rejected) || rejected.Status != status || rejected.RetryAfter != 2*time.Second {
					t.Fatal("lost error metadata", err)
				}
			})
		}
	}
	if networkWaitState(&HTTPError{Status: 409}) != "" || networkWaitState(&HTTPError{Status: 400}) != "" {
		t.Fatal("protocol rejection entered network loop")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	var result any
	err := (Remote{server.Client(), server.URL, "fixture"}).request(ctx, "GET", "/", nil, -1, nil, &result)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("caller cancellation lost", err)
	}
}

func TestNetworkAcceptanceN12ExplicitProxyReopen(t *testing.T) {
	var hits [2]int
	for i := 0; i < 2; i++ {
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[i]++
			if r.Header.Get("Authorization") != "Bearer fixture-token" || r.URL.Host != "saturn.test" {
				t.Error("origin identity changed")
			}
			_, _ = io.WriteString(w, `{}`)
		}))
		client, err := NewHTTPClientWithProxy(network.ProxyConfig{Mode: "explicit", URL: proxy.URL})
		if err != nil {
			t.Fatal(err)
		}
		var result any
		err = (Remote{client, "http://saturn.test", "fixture-token"}).request(context.Background(), "GET", "/status", nil, -1, nil, &result)
		client.CloseIdleConnections()
		proxy.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits != [2]int{1, 1} {
		t.Fatal("reopen retained old proxy", hits)
	}
}

func TestNetworkAcceptanceN10CompleteProtocolLimits(t *testing.T) {
	for _, size := range []int{65536, 65537} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, `"`+strings.Repeat("a", size-2)+`"`)
			}))
			defer server.Close()
			var result any
			err := (Remote{HTTP: server.Client(), Origin: server.URL}).request(context.Background(), "GET", "/", nil, -1, nil, &result)
			if size == 65536 && err != nil {
				t.Fatal(err)
			}
			if size == 65537 && (err == nil || networkWaitState(err) != "") {
				t.Fatalf("overflow misclassified: %v", err)
			}
		})
	}
}

func TestNetworkAcceptanceN01LegacyHasNoWholeTransferTimer(t *testing.T) {
	client := NewHTTPClient()
	defer client.CloseIdleConnections()
	if client.Timeout != 0 {
		t.Fatalf("whole-transfer timer %v truncates progressing files", client.Timeout)
	}
	if client.Transport.(*http.Transport).ResponseHeaderTimeout != 2*60*1000000000 {
		t.Fatal("legacy copy header budget changed")
	}
}
