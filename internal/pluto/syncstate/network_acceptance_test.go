package syncstate

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"pluto/internal/network"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkAcceptanceN13FourConnectionsCancelFifthAndRecoverTwelveTimes(t *testing.T) {
	var calls, active, maximum atomic.Int32
	started := make(chan struct{}, 4)
	finished := make(chan struct{}, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		calls.Add(1)
		n := active.Add(1)
		defer func() { active.Add(-1); finished <- struct{}{} }()
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).MaxConnsPerHost = 4
	defer client.CloseIdleConnections()
	request := func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
		response, err := network.Do(client, req, network.GuardedDeadlines(false))
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, err = io.ReadAll(response.Body)
		return err
	}
	for cycle := 0; cycle < 12; cycle++ {
		ctx, cancel := context.WithCancel(context.Background())
		results := make(chan error, 4)
		for i := 0; i < 4; i++ {
			go func() { results <- request(ctx) }()
		}
		for i := 0; i < 4; i++ {
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				cancel()
				t.Fatal("connections not admitted")
			}
		}
		fifth, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := request(fifth)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			cancel()
			t.Fatal("waiting request did not cancel", err)
		}
		if calls.Load() != int32((cycle+1)*4) {
			cancel()
			t.Fatal("fifth request escaped admission")
		}
		cancel()
		for i := 0; i < 4; i++ {
			if err := <-results; !errors.Is(err, context.Canceled) {
				t.Fatal("caller cancellation changed", err)
			}
		}
		// Client cancellation closes sockets before the peer goroutines are
		// necessarily scheduled to observe EOF. Join that fixture generation
		// before counting concurrency in the next fault/recovery cycle.
		for i := 0; i < 4; i++ {
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("server generation did not drain")
			}
		}
		if active.Load() != 0 {
			t.Fatal("cycle retained active handlers")
		}
	}
	client.CloseIdleConnections()
	until := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 || maximum.Load() > 4 {
		t.Fatalf("active=%d max=%d", active.Load(), maximum.Load())
	}
}

func TestNetworkAcceptanceN06ErrorHeadersSurviveTruncatedBody(t *testing.T) {
	for _, status := range []int{401, 403, 407, 429, 503} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("status%d/batch%v", status, batch), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", "100")
					w.Header().Set("Retry-After", "2")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, "<html>")
				}))
				defer server.Close()
				s := &IsolatedHTTPSession{origin: server.URL, client: server.Client()}
				var err error
				if batch {
					_, err = s.smallBatchRequest(context.Background(), "status", "application/json", nil, 0, 16384)
				} else {
					_, err = s.request(context.Background(), "POST", "status", "application/json", nil, 0)
				}
				if HTTPStatus(err) != status || HTTPRetryAfter(err) != 2*time.Second {
					t.Fatalf("lost headers: status=%d retry=%v error=%v", HTTPStatus(err), HTTPRetryAfter(err), err)
				}
				if s.denied.Load() {
					t.Fatal("intermediary revoked binding")
				}
			})
		}
	}
}

func TestNetworkAcceptanceN08TLSProxyChild(t *testing.T) {
	if endpoint := os.Getenv("NETWORK_TLS_PROXY"); endpoint != "" {
		proxy, _ := url.Parse(endpoint)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		connection, err := dialTunnel(ctx, "tcp", "127.0.0.1:443", proxy, (&net.Dialer{}).DialContext)
		if connection != nil {
			connection.Close()
		}
		if os.Getenv("NETWORK_TLS_TRUSTED") == "1" && err != nil {
			t.Fatal("trusted HTTPS proxy failed", err)
		}
		if os.Getenv("NETWORK_TLS_TRUSTED") != "1" && err == nil {
			t.Fatal("untrusted HTTPS proxy accepted")
		}
		return
	}
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "127.0.0.1:443" || r.Header.Get("Authorization") != "" {
			t.Error("CONNECT identity boundary")
		}
		w.WriteHeader(200)
	}))
	defer proxy.Close()
	directory := t.TempDir()
	certificate := filepath.Join(directory, "proxy.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, trusted := range []bool{true, false} {
		command := exec.Command(os.Args[0], "-test.run=^TestNetworkAcceptanceN08TLSProxyChild$")
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "SSL_CERT_") && !strings.HasPrefix(value, "NETWORK_TLS_") {
				command.Env = append(command.Env, value)
			}
		}
		command.Env = append(command.Env, "NETWORK_TLS_PROXY="+proxy.URL, "SSL_CERT_DIR="+directory)
		if trusted {
			command.Env = append(command.Env, "NETWORK_TLS_TRUSTED=1", "SSL_CERT_FILE="+certificate)
		} else {
			command.Env = append(command.Env, "SSL_CERT_FILE="+filepath.Join(directory, "missing"), "SSL_CERT_DIR="+filepath.Join(directory, "missing-dir"))
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("TLS proxy child: %v %s", err, output)
		}
	}
}

func TestNetworkAcceptanceN08ConnectBoundsAndForbiddenDNS(t *testing.T) {
	origin, _ := url.Parse("https://saturn.test")
	called := false
	connector, err := guardedDial(origin, map[string]bool{"127.0.0.1": true}, true, network.ProxyConfig{Mode: "direct"}, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}, func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("must not dial")
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connector(context.Background(), "tcp", "saturn.test:443"); !errors.Is(err, ErrRemoteUnqualified) || called {
		t.Fatal("forbidden address dialed")
	}
	for _, wire := range []string{"HTTP/1.1 200 OK\r\nX-Long: " + strings.Repeat("x", 33000) + "\r\n\r\n", "HTTP/1.1 200", ""} {
		t.Run(fmt.Sprint(len(wire)), func(t *testing.T) {
			proxy, _ := url.Parse("http://proxy.test")
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan struct{})
			dial := func(context.Context, string, string) (net.Conn, error) {
				left, right := net.Pipe()
				go func() {
					defer close(done)
					defer right.Close()
					buffer := make([]byte, 4096)
					_, _ = right.Read(buffer)
					if wire != "" {
						_, _ = io.WriteString(right, wire)
					}
					<-ctx.Done()
				}()
				return left, nil
			}
			conn, err := dialTunnel(ctx, "tcp", "127.0.0.1:443", proxy, dial)
			if conn != nil {
				conn.Close()
				t.Fatal("invalid CONNECT accepted")
			}
			if err == nil {
				t.Fatal("missing CONNECT error")
			}
			cancel()
			<-done
		})
	}
}

func TestNetworkAcceptanceN01ProgressingChunkAndBatchOutliveControlDeadline(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				if batch {
					w.WriteHeader(http.StatusAccepted)
				}
				_, _ = io.WriteString(w, `{"ok":"`)
				w.(http.Flusher).Flush()
				for i := 0; i < 8; i++ {
					time.Sleep(20 * time.Millisecond)
					_, _ = io.WriteString(w, "x")
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, `"}`)
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 40 * time.Millisecond
			s := &IsolatedHTTPSession{origin: server.URL, client: client}
			var raw []byte
			var err error
			if batch {
				raw, err = s.smallBatchRequest(context.Background(), "data", "application/octet-stream", http.NoBody, 0, 16384)
			} else {
				raw, err = s.request(context.Background(), "PATCH", "stream-uploads/chunk", HTTPFrameType, []byte{0, 0, 0, 0}, 0)
			}
			if err != nil || string(raw) != `{"ok":"xxxxxxxx"}` {
				t.Fatalf("progressing transfer interrupted: %s %v", raw, err)
			}
		})
	}
}
