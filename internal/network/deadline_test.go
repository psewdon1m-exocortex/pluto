package network

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNetworkAcceptanceN01UploadProgressIdleAndCallerCancel(t *testing.T) {
	// The tolerance is fixed before the run: 10ms chunks, 100ms idle,
	// 20 chunks (> the 60ms control equivalent), 3s harness deadline.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		if _, err := io.Copy(h, r.Body); err != nil {
			return
		}
		_, _ = w.Write(h.Sum(nil))
	}))
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	defer client.CloseIdleConnections()
	for _, mode := range []string{"progress", "idle", "cancel", "recovered"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			done := make(chan struct{})
			payload := bytes.Repeat([]byte("original bytes"), 4096)
			go func() {
				defer close(done)
				defer writer.Close()
				for i := 0; i < 20; i++ {
					if _, err := writer.Write(payload); err != nil {
						return
					}
					if i == 0 && mode == "cancel" {
						cancel()
					}
					if i == 0 && (mode == "idle" || mode == "cancel") {
						// A transport cancellation must close the blocked producer.
						_, _ = writer.Write(nil)
						<-ctx.Done()
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()
			request, _ := http.NewRequestWithContext(ctx, "PUT", server.URL, reader)
			response, err := Do(client, request, Deadlines{Idle: 100 * time.Millisecond, Header: 100 * time.Millisecond})
			if mode == "idle" || mode == "cancel" {
				if response != nil {
					response.Body.Close()
					t.Fatal("stalled upload succeeded")
				}
				want := context.DeadlineExceeded
				if mode == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Fatalf("%s: %v", mode, err)
				}
				if mode == "idle" && ctx.Err() != nil {
					t.Fatal("harness expired instead of idle deadline")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				raw, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				want := sha256.Sum256(bytes.Repeat(payload, 20))
				if readErr != nil || !bytes.Equal(raw, want[:]) {
					t.Fatalf("original hash differs: %x %v", raw, readErr)
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("producer did not join")
			}
		})
	}
}

func TestNetworkAcceptanceN01DeadlinesAndPoolReuse(t *testing.T) {
	if GuardedDeadlines(true).Header != TransferIdleTimeout {
		t.Fatal("data header wait must use idle budget")
	}
	if GuardedDeadlines(false).Control != 45*time.Second || GuardedDeadlines(true).Control != 0 || TransferIdleTimeout != 30*time.Second || ConnectTimeout != 10*time.Second || LegacyCopyHeaderTimeout != 2*time.Minute {
		t.Fatal("production defaults changed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/copy" {
			time.Sleep(120 * time.Millisecond)
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		if r.URL.Path == "/hang" {
			<-r.Context().Done()
			return
		}
		for i := 0; i < 10; i++ {
			_, _ = io.WriteString(w, "x")
			w.(http.Flusher).Flush()
			time.Sleep(15 * time.Millisecond)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	defer client.CloseIdleConnections()
	for cycle := 0; cycle < 12; cycle++ {
		request, _ := http.NewRequest("GET", server.URL+"/hang", nil)
		response, err := Do(client, request, Deadlines{Control: 60 * time.Millisecond, Idle: time.Second, Header: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(response.Body)
		response.Body.Close()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("control body: %v", err)
		}
		request, _ = http.NewRequest("GET", server.URL+"/progress", nil)
		response, err = Do(client, request, Deadlines{Idle: 60 * time.Millisecond, Header: 60 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(raw) != strings.Repeat("x", 10) {
			t.Fatalf("progress: %q %v", raw, err)
		}
		request, _ = http.NewRequest("GET", server.URL+"/hang", nil)
		response, err = Do(client, request, Deadlines{Idle: 40 * time.Millisecond, Header: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(response.Body)
		response.Body.Close()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("idle body: %v", err)
		}
	}
	request, _ := http.NewRequest("PUT", server.URL+"/copy", strings.NewReader("copy bytes"))
	response, err := Do(client, request, Deadlines{Idle: 40 * time.Millisecond, Header: 200 * time.Millisecond})
	if err != nil {
		t.Fatal("legacy header wait", err)
	}
	defer response.Body.Close()
	if raw, err := io.ReadAll(response.Body); err != nil || string(raw) != "ok" {
		t.Fatalf("copy: %s %v", raw, err)
	}
}

func TestNetworkAcceptanceN02CallerCancellationDuringBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	response, err := Do(server.Client(), request, GuardedDeadlines(false))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = io.ReadAll(response.Body)
	response.Body.Close()
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
