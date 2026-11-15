package pluto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type tuiSingleByteReader struct{ io.Reader }

func (r tuiSingleByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return r.Reader.Read(p[:1])
}

func TestTUILiveStatusTransientRefreshPreservesSelectionAndRecovers(t *testing.T) {
	for _, fault := range []string{"503", "timeout"} {
		t.Run(fault, func(t *testing.T) {
			var reads, controls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/status" {
					controls.Add(1)
					http.Error(w, "unexpected mutation", 400)
					return
				}
				read := reads.Add(1)
				if read == 3 {
					if fault == "timeout" {
						<-r.Context().Done()
						return
					}
					http.Error(w, "temporarily unavailable", 503)
					return
				}
				json.NewEncoder(w).Encode(Status{Version: "test", Running: read < 4})
			}))
			defer server.Close()
			var output bytes.Buffer
			input := testTUIInput("", &output)
			input.reader = bufio.NewReader(tuiSingleByteReader{strings.NewReader("jq")})
			waits := 0
			input.wait = func(context.Context, time.Duration) (bool, error) { waits++; return waits != 2, nil }
			if err := runTUI(context.Background(), Remote{server.Client(), server.URL, ""}, input, nil, nil); err != nil {
				t.Fatal("transient refresh closed TUI", err)
			}
			text := output.String()
			last := text[strings.LastIndex(text, "\x1b[2J\x1b[H"):]
			if reads.Load() < 4 || controls.Load() != 0 || !strings.Contains(text, "Status unavailable (last known values)") || strings.Contains(last, "Status unavailable") || !strings.Contains(last, "Running: false") || !strings.Contains(last, "> 2 Files and folders") {
				t.Fatalf("refresh recovery/selection failed reads=%d controls=%d output=%q", reads.Load(), controls.Load(), text)
			}
		})
	}
}

func TestTUILiveStatusPollingCancellationCancelsRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reads.Add(1) == 2 {
			cancel()
			<-r.Context().Done()
			return
		}
		json.NewEncoder(w).Encode(Status{Version: "test"})
	}))
	defer server.Close()
	var output bytes.Buffer
	input := testTUIInput("q", &output)
	input.wait = func(context.Context, time.Duration) (bool, error) { return true, nil }
	started := time.Now()
	if err := runTUI(ctx, Remote{server.Client(), server.URL, ""}, input, nil, nil); !errors.Is(err, context.Canceled) || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("polling cancellation did not stop promptly: %v", err)
	}
}

func TestTUILiveStatusRefreshesWhileIdleWithoutControl(t *testing.T) {
	var reads, controls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/status" {
			controls.Add(1)
			http.Error(w, "unexpected mutation", 400)
			return
		}
		read := reads.Add(1)
		json.NewEncoder(w).Encode(Status{Version: "test", Running: read <= 2})
	}))
	defer server.Close()
	var output bytes.Buffer
	input := testTUIInput("q", &output)
	waits := 0
	input.wait = func(context.Context, time.Duration) (bool, error) {
		waits++
		return waits >= 3, nil
	}
	if err := runTUI(context.Background(), Remote{server.Client(), server.URL, ""}, input, nil, nil); err != nil {
		t.Fatal(err)
	}
	if reads.Load() < 3 || !strings.Contains(output.String(), "Running: true") || !strings.Contains(output.String(), "Running: false") || controls.Load() != 0 {
		t.Fatalf("idle status remained stale or mutated daemon: reads=%d controls=%d output=%q", reads.Load(), controls.Load(), output.String())
	}
}

func TestTUILiveStatusIdleCancellationReturns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Status{Version: "test"})
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	input := testTUIInput("q", &output)
	input.wait = func(context.Context, time.Duration) (bool, error) { cancel(); return false, nil }
	if err := runTUI(ctx, Remote{server.Client(), server.URL, ""}, input, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("idle cancellation lost: %v", err)
	}
}
