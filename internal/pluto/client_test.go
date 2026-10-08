package pluto

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteHeaderTimeoutIsReportedWithoutSensitiveURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	}))
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 10 * time.Millisecond}}
	defer client.CloseIdleConnections()
	err := (Remote{client, server.URL, "private-token"}).request(context.Background(), "GET", "/private-path", nil, -1, nil, nil)
	if err == nil || err.Error() != "remote request timed out; copying will retry" {
		t.Fatalf("expected safe timeout status, got %v", err)
	}
}

func TestRemoteCancellationRemainsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (Remote{NewHTTPClient(), "https://example.invalid", "private-token"}).request(ctx, "GET", "/private-path", nil, -1, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
