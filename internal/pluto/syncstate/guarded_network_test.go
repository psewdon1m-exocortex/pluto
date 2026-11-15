package syncstate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"pluto/internal/network"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardedDNSFallbackOnlyDialsAllowedCandidates(t *testing.T) {
	origin, _ := url.Parse("https://saturn.test")
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.9")}, {IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	var attempted []string
	dial := func(ctx context.Context, protocol, address string) (net.Conn, error) {
		attempted = append(attempted, address)
		if address == "[::1]:443" {
			return nil, errors.New("first allowed address unavailable")
		}
		left, right := net.Pipe()
		right.Close()
		return left, nil
	}
	connect, err := guardedDial(origin, map[string]bool{"::1": true, "127.0.0.1": true}, true, network.ProxyConfig{Mode: "direct"}, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := connect(context.Background(), "tcp", "saturn.test:443")
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if len(attempted) != 2 || attempted[0] != "[::1]:443" || attempted[1] != "127.0.0.1:443" {
		t.Fatalf("unexpected candidates: %v", attempted)
	}
}

func TestGuardedProxyConnectPinsAddressAndPreservesOriginTLS(t *testing.T) {
	var originCalls atomic.Int32
	originServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "Bearer origin-token" {
			t.Error("credential boundary violated")
		}
		w.Write([]byte("ok"))
	}))
	defer originServer.Close()
	target, _ := url.Parse(originServer.URL)
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		if r.Method != "CONNECT" || r.Host != target.Host || r.Header.Get("Proxy-Authorization") != "Basic cHJveHk6c2VjcmV0" || r.Header.Get("Authorization") != "" {
			t.Errorf("invalid CONNECT method/target/credential scope: %s %s", r.Method, r.Host)
			w.WriteHeader(400)
			return
		}
		upstream, err := net.DialTimeout("tcp", target.Host, time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		downstream, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		downstream.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { defer downstream.Close(); defer upstream.Close(); io.Copy(upstream, downstream) }()
		io.Copy(downstream, upstream)
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	proxyURL.User = url.UserPassword("proxy", "secret")
	origin, _ := url.Parse("https://example.com:" + target.Port())
	connect, err := guardedDial(origin, map[string]bool{"127.0.0.1": true}, true,
		network.ProxyConfig{Mode: "explicit", URL: proxyURL.String()},
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		(&net.Dialer{}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(originServer.Certificate())
	transport := &http.Transport{DialContext: connect, TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	request, _ := http.NewRequest("GET", origin.String(), nil)
	request.Header.Set("Authorization", "Bearer origin-token")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if originCalls.Load() != 1 || connects.Load() != 1 {
		t.Fatal("request did not traverse the proxy")
	}
	// The same path must reject an untrusted origin certificate.
	untrusted := &http.Transport{DialContext: connect}
	defer untrusted.CloseIdleConnections()
	_, err = (&http.Client{Transport: untrusted, Timeout: 2 * time.Second}).Get(origin.String())
	if err == nil {
		t.Fatal("TLS trust was bypassed")
	}
}

func TestGuardedProxy407NeverFallsBackToDirect(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) }))
	defer proxy.Close()
	origin, _ := url.Parse("https://saturn.test")
	var calls atomic.Int32
	connect, err := guardedDial(origin, nil, true, network.ProxyConfig{Mode: "explicit", URL: proxy.URL},
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}}, nil
		},
		func(ctx context.Context, protocol, address string) (net.Conn, error) {
			calls.Add(1)
			return (&net.Dialer{}).DialContext(ctx, protocol, address)
		})
	if err != nil {
		t.Fatal(err)
	}
	_, err = connect(context.Background(), "tcp", "saturn.test:443")
	var denied *network.ProxyError
	if !errors.As(err, &denied) || denied.Status != 407 || calls.Load() != 1 {
		t.Fatalf("bad proxy classification or fallback: %v, calls=%d", err, calls.Load())
	}
}

func TestIsolatedTransportRejectsProxyAndWrongHost(t *testing.T) {
	origin, _ := url.Parse("http://isolated.test")
	if _, err := guardedDial(origin, nil, false, network.ProxyConfig{Mode: "environment"}, nil, nil); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal(err)
	}
	dial, err := guardedDial(origin, nil, false, network.ProxyConfig{Mode: "direct"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dial(context.Background(), "tcp", "other.test:80"); !errors.Is(err, ErrRemoteUnqualified) {
		t.Fatal(err)
	}
}
