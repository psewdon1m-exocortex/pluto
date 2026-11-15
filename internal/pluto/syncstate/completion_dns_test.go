package syncstate

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"pluto/internal/network"
	"strconv"
	"testing"
)

func TestCompletionPendingOriginalSurvivesApprovedDNSRotation(t *testing.T) {
	r, _, w, initial, f, source := actualHTTPFixture(t, 1)
	initial.Close()
	server := httptest.NewUnstartedServer(f)
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	origin, _ := url.Parse("http://completion-dns.invalid:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	cfg := IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: origin.String(), AllowedAddresses: []string{"127.0.0.1", "127.0.0.2"}, Binding: bindingHTTP(f.binding), DeviceID: initial.identity.DeviceID, BackendIdentity: initial.identity.BackendIdentity, QualificationReceiptSHA256: initial.identity.ContractReceiptSHA256, Token: "fixture-token"}
	makeSession := func(importer *RemoteImport, ip string, dials *int) *IsolatedHTTPSession {
		s, e := NewIsolatedHTTPSession(testContext, importer, "root", cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(s.Close)
		dialer := &net.Dialer{}
		dial, e := guardedDial(origin, map[string]bool{"127.0.0.1": true, "127.0.0.2": true}, false, network.ProxyConfig{Mode: "direct"}, func(context.Context, string) ([]net.IPAddr, error) { return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil }, func(ctx context.Context, n, a string) (net.Conn, error) {
			*dials++
			return dialer.DialContext(ctx, n, a)
		})
		if e != nil {
			t.Fatal(e)
		}
		s.client.Transport.(*http.Transport).DialContext = dial
		s.SetRecoveryReader(artifactTestReader)
		return s
	}
	firstDials := 0
	s := makeSession(r, "127.0.0.1", &firstDials)
	if err = s.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	f.lostComplete = true
	first, err := runActualHTTPFixture(t, r, w, s)
	if err == nil || first.Failed != 1 {
		t.Fatal(first, err)
	}
	pending, err := r.store.PendingPage(testContext, "root", "", 10)
	if err != nil || len(pending) != 1 {
		t.Fatal(pending, err)
	}
	original := pending[0]
	s.Close()
	directory := filepath.Dir(r.store.filename)
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(source, "file-000")); err != nil {
		t.Fatal(err)
	}
	store, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sources, err := store.EnableSources(testContext, DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = artifacts.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	r, err = store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	w, err = sources.BeginSourceOwner(testContext, "set", 1, "dns-reopen")
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.r = r
	f.mu.Unlock()
	forbiddenDials := 0
	bad := makeSession(r, "127.0.0.3", &forbiddenDials)
	if err = bad.InitializeRemote(testContext); !errors.Is(err, ErrRemoteUnqualified) || forbiddenDials != 0 {
		t.Fatal("unapproved address used", forbiddenDials, err)
	}
	bad.Close()
	secondDials := 0
	next := makeSession(r, "127.0.0.2", &secondDials)
	if err = next.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	recovered, err := runActualHTTPFixture(t, r, w, next)
	if err != nil || recovered.Recovered != 1 {
		t.Fatal(recovered, err)
	}
	ack, err := store.Operation(testContext, original.OperationID)
	if err != nil || ack.Stage != "CLIENT_ACKED" || ack.IntentFingerprint != original.IntentFingerprint || string(mustJSON(ack.Intent)) != string(mustJSON(original.Intent)) {
		t.Fatal("original replaced", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.uploads) != 1 || firstDials == 0 || secondDials == 0 {
		t.Fatal("duplicate effect or missing route", len(f.uploads), firstDials, secondDials)
	}
	if _, err = os.Stat(filepath.Join(source, "file-000")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source recreated", err)
	}
}
