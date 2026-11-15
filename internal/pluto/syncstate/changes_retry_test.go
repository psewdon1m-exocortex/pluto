package syncstate

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type changesRetryTransport struct {
	base      http.RoundTripper
	fail      error
	remaining int
	bodies    [][]byte
	first     chan struct{}
}

func (t *changesRetryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasSuffix(r.URL.Path, "/changes") {
		return t.base.RoundTrip(r)
	}
	b, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, e
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	t.bodies = append(t.bodies, append([]byte(nil), b...))
	if len(t.bodies) == 1 && t.first != nil {
		close(t.first)
	}
	if t.remaining != 0 {
		t.remaining--
		return nil, t.fail
	}
	return t.base.RoundTrip(r)
}
func changesTimeout() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
}

func TestChangesReadTransientTimeoutPreservesScanAndOriginals(t *testing.T) {
	r, _, w, s, f, _ := actualHTTPFixture(t, 4)
	before, _ := r.Candidate(testContext, "root")
	tr := &changesRetryTransport{base: s.client.Transport, fail: changesTimeout(), remaining: 1}
	s.client.Transport = tr
	report, e := runActualHTTPFixture(t, r, w, s)
	if e != nil || !report.Complete || report.Uploaded != 4 {
		t.Fatalf("transient read aborted same scan: %+v %v", report, e)
	}
	if len(tr.bodies) < 2 || !bytes.Equal(tr.bodies[0], tr.bodies[1]) {
		t.Fatal("read retry changed original binding/cursor")
	}
	after, _ := r.Candidate(testContext, "root")
	if after.Binding != before.Binding || len(f.uploads) != 4 {
		t.Fatal("binding or publication uniqueness changed")
	}
	var scans int
	if e = r.store.db.QueryRow("SELECT count(*) FROM source_scans").Scan(&scans); e != nil || scans != 1 {
		t.Fatal("scan was replaced", scans, e)
	}
	if s.freshAt.IsZero() {
		t.Fatal("complete fresh feed did not restore authority")
	}
}

func TestChangesReadRetriesAreBoundedAndDoNotRetainCachedAuthority(t *testing.T) {
	r, _, _, s, _, _ := actualHTTPFixture(t, 0)
	before, _ := r.Candidate(testContext, "root")
	tr := &changesRetryTransport{base: s.client.Transport, fail: changesTimeout(), remaining: 99}
	s.client.Transport = tr
	started := time.Now()
	if e := s.Refresh(testContext); e == nil {
		t.Fatal("permanent failure accepted")
	}
	if len(tr.bodies) != 3 || time.Since(started) > 6*time.Second || !s.freshAt.IsZero() {
		t.Fatal("retry budget or cached authority", len(tr.bodies), s.freshAt)
	}
	after, _ := r.Candidate(testContext, "root")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed read mutated remote cut")
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, e := s.Authority(ctx); e == nil {
		t.Fatal("failed refresh left usable authority")
	}
}

func TestChangesReadCancellationInterruptsBackoff(t *testing.T) {
	_, _, _, s, _, _ := actualHTTPFixture(t, 0)
	first := make(chan struct{})
	tr := &changesRetryTransport{base: s.client.Transport, fail: changesTimeout(), remaining: 99, first: first}
	s.client.Transport = tr
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- s.Refresh(ctx) }()
	<-first
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked by retry wait")
	}
	if len(tr.bodies) != 1 || !s.freshAt.IsZero() {
		t.Fatal("request after cancellation")
	}
}

func TestChangesReadDoesNotRetryIdentityContractOrCertificateFailures(t *testing.T) {
	for _, cause := range []error{ErrRemoteUnqualified, &tls.CertificateVerificationError{Err: errors.New("untrusted")}, errors.New("invalid contract")} {
		t.Run(cause.Error(), func(t *testing.T) {
			_, _, _, s, _, _ := actualHTTPFixture(t, 0)
			tr := &changesRetryTransport{base: s.client.Transport, fail: cause, remaining: 99}
			s.client.Transport = tr
			if e := s.Refresh(testContext); e == nil || len(tr.bodies) != 1 || !s.freshAt.IsZero() {
				t.Fatal("non-transient error replayed", e, len(tr.bodies))
			}
		})
	}
}
