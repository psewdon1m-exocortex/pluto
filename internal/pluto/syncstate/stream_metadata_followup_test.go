package syncstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func streamMetadataFixture(t *testing.T) (*RemoteImport, SourceWitness, *IsolatedHTTPSession, *stage3WireFixture, string) {
	t.Helper()
	r, w, s, f, directory := stage3Wire(t, 1)
	if err := os.Truncate(filepath.Join(directory, "file-000"), 2*StreamChunkBytes+1); err != nil {
		t.Fatal(err)
	}
	s.features["stream-upload-v1"] = true
	s.features["namespace-mutations-v1"] = true
	if err := r.sources.StartObserver(testContext, w); err != nil {
		t.Fatal(err)
	}
	if err := r.EnableMetadataFollowups(testContext, w); err != nil {
		t.Fatal(err)
	}
	return r, w, s, f, directory
}

func assertStreamMetadataOriginals(t *testing.T, r *RemoteImport, streams, metadata int) {
	t.Helper()
	var bodies, patches int
	if err := r.store.db.QueryRow("SELECT count(*) FROM operations WHERE kind='STREAM_PUT' AND stage='CLIENT_ACKED'").Scan(&bodies); err != nil {
		t.Fatal(err)
	}
	if err := r.store.db.QueryRow("SELECT count(*) FROM operations WHERE kind='METADATA_PATCH' AND stage='CLIENT_ACKED'").Scan(&patches); err != nil {
		t.Fatal(err)
	}
	if bodies != streams || patches != metadata {
		t.Fatal("stream/metadata original count changed", bodies, patches)
	}
}

func TestStreamMetadataFollowupRemainsPendingUntilMtimePublished(t *testing.T) {
	r, w, s, f, directory := streamMetadataFixture(t)
	// This hint belongs to the cycle that publishes the content. Its ACK must
	// not consume the metadata continuation produced during that cycle.
	hint := DirtyHint{SourceID: "source", Destination: "tree/nested/file-000", PhysicalPath: filepath.Join(directory, "file-000")}
	if err := r.sources.RecordDirty(testContext, w, []DirtyHint{hint}); err != nil {
		t.Fatal(err)
	}
	old, err := r.sources.DirtyPage(testContext, w, time.Now().Add(time.Second))
	if err != nil || len(old) != 1 {
		t.Fatal(old, err)
	}
	if report, err := stage3HTTPScan(t, r, w, s); err != nil || report.Uploaded != 1 {
		t.Fatal("stream publication", report, err)
	}
	assertStreamMetadataOriginals(t, r, 1, 0)
	if err = r.sources.AckDirty(testContext, w, old[0]); err != nil {
		t.Fatal(err)
	}
	status, err := r.sources.ObserverStatus(testContext, w)
	if err != nil || status.Pending != 1 {
		t.Fatal("content ACK reported completion before metadata", status, err)
	}
	before := s.Metrics().DataBytes
	if len(f.streams) != 1 || before != 2*StreamChunkBytes+1 {
		t.Fatal("actual stream not exercised", len(f.streams), before)
	}
	if report, err := stage3HTTPScan(t, r, w, s); err != nil || report.Uploaded != 1 {
		t.Fatal("metadata continuation", report, err)
	}
	assertStreamMetadataOriginals(t, r, 1, 1)
	if s.Metrics().DataBytes != before || len(f.streams) != 1 {
		t.Fatal("metadata resent content")
	}
	current, err := r.sources.DirtyPage(testContext, w, time.Now().Add(time.Second))
	if err != nil || len(current) != 1 {
		t.Fatal(current, err)
	}
	if err = r.sources.AckDirty(testContext, w, current[0]); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if report, err := stage3HTTPScan(t, r, w, s); err != nil || report.Uploaded != 0 {
			t.Fatal("stable post-completion no-op", n, report, err)
		}
	}
	assertStreamMetadataOriginals(t, r, 1, 1)
	if status, err = r.sources.ObserverStatus(testContext, w); err != nil || status.Pending != 0 || s.Metrics().DataBytes != before {
		t.Fatal("completed stream left work/replayed payload", status, err)
	}
}

func TestStreamMetadataFollowupCommittedAckBoundariesReopen(t *testing.T) {
	for _, boundary := range []string{"metadata.after_content_ack", "metadata.before_dirty", "metadata.after_dirty"} {
		t.Run(boundary, func(t *testing.T) {
			r, w, s, fixture, _ := streamMetadataFixture(t)
			injected := false
			r.testPoint = func(point string) error {
				if point == boundary && !injected {
					injected = true
					return context.Canceled
				}
				return nil
			}
			if _, err := stage3HTTPScan(t, r, w, s); err == nil || !injected {
				t.Fatal("stream ACK boundary not exercised", injected, err)
			}
			var id, intent, receipt string
			if err := r.store.db.QueryRow("SELECT operation_id,intent_fingerprint,receipt_json FROM operations WHERE kind='STREAM_PUT' AND stage='CLIENT_ACKED'").Scan(&id, &intent, &receipt); err != nil {
				t.Fatal("stream receipt was not durable", err)
			}
			directory := filepath.Dir(r.store.filename)
			s.Close()
			if err := r.store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := Open(testContext, directory)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
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
			r2, err := store.EnableRemoteImport(testContext)
			if err != nil {
				t.Fatal(err)
			}
			w2, err := sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "stream-metadata-reopen")
			if err != nil {
				t.Fatal(err)
			}
			if err = sources.StartObserver(testContext, w2); err != nil {
				t.Fatal(err)
			}
			if err = r2.EnableMetadataFollowups(testContext, w2); err != nil {
				t.Fatal(err)
			}
			fixture.base.mu.Lock()
			fixture.base.r = r2
			fixture.base.mu.Unlock()
			s2, err := NewIsolatedHTTPSession(testContext, r2, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: s.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(s.binding), DeviceID: s.identity.DeviceID, BackendIdentity: s.identity.BackendIdentity, QualificationReceiptSHA256: s.identity.ContractReceiptSHA256, Token: "fixture-token"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s2.Close)
			fixture.session = s2
			s2.SetRecoveryReader(artifactTestReader)
			if err = s2.InitializeRemote(testContext); err != nil {
				t.Fatal(err)
			}
			s2.features = s.features
			s2.namespace = s.namespace
			if report, err := stage3HTTPScan(t, r2, w2, s2); err != nil || report.Uploaded != 1 {
				t.Fatal("reopened metadata completion", report, err)
			}
			assertStreamMetadataOriginals(t, r2, 1, 1)
			var afterIntent, afterReceipt string
			if err = store.db.QueryRow("SELECT intent_fingerprint,receipt_json FROM operations WHERE operation_id=?", id).Scan(&afterIntent, &afterReceipt); err != nil || afterIntent != intent || afterReceipt != receipt || s2.Metrics().DataBytes != 0 || len(fixture.streams) != 1 {
				t.Fatal("reopen replaced stream original/receipt or resent content", err)
			}
			for n := 0; n < 2; n++ {
				if report, err := stage3HTTPScan(t, r2, w2, s2); err != nil || report.Uploaded != 0 {
					t.Fatal("post-recovery no-op", report, err)
				}
			}
		})
	}
}

func TestStreamMetadataFollowupOldReceiptRetainsNewerSourceHint(t *testing.T) {
	r, w, s, _, directory := streamMetadataFixture(t)
	if report, err := stage3HTTPScan(t, r, w, s); err != nil || report.Uploaded != 1 {
		t.Fatal(report, err)
	}
	var id string
	if err := r.store.db.QueryRow("SELECT operation_id FROM operations WHERE kind='STREAM_PUT'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, "file-000")
	f, err := os.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteAt([]byte("newer source bytes"), 0)
	closeErr := f.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	scanSource(t, r.sources, w, "newer-stream-metadata-source", nil)
	if err = r.sources.RecordDirty(testContext, w, []DirtyHint{{SourceID: "source", Destination: "tree/nested/file-000", PhysicalPath: name}}); err != nil {
		t.Fatal(err)
	}
	before, err := r.sources.DirtyPage(testContext, w, time.Now().Add(time.Second))
	if err != nil || len(before) != 1 {
		t.Fatal(before, err)
	}
	if err = r.afterContentAck(testContext, id); err != nil {
		t.Fatal(err)
	}
	after, err := r.sources.DirtyPage(testContext, w, time.Now().Add(time.Second))
	if err != nil || len(after) != 1 || after[0] != before[0] {
		t.Fatal("old stream ACK modified a newer source hint", before, after, err)
	}
}
