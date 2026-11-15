package syncstate

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetadataFollowupGroupedAckInterruptedBeforeAllHintsReopensExactOriginals(t *testing.T) {
	var metadataServer *stage3WireFixture
	d, receiver, plan, w := dispatchFixtureWithHandler(t, 16, func(f *dispatchHTTPFixture) http.Handler {
		f.jobProtocol = true
		metadataServer = &stage3WireFixture{t: t, base: f.base, mutations: map[string]map[string]any{}}
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if strings.Contains(request.URL.Path, "/mutations/") {
				metadataServer.ServeHTTP(response, request)
				return
			}
			f.ServeHTTP(response, request)
		})
	})
	r := d.session.r
	metadataServer.session = d.session
	d.session.features = map[string]bool{"namespace-mutations-v1": true}
	d.session.namespace = map[string]any{"codec": "legacy", "policyHash": hashBytes([]byte("group-metadata-policy"))}
	if err := r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	if err := r.sources.StartObserver(testContext, w); err != nil {
		t.Fatal(err)
	}
	if err := r.EnableMetadataFollowups(testContext, w); err != nil {
		t.Fatal(err)
	}
	job, err := plan.asExecutionJob()
	if err != nil {
		t.Fatal(err)
	}
	hintsAttempted := 0
	r.testPoint = func(point string) error {
		if point == "metadata.before_dirty" {
			hintsAttempted++
			if hintsAttempted == 3 {
				return context.Canceled
			}
		}
		return nil
	}
	if err = d.dispatch(testContext, job); err == nil || hintsAttempted != 3 {
		t.Fatal("group interruption not exercised", hintsAttempted, err)
	}
	state, err := r.sources.ObserverStatus(testContext, w)
	if err != nil || state.Pending != 2 {
		t.Fatal("expected partial durable hint set", state, err)
	}
	type identity struct{ intent, receipt string }
	before := map[string]identity{}
	for _, entry := range plan.entries {
		var intent, receipt string
		if err = r.store.db.QueryRow("SELECT intent_fingerprint,receipt_json FROM operations WHERE operation_id=? AND stage='CLIENT_ACKED'", entry.original.OperationID).Scan(&intent, &receipt); err != nil {
			t.Fatal("not all16content ACKs committed", err)
		}
		before[entry.original.OperationID] = identity{intent, receipt}
	}
	directory := filepath.Dir(r.store.filename)
	old := d.session
	old.Close()
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	r2, native := reopenNativeSmallBatch(t, directory)
	w2, err := r2.sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "group-metadata-after-reopen")
	if err != nil {
		t.Fatal(err)
	}
	if err = r2.sources.StartObserver(testContext, w2); err != nil {
		t.Fatal(err)
	}
	if err = r2.EnableMetadataFollowups(testContext, w2); err != nil {
		t.Fatal(err)
	}
	receiver.base.mu.Lock()
	receiver.base.r = r2
	receiver.base.mu.Unlock()
	s2, err := NewIsolatedHTTPSession(testContext, r2, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: old.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(old.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s2.Close)
	s2.SetRecoveryReader(artifactTestReader)
	receiver.session = s2
	metadataServer.session = s2
	if err = s2.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	s2.features = map[string]bool{"namespace-mutations-v1": true}
	s2.namespace = old.namespace
	d2, err := newSmallBatchDispatcher(native, s2, artifactTestReader)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := native.state.read(testContext, plan.id)
	if err != nil {
		t.Fatal(err)
	}
	if err = d2.dispatch(testContext, saved.Plan); err != nil {
		t.Fatal("retained group recovery", err)
	}
	state, err = r2.sources.ObserverStatus(testContext, w2)
	if err != nil || state.Pending != 16 {
		t.Fatal("lost one of16followups after group ACK interruption", state, err)
	}
	if report, err := stage3HTTPScan(t, r2, w2, s2); err != nil || report.Uploaded != 16 {
		t.Fatal("metadata completion for all16entries", report, err)
	}
	var contentCount, metadataCount int
	if err = r2.store.db.QueryRow("SELECT count(*) FROM operations WHERE kind='PUT'").Scan(&contentCount); err != nil {
		t.Fatal(err)
	}
	if err = r2.store.db.QueryRow("SELECT count(*) FROM operations WHERE kind='METADATA_PATCH' AND stage='CLIENT_ACKED'").Scan(&metadataCount); err != nil {
		t.Fatal(err)
	}
	if contentCount != 16 || metadataCount != 16 || s2.Metrics().DataBytes != 0 {
		t.Fatal("group reopen minted content/replayed payload/lost metadata", contentCount, metadataCount, s2.Metrics())
	}
	for id, want := range before {
		var intent, receipt string
		if err = r2.store.db.QueryRow("SELECT intent_fingerprint,receipt_json FROM operations WHERE operation_id=? AND stage='CLIENT_ACKED'", id).Scan(&intent, &receipt); err != nil || intent != want.intent || receipt != want.receipt {
			t.Fatal("historical group original changed", id, err)
		}
	}
	hints, err := r2.sources.DirtyPage(testContext, w2, time.Now().Add(time.Second))
	if err != nil || len(hints) != 16 {
		t.Fatal(hints, err)
	}
	for _, hint := range hints {
		if err = r2.sources.AckDirty(testContext, w2, hint); err != nil {
			t.Fatal(err)
		}
	}
	state, err = r2.sources.ObserverStatus(testContext, w2)
	if err != nil || state.Pending != 0 {
		t.Fatal("completion cannot be observed until hint set drains", state, err)
	}
	if report, err := stage3HTTPScan(t, r2, w2, s2); err != nil || report.Uploaded != 0 {
		t.Fatal("post-group stable NOOP", report, err)
	}
}

func TestMetadataFollowupCommittedAckBoundariesRecoverThroughRealReopen(t *testing.T) {
	for _, boundary := range []string{"metadata.after_content_ack", "metadata.before_dirty", "metadata.after_dirty"} {
		t.Run(boundary, func(t *testing.T) {
			r, w, session, fixture, _ := stage3Wire(t, 1)
			session.features["namespace-mutations-v1"] = true
			if err := r.sources.StartObserver(testContext, w); err != nil {
				t.Fatal(err)
			}
			if err := r.EnableMetadataFollowups(testContext, w); err != nil {
				t.Fatal(err)
			}
			injected := false
			r.testPoint = func(point string) error {
				if point == boundary && !injected {
					injected = true
					return context.Canceled
				}
				return nil
			}
			if _, err := stage3HTTPScan(t, r, w, session); err == nil || !injected {
				t.Fatal("boundary not exercised", injected, err)
			}
			var id, intent, receipt string
			if err := r.store.db.QueryRow("SELECT operation_id,intent_fingerprint,receipt_json FROM operations WHERE kind='PUT' AND stage='CLIENT_ACKED'").Scan(&id, &intent, &receipt); err != nil {
				t.Fatal("content ACK was not durable", err)
			}
			directory := filepath.Dir(r.store.filename)
			if err := r.store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(testContext, directory)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { reopened.Close() })
			sources, err := reopened.EnableSources(testContext, DefaultSourceLimits())
			if err != nil {
				t.Fatal(err)
			}
			artifacts, err := reopened.EnableArtifacts(testContext, DefaultArtifactLimits())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = artifacts.Reconcile(testContext, artifactTestReader); err != nil {
				t.Fatal(err)
			}
			r2, err := reopened.EnableRemoteImport(testContext)
			if err != nil {
				t.Fatal(err)
			}
			w2, err := sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "metadata-reopen-owner")
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
			s2, err := NewIsolatedHTTPSession(testContext, r2, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: session.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(session.binding), DeviceID: session.identity.DeviceID, BackendIdentity: session.identity.BackendIdentity, QualificationReceiptSHA256: session.identity.ContractReceiptSHA256, Token: "fixture-token"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s2.Close)
			fixture.session = s2
			s2.SetRecoveryReader(artifactTestReader)
			if err = s2.InitializeRemote(testContext); err != nil {
				t.Fatal(err)
			}
			s2.features = map[string]bool{"namespace-mutations-v1": true}
			s2.namespace = session.namespace
			if report, err := stage3HTTPScan(t, r2, w2, s2); err != nil || report.Uploaded != 1 {
				t.Fatal("cold-gap metadata recovery", report, err)
			}
			var contents, metadata int
			if err = reopened.db.QueryRow("SELECT count(*) FROM operations WHERE kind='PUT'").Scan(&contents); err != nil {
				t.Fatal(err)
			}
			if err = reopened.db.QueryRow("SELECT count(*) FROM operations WHERE kind='METADATA_PATCH' AND stage='CLIENT_ACKED'").Scan(&metadata); err != nil {
				t.Fatal(err)
			}
			var afterIntent, afterReceipt string
			if err = reopened.db.QueryRow("SELECT intent_fingerprint,receipt_json FROM operations WHERE operation_id=?", id).Scan(&afterIntent, &afterReceipt); err != nil {
				t.Fatal(err)
			}
			if contents != 1 || metadata != 1 || afterIntent != intent || afterReceipt != receipt || s2.Metrics().DataBytes != 0 {
				t.Fatal("reopen changed originals/receipt or replayed payload", contents, metadata)
			}
			for n := 0; n < 2; n++ {
				if report, err := stage3HTTPScan(t, r2, w2, s2); err != nil || report.Uploaded != 0 {
					t.Fatal("post-recovery NOOP", report, err)
				}
			}
		})
	}
}

func TestMetadataFollowupSmallExecutionJobKeepsEveryPublishedEntryPending(t *testing.T) {
	dispatcher, _, plan, _ := dispatchFixtureWithHandler(t, 16, func(f *dispatchHTTPFixture) http.Handler {
		f.jobProtocol = true
		return f
	})
	r := dispatcher.session.r
	w := plan.entries[0].original.Captured.Evidence.Witness
	if err := r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	if err := r.sources.StartObserver(testContext, w); err != nil {
		t.Fatal(err)
	}
	if err := r.EnableMetadataFollowups(testContext, w); err != nil {
		t.Fatal(err)
	}
	job, err := plan.asExecutionJob()
	if err != nil {
		t.Fatal(err)
	}
	if err = dispatcher.dispatch(testContext, job); err != nil {
		t.Fatal(err)
	}
	state, err := r.sources.ObserverStatus(testContext, w)
	if err != nil || state.Pending != 16 {
		t.Fatal("grouped content ACK dropped metadata completion", state, err)
	}
}

func TestMetadataFollowupPreservesNewerHintAndStableNoopOriginals(t *testing.T) {
	r, w, session, _, _ := stage3Wire(t, 1)
	session.features["namespace-mutations-v1"] = true
	if err := r.sources.StartObserver(testContext, w); err != nil {
		t.Fatal(err)
	}
	if err := r.EnableMetadataFollowups(testContext, w); err != nil {
		t.Fatal(err)
	}
	if report, err := stage3HTTPScan(t, r, w, session); err != nil || report.Uploaded != 1 {
		t.Fatal(report, err)
	}
	hints, err := r.sources.DirtyPage(testContext, w, time.Now().Add(time.Second))
	if err != nil || len(hints) != 1 {
		t.Fatal("content completion lost pending source metadata", hints, err)
	}
	old := hints[0]
	if err = r.sources.RecordDirty(testContext, w, []DirtyHint{old}); err != nil {
		t.Fatal(err)
	}
	if err = r.sources.AckDirty(testContext, w, old); err != nil {
		t.Fatal(err)
	}
	state, err := r.sources.ObserverStatus(testContext, w)
	if err != nil || state.Pending != 1 {
		t.Fatal("old cycle ACK consumed newer metadata/source hint", state, err)
	}
	if report, err := stage3HTTPScan(t, r, w, session); err != nil || report.Uploaded != 1 {
		t.Fatal("metadata did not publish independently", report, err)
	}
	var before, patches int
	if err = r.store.db.QueryRow("SELECT count(*) FROM operations").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = r.store.db.QueryRow("SELECT count(*) FROM operations WHERE kind='METADATA_PATCH' AND stage='CLIENT_ACKED'").Scan(&patches); err != nil || patches != 1 {
		t.Fatal("missing exact metadata receipt", patches, err)
	}
	bytes := session.Metrics().DataBytes
	for cycle := 0; cycle < 5; cycle++ {
		if report, err := stage3HTTPScan(t, r, w, session); err != nil || report.Uploaded != 0 {
			t.Fatal("stable no-op", cycle, report, err)
		}
		var after int
		if err = r.store.db.QueryRow("SELECT count(*) FROM operations").Scan(&after); err != nil || after != before || session.Metrics().DataBytes != bytes {
			t.Fatal("no-op created an original or sent payload", cycle, before, after, err)
		}
	}
}
