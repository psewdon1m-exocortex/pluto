package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEnduranceExpiredPartialImportRestartsWithoutChangingOriginals(t *testing.T) {
	r, _, w, s, g, _ := rebootstrapFixture(t, 1)
	g.f.lostPrepare = true
	if report, err := runActualHTTPFixture(t, r, w, s); err == nil || report.Failed != 1 {
		t.Fatal(report, err)
	}
	digest := retainedRecoveryDigest(t, r)
	c, err := r.Candidate(testContext, "root")
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.beginHTTPRebootstrap(testContext, c, s.httpFailure(410, "changes", "application/json", []byte(`{"code":"cursor_expired"}`)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.startRebootstrapSnapshot(testContext, c, *c.HTTPRebootstrap)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a lease expiring while disconnected after a bounded page import.
	// These are invisible staged cache rows, not active R or publication originals.
	err = r.sources.change(testContext, MaxSourcePageBytes, func(tx *sql.Tx) error {
		p.ExpiresMS = time.Now().Add(-time.Minute).UnixMilli()
		if e := savePreparation(testContext, tx, p); e != nil {
			return e
		}
		for i := 0; i < 501; i++ {
			if e := saveRemoteCandidateEntry(testContext, tx, RemoteEntry{RootID: "root", Generation: p.Generation, NodeID: remoteVersion(10000 + i)}); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	next := rebootstrapSession(t, r, s, s.origin, nil)
	if err = next.InitializeRemote(testContext); err != nil {
		t.Fatal("expired partial read must recover", err)
	}
	if digest != retainedRecoveryDigest(t, r) {
		t.Fatal("read retirement changed originals/B/artifacts/debt")
	}
	after, err := r.Candidate(testContext, "root")
	if err != nil || !after.Valid || after.HTTPRebootstrap != nil || after.SnapshotID == p.Snapshot.SnapshotID {
		t.Fatal(after, err)
	}
	var count int
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM remote_entries WHERE root_id='root' AND generation=?", after.Generation).Scan(&count); err != nil || count != len(g.f.nodes) {
		t.Fatal("staged cache leaked", count, err)
	}
	if report, err := runActualHTTPFixture(t, r, w, next); err != nil || report.Recovered != 1 {
		t.Fatal(report, err)
	}
}

func expiredImportFixture(t *testing.T) (*RemoteImport, *IsolatedHTTPSession, RemoteCandidate, SnapshotPreparation, string) {
	t.Helper()
	r, _, w, s, g, _ := rebootstrapFixture(t, 1)
	g.f.lostPrepare = true
	if _, err := runActualHTTPFixture(t, r, w, s); err == nil {
		t.Fatal("lost ACK not injected")
	}
	digest := retainedRecoveryDigest(t, r)
	c, err := r.Candidate(testContext, "root")
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.beginHTTPRebootstrap(testContext, c, s.httpFailure(410, "changes", "application/json", []byte(`{"code":"cursor_expired"}`)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.startRebootstrapSnapshot(testContext, c, *c.HTTPRebootstrap)
	if err != nil {
		t.Fatal(err)
	}
	p.ExpiresMS = time.Now().Add(-time.Minute).UnixMilli()
	err = r.sources.change(testContext, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if e := savePreparation(testContext, tx, p); e != nil {
			return e
		}
		for i := 0; i < 501; i++ {
			if e := saveRemoteCandidateEntry(testContext, tx, RemoteEntry{RootID: "root", Generation: p.Generation, NodeID: remoteVersion(10000 + i)}); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, s, c, p, digest
}

func TestEnduranceExpiredImportCrashResumesBoundedCleanup(t *testing.T) {
	for _, point := range []string{"expired_import_before_commit", "expired_import_marked", "expired_import_pruned", "expired_import_finished_before_commit"} {
		t.Run(point, func(t *testing.T) {
			r, s, _, p, digest := expiredImportFixture(t)
			r.testPoint = func(at string) error {
				if at == "http_rebootstrap."+point {
					return context.Canceled
				}
				return nil
			}
			if err := s.InitializeRemote(testContext); !errors.Is(err, context.Canceled) {
				t.Fatal("crash gate missed", err)
			}
			if digest != retainedRecoveryDigest(t, r) {
				t.Fatal("crash changed originals")
			}
			if point == "expired_import_pruned" {
				var n int
				if e := r.store.db.QueryRow("SELECT COUNT(*) FROM remote_entries WHERE root_id='root' AND generation=?", p.Generation).Scan(&n); e != nil || n != 1 {
					t.Fatal("cleanup must be bounded to 500 rows", n, e)
				}
			}
			s.Close()
			r.testPoint = nil
			next := rebootstrapSession(t, r, s, s.origin, nil)
			if err := next.InitializeRemote(testContext); err != nil {
				t.Fatal("restart", err)
			}
			if digest != retainedRecoveryDigest(t, r) {
				t.Fatal("restart changed originals")
			}
			c, err := r.Candidate(testContext, "root")
			if err != nil || !c.Valid || c.HTTPRebootstrap != nil {
				t.Fatal(c, err)
			}
		})
	}
}

func TestEnduranceExpiredImportRefusesUnsafeRetirement(t *testing.T) {
	for _, mode := range []string{"live-lease", "wrong-preparation", "wrong-binding", "wrong-pin", "stale-candidate", "active-generation", "replacement-limit"} {
		t.Run(mode, func(t *testing.T) {
			r, s, c, p, digest := expiredImportFixture(t)
			expected := c
			switch mode {
			case "live-lease":
				p.ExpiresMS = time.Now().Add(time.Minute).UnixMilli()
				if err := r.sources.change(testContext, MaxSourcePageBytes, func(tx *sql.Tx) error { return savePreparation(testContext, tx, p) }); err != nil {
					t.Fatal(err)
				}
			case "wrong-preparation":
				p.Cursor = "another-cursor"
			case "wrong-binding":
				s.binding.ServerEpoch = remoteVersion(99999)
			case "wrong-pin":
				s.transportPin = hashBytes([]byte("other transport"))
			case "stale-candidate":
				expected.Revision++
			case "active-generation":
				if _, err := r.store.db.Exec("UPDATE roots SET active_remote_generation=? WHERE root_id='root'", p.Generation); err != nil {
					t.Fatal(err)
				}
			case "replacement-limit":
				cp := *c.HTTPRebootstrap
				ids := make([]string, 16)
				for i := range ids {
					ids[i], _ = NewOperationID()
				}
				cp.RetiredSnapshotIDs = strings.Join(ids, ",")
				c.HTTPRebootstrap = &cp
				expected = c
				if err := r.sources.change(testContext, MaxSourcePageBytes, func(tx *sql.Tx) error { return saveCandidate(testContext, tx, c) }); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := r.Preparation(testContext, "root")
			if _, err := s.beginExpiredImportRetirement(testContext, expected, p, time.Now()); err == nil {
				t.Fatal("unsafe retirement admitted")
			}
			after, _ := r.Preparation(testContext, "root")
			current, _ := r.Candidate(testContext, "root")
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(current, c) || digest != retainedRecoveryDigest(t, r) {
				t.Fatal("rejection mutated retained state")
			}
			var n int
			if err := r.store.db.QueryRow("SELECT COUNT(*) FROM remote_entries WHERE root_id='root' AND generation=?", p.Generation).Scan(&n); err != nil || n != 501 {
				t.Fatal(n, err)
			}
		})
	}
}
