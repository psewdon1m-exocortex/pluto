package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestEnduranceExpiredInitialImportRetainsSourceAndResumes(t *testing.T) {
	for _, crash := range []string{"", "initial_import.pruned", "initial_import.read_linked", "initial_import.read_archived", "initial_import.before_commit"} {
		t.Run(crash, func(t *testing.T) {
			r, _, _, old, _, _ := actualHTTPFixtureInitialization(t, 1, false)
			id, err := r.pendingHTTPSnapshot(old.binding)
			if err != nil {
				t.Fatal(err)
			}
			p, err := r.PrepareSnapshot(testContext, "root", 1, wireReady(old.binding, id, "0"), time.Now())
			if err != nil {
				t.Fatal(err)
			}
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
			digest := retainedRecoveryDigest(t, r)
			if crash != "" {
				r.testPoint = func(point string) error {
					if point == crash {
						return context.Canceled
					}
					return nil
				}
				if err = old.InitializeRemote(testContext); !errors.Is(err, context.Canceled) {
					t.Fatal("crash missed", err)
				}
				r.testPoint = nil
				old.Close()
				old = rebootstrapSession(t, r, old, old.origin, nil)
			}
			if err = old.InitializeRemote(testContext); err != nil {
				t.Fatal("expired initial import must converge", err)
			}
			if digest != retainedRecoveryDigest(t, r) {
				t.Fatal("changed original source/B/artifacts")
			}
			c, err := r.Candidate(testContext, "root")
			if err != nil || !c.Valid || c.SnapshotID == id {
				t.Fatal(c, err)
			}
			var stale int
			if err = r.store.db.QueryRow("SELECT COUNT(*) FROM remote_entries WHERE root_id='root' AND node_id>=?", remoteVersion(10000)).Scan(&stale); err != nil || stale != 0 {
				t.Fatal("stale initial cache", stale, err)
			}
			archives, _ := filepath.Glob(filepath.Join(filepath.Dir(r.store.filename), "http-snapshot-*.expired-*"))
			if len(archives) != 1 {
				t.Fatal("old read identity evidence", len(archives))
			}
		})
	}
}

func TestEnduranceInitialImportRetirementRejectsUnqualifiedState(t *testing.T) {
	for _, mode := range []string{"unexpired", "zero-expiry", "wrong-binding", "wrong-read-id", "wrong-generation", "wrong-trust", "wrong-root"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, s, _, _ := actualHTTPFixtureInitialization(t, 1, false)
			id, err := r.pendingHTTPSnapshot(s.binding)
			if err != nil {
				t.Fatal(err)
			}
			p, err := r.PrepareSnapshot(testContext, "root", 1, wireReady(s.binding, id, "0"), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			p.ExpiresMS = time.Now().Add(-time.Minute).UnixMilli()
			switch mode {
			case "unexpired":
				p.ExpiresMS = time.Now().Add(time.Minute).UnixMilli()
			case "zero-expiry":
				p.ExpiresMS = 0
			case "wrong-binding":
				p.Snapshot.ServerEpoch = remoteVersion(54321)
			case "wrong-read-id":
				p.Snapshot.SnapshotID = remoteVersion(54321)
			case "wrong-generation":
				p.Generation = 3
			case "wrong-trust":
				p.TrustGeneration++
			case "wrong-root":
				s.identity.DeviceID = remoteVersion(54321)
			}
			err = r.sources.change(testContext, MaxSourcePageBytes, func(tx *sql.Tx) error {
				if e := savePreparation(testContext, tx, p); e != nil {
					return e
				}
				return saveRemoteCandidateEntry(testContext, tx, RemoteEntry{RootID: "root", Generation: p.Generation, NodeID: remoteVersion(10000)})
			})
			if err != nil {
				t.Fatal(err)
			}
			digest := retainedRecoveryDigest(t, r)
			err = s.retireExpiredInitialImport(testContext)
			if mode == "unexpired" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unqualified retirement accepted")
			}
			got, e := r.Preparation(testContext, "root")
			if e != nil || fingerprint(got) != fingerprint(p) {
				t.Fatal("preparation changed", e)
			}
			var count int
			if e = r.store.db.QueryRow("SELECT COUNT(*) FROM remote_entries WHERE root_id='root'").Scan(&count); e != nil || count != 1 {
				t.Fatal("cache changed", count, e)
			}
			if digest != retainedRecoveryDigest(t, r) {
				t.Fatal("retained originals changed")
			}
		})
	}
}
