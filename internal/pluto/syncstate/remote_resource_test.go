package syncstate

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"pluto/internal/syncproto"
)

func TestRemoteIndexedLargeCatalogOneChangeBounded(t *testing.T) {
	if os.Getenv("PLUTO_REMOTE_RESOURCE") != "1" {
		t.Skip("dedicated bounded100k/500k catalog qualification")
	}
	for _, count := range []int{100000, 500000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r, _, _ := remoteFixture(t)
			c := publishRemote(t, r, []syncproto.Descriptor{folderRemote("remote-root", "", "root")})
			// Structural fixture: real SQLite rows and returned descriptors. It is
			// deliberately not500k filesystem content reads or server authority.
			for start := 0; start < count; start += 1000 {
				if err := r.store.transaction(testContext, func(tx *sql.Tx) error {
					stmt, err := tx.Prepare("INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES('root',2,?,0,?)")
					if err != nil {
						return err
					}
					defer stmt.Close()
					for i := start; i < start+1000 && i < count; i++ {
						id := fmt.Sprintf("entry-%08d", i)
						d := fileRemote(id, "remote-root", fmt.Sprintf("name-%08d-%s", i, strings.Repeat("x", 128)), "one")
						e := remoteFromDescriptor("root", 2, 0, c.Binding, d, "")
						raw, _ := json.Marshal(e)
						if _, err = stmt.Exec(id, string(raw)); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			name := fmt.Sprintf("name-%08d-%s", count-1, strings.Repeat("x", 128))
			id := fmt.Sprintf("entry-%08d", count-1)
			query := "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND json_extract(descriptor_json,'$.ParentID')=? AND json_extract(descriptor_json,'$.Name')=? AND json_extract(descriptor_json,'$.Presence')='PRESENT' ORDER BY node_id LIMIT 2"
			rows, err := r.store.db.Query("EXPLAIN QUERY PLAN "+query, "root", 2, "remote-root", name)
			if err != nil {
				t.Fatal(err)
			}
			var explain []string
			for rows.Next() {
				var i, p, u int
				var detail string
				if err = rows.Scan(&i, &p, &u, &detail); err != nil {
					t.Fatal(err)
				}
				explain = append(explain, detail)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(explain, " "), "remote_candidate_namespace") || strings.Contains(strings.Join(explain, " "), "TEMP B-TREE") {
				t.Fatal("namespace not indexed", explain)
			}
			d := fileRemote(id, "remote-root", name, "two")
			d.Version = remoteVersion(100)
			raw := wireFeed(c.RemoteWitness, []syncproto.FeedItem{{Descriptor: d, Seq: "1", Kind: "upsert", OperationID: "one-change"}}, "one-change-cursor")
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			next, err := r.ImportFeed(testContext, c.RemoteWitness, raw)
			if err != nil {
				t.Fatal(err)
			}
			var returned *RemoteEntry
			if err = r.store.transaction(testContext, func(tx *sql.Tx) error {
				var e error
				returned, e = namespaceCandidate(testContext, tx, next.RemoteWitness, "remote-root", name)
				return e
			}); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			allocated := after.TotalAlloc - before.TotalAlloc
			if returned == nil || returned.NodeID != id || returned.SHA256 != hashBytes([]byte("two")) || allocated > 8<<20 {
				t.Fatal("one-change query/resource regression", returned, allocated)
			}
			usage, err := r.sources.DiskUsage(testContext)
			if err != nil {
				t.Fatal(err)
			}
			var peak any
			if data, err := os.ReadFile("/sys/fs/cgroup/memory.peak"); err == nil {
				peak = strings.TrimSpace(string(data))
			}
			t.Logf("REMOTE_RESOURCE %s", mustJSON(map[string]any{"rows": count, "returnedDescriptors": 1, "feedItems": 1, "allocatedBytes": allocated, "elapsedMicros": elapsed.Microseconds(), "retainedHeapBytes": after.HeapAlloc, "physical": usage, "queryPlan": explain, "cgroupPeakBytes": peak, "realRepeatSpeedClaim": false}))
		})
	}
}

func TestRemotePhysicalPinnedWALAdmissionPreservesCursor(t *testing.T) {
	r, _, _ := remoteFixture(t)
	c := publishRemote(t, r, []syncproto.Descriptor{folderRemote("remote-root", "", "root")})
	reader, err := openDB(r.store.filename, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	read, err := reader.BeginTx(testContext, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer read.Rollback()
	var raw string
	if err = read.QueryRow("SELECT descriptor_json FROM remote_candidate_roots WHERE root_id='root'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	// Hold an actual reader while committed fixture writes exceed the WAL cap.
	// The imported feed must see physical WAL usage, not the first PRAGMA scalar.
	for batch := 0; batch < 4; batch++ {
		if err = r.store.transaction(testContext, func(tx *sql.Tx) error {
			for i := 0; i < 100; i++ {
				id := fmt.Sprintf("fixture-%d-%d", batch, i)
				d := fileRemote(id, "remote-root", id+strings.Repeat("x", 900), "one")
				e := remoteFromDescriptor("root", 2, 0, c.Binding, d, "")
				if err := saveRemoteCandidateEntry(testContext, tx, e); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	u, err := r.sources.DiskUsage(testContext)
	if err != nil || u.PageSize < 512 || u.WAL <= 0 {
		t.Fatal("physical WAL accounting", u, err)
	}
	oldLimit := r.sources.limits.WALBytes
	r.sources.limits.WALBytes = u.WAL + MaxSourcePageBytes - 1
	defer func() { r.sources.limits.WALBytes = oldLimit }()
	if _, err = r.ImportFeed(testContext, c.RemoteWitness, wireFeed(c.RemoteWitness, nil, "feed")); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("pinned WAL ignored", u, err)
	}
	after, _ := r.Candidate(testContext, "root")
	if after.RemoteWitness != c.RemoteWitness {
		t.Fatal("quota refusal advanced cursor")
	}
}
