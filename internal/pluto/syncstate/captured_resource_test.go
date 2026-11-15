package syncstate

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCapturedLargeIndexedPublicationAndReceiptHistory(t *testing.T) {
	if os.Getenv("PLUTO_CAPTURED_RESOURCE") != "1" {
		t.Skip("dedicated bounded 100k/500k captured executor qualification")
	}
	for _, count := range []int{100000, 500000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r, w, v, entry, c, original := createCapturedOperationFixture(t)
			if _, err := r.store.db.Exec("DELETE FROM operations WHERE operation_id=?", original.OperationID); err != nil {
				t.Fatal(err)
			}
			for start := 0; start < count; start += MaxBatch {
				if err := r.store.transaction(testContext, func(tx *sql.Tx) error {
					remote, err := tx.Prepare("INSERT INTO remote_entries(root_id,generation,node_id,last_seq,descriptor_json) VALUES('root',?,?,0,?)")
					if err != nil {
						return err
					}
					defer remote.Close()
					history, err := tx.Prepare("INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,'root',?,?,'PUT','{}','fixture-only','CLIENT_ACKED')")
					if err != nil {
						return err
					}
					defer history.Close()
					for i := start; i < min(start+MaxBatch, count); i++ {
						id := fmt.Sprintf("unrelated-%09d", i)
						d := fileRemote(id, c.Binding.RootID, id+strings.Repeat("x", 128), "one")
						e := remoteFromDescriptor("root", c.Generation, 0, c.Binding, d, "")
						if _, err = remote.Exec(c.Generation, id, string(mustJSON(e))); err != nil {
							return err
						}
						if _, err = history.Exec("history-"+id, entry, i+1000); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(start, err)
				}
			}
			queries := []struct {
				sql   string
				args  []any
				index string
			}{
				{"SELECT operation_id FROM operations WHERE root_id=? AND entry_id=? AND stage<>'CLIENT_ACKED' ORDER BY local_generation,kind LIMIT 2", []any{"root", entry}, "pending_entry_operations"},
				{"SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND json_extract(descriptor_json,'$.ParentID')=? AND json_extract(descriptor_json,'$.Name')=? AND json_extract(descriptor_json,'$.Presence')='PRESENT' ORDER BY node_id LIMIT 2", []any{"root", c.Generation, c.Binding.RootID, "unrelated-000000001" + strings.Repeat("x", 128)}, "remote_candidate_namespace"},
			}
			plans := []string{}
			for _, q := range queries {
				rows, err := r.store.db.Query("EXPLAIN QUERY PLAN "+q.sql, q.args...)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for rows.Next() {
					var a, b, c int
					var d string
					if err = rows.Scan(&a, &b, &c, &d); err != nil {
						t.Fatal(err)
					}
					plans = append(plans, d)
					found = found || strings.Contains(d, q.index)
					if strings.Contains(d, "TEMP B-TREE") || strings.HasPrefix(d, "SCAN ") {
						t.Fatal("unbounded indexed work", d)
					}
				}
				err = rows.Err()
				rows.Close()
				if err != nil || !found {
					t.Fatal(q.index, plans, err)
				}
			}
			s := &fixtureCapturedSession{r: r, results: make(map[string]CapturedPublication), published: make(chan struct{})}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			out, err := r.ExecuteCaptured(testContext, w, "root", entry, v, s, remoteNow)
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			if err != nil || !out.Uploaded || s.writes.Load() != 1 || after.TotalAlloc-before.TotalAlloc > 16<<20 {
				t.Fatal("one captured effect not bounded", out, err, after.TotalAlloc-before.TotalAlloc)
			}
			current, err := r.store.Operation(testContext, out.OperationID)
			if err != nil || current.Stage != "CLIENT_ACKED" || current.Captured == nil {
				t.Fatal(current, err)
			}
			usage, err := r.sources.DiskUsage(testContext)
			if err != nil || usage.Database+usage.WAL+usage.SHM > r.sources.limits.DatabaseBytes || usage.WAL > r.sources.limits.WALBytes {
				t.Fatal(usage, err)
			}
			status, err := os.ReadFile("/proc/self/status")
			if err != nil || len(status) > 65536 {
				t.Fatal(err)
			}
			var rss int64
			for _, line := range strings.Split(string(status), "\n") {
				f := strings.Fields(line)
				if len(f) == 3 && f[0] == "VmHWM:" {
					n, e := strconv.ParseInt(f[1], 10, 64)
					if e != nil {
						t.Fatal(e)
					}
					rss = n * 1024
				}
			}
			if rss <= 0 || rss > 512<<20 {
				t.Fatal("captured process RSS regression", rss)
			}
			peak, _ := os.ReadFile("/sys/fs/cgroup/memory.peak")
			result := map[string]any{"syntheticCatalogRows": count, "syntheticAckHistoryRowsSameEntry": count, "actualOwnCapturedFiles": 1, "actualPublishedFiles": s.writes.Load(), "actualHashedSourceBytes": 3, "executionAllocatedBytes": after.TotalAlloc - before.TotalAlloc, "retainedHeapBytes": after.HeapAlloc, "executionMicros": elapsed.Microseconds(), "processPeakRSSBytes": rss, "cgroupPeakBytes": strings.TrimSpace(string(peak)), "physical": usage, "queryPlan": plans, "full500kContentReadClaim": false, "productionActivation": false, "defaultCopyChanged": false}
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(raw))
			if dir := os.Getenv("PLUTO_CAPTURED_RESOURCE_DIR"); dir != "" {
				if err = os.WriteFile(filepath.Join(dir, fmt.Sprintf("captured-resource-%d.json", count)), append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
