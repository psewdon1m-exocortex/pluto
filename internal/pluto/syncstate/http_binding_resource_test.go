package syncstate

import (
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

func TestHTTPCurrentScanIndexed100k500kRetainedVerification(t *testing.T) {
	if os.Getenv("PLUTO_HTTP_BINDING_RESOURCE") != "1" {
		t.Skip("qualified separately in bounded dedicated container")
	}
	for _, count := range []int{100000, 500000} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			r, s, w := remoteFixture(t)
			if err := r.enableHTTPBindings(testContext); err != nil {
				t.Fatal(err)
			}
			binding, err := s.Binding(testContext, w.SetID, "source")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.BeginScan(testContext, w, "source", "current-scan"); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			for offset := 0; offset < count; offset += MaxBatch {
				tx, err := s.store.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				e, err := tx.Prepare("INSERT INTO source_entries(set_id,destination,generation,verification_request,ambiguous,descriptor_json) VALUES(?,?,1,1,0,?)")
				if err != nil {
					t.Fatal(err)
				}
				m, err := tx.Prepare("INSERT INTO source_membership(set_id,source_id,destination,seen_scan_id) VALUES(?,?,?,?)")
				if err != nil {
					t.Fatal(err)
				}
				v, err := tx.Prepare("INSERT INTO source_verification(set_id,destination,request) VALUES(?,?,1)")
				if err != nil {
					t.Fatal(err)
				}
				for n := offset; n < min(offset+MaxBatch, count); n++ {
					key := fmt.Sprintf("f-%09d", n)
					entry := SourceEntry{SourceDescriptor: SourceDescriptor{Destination: key, PhysicalPath: filepath.Join(binding.PhysicalPath, key), Kind: "file", Presence: "PRESENT", FileIdentity: "synthetic-identity:" + key, SizeBytes: 3}, SetID: w.SetID, SourceID: "source", SourceRootPath: binding.PhysicalPath, Generation: 1, VerificationRequest: 1, SourceIncarnation: binding.Incarnation}
					raw := string(mustJSON(entry))
					seen := "previous-retained-scan"
					if n == count-1 {
						seen = "current-scan"
					}
					if _, err = e.Exec(w.SetID, key, raw); err != nil {
						t.Fatal(err)
					}
					if _, err = m.Exec(w.SetID, "source", key, seen); err != nil {
						t.Fatal(err)
					}
					if _, err = v.Exec(w.SetID, key); err != nil {
						t.Fatal(err)
					}
				}
				e.Close()
				m.Close()
				v.Close()
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			query := "SELECT e.descriptor_json,e.generation,e.verification_request,e.ambiguous,v.request FROM source_membership m INDEXED BY source_current_scan_entries JOIN source_verification v ON v.set_id=m.set_id AND v.destination=m.destination JOIN source_entries e ON e.set_id=m.set_id AND e.destination=m.destination WHERE m.seen_scan_id=? AND m.destination>? AND m.set_id=? AND m.source_id=? ORDER BY m.destination LIMIT ?"
			rows, err := s.store.db.Query("EXPLAIN QUERY PLAN "+query, "current-scan", "", w.SetID, "source", 128)
			if err != nil {
				t.Fatal(err)
			}
			plans := []string{}
			for rows.Next() {
				var a, b, c int
				var p string
				if err = rows.Scan(&a, &b, &c, &p); err != nil {
					t.Fatal(err)
				}
				plans = append(plans, p)
				if strings.Contains(p, "SCAN ") || strings.Contains(p, "TEMP B-TREE") {
					t.Fatal("unbounded lookup", p)
				}
			}
			rows.Close()
			if !strings.Contains(strings.Join(plans, ";"), "source_current_scan_entries") {
				t.Fatal(plans)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			probe := time.Now()
			page, err := s.VerificationPageForScan(testContext, w, "current-scan", "", 128)
			elapsed := time.Since(probe)
			runtime.ReadMemStats(&after)
			if err != nil || len(page) != 1 || page[0].Entry.Destination != fmt.Sprintf("f-%09d", count-1) {
				t.Fatal(page, err)
			}
			if after.TotalAlloc-before.TotalAlloc > 4<<20 || after.HeapInuse > 128<<20 {
				t.Fatal("unbounded page memory", after.TotalAlloc-before.TotalAlloc, after.HeapInuse)
			}
			if _, err = s.VerificationPageForScan(testContext, w, "current-scan", "", 129); err != ErrSourceQuota {
				t.Fatal("page cap", err)
			}
			var retained int
			s.store.db.QueryRow("SELECT COUNT(*) FROM source_verification").Scan(&retained)
			if retained != count {
				t.Fatal("historical work erased", retained)
			}
			usage, err := s.DiskUsage(testContext)
			if err != nil || usage.Database+usage.WAL+usage.SHM > s.limits.DatabaseBytes || usage.WAL > s.limits.WALBytes {
				t.Fatal(usage, err)
			}
			status, err := os.ReadFile("/proc/self/status")
			if err != nil {
				t.Fatal(err)
			}
			var rss int64
			for _, line := range strings.Split(string(status), "\n") {
				f := strings.Fields(line)
				if len(f) == 3 && f[0] == "VmHWM:" {
					rss, _ = strconv.ParseInt(f[1], 10, 64)
					rss *= 1024
				}
			}
			evidence := map[string]any{"entries": count, "retainedVerification": retained, "returned": len(page), "plans": plans, "pageAllocationBytes": after.TotalAlloc - before.TotalAlloc, "heapInuseBytes": after.HeapInuse, "rssPeakBytes": rss, "lookupNanoseconds": elapsed.Nanoseconds(), "setupMilliseconds": time.Since(start).Milliseconds(), "disk": usage, "scope": "structural indexed current-scan lookup; no content/authority proof"}
			raw, _ := json.MarshalIndent(evidence, "", "  ")
			t.Log(string(raw))
			if dir := os.Getenv("PLUTO_HTTP_BINDING_RESOURCE_DIR"); dir != "" {
				if err = os.WriteFile(filepath.Join(dir, fmt.Sprintf("http-current-scan-%d.json", count)), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
