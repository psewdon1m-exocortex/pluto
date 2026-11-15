package syncstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSourceLargeStructuralStreamingAndIndexedWork(t *testing.T) {
	if os.Getenv("PLUTO_SOURCE_RESOURCE") != "1" {
		t.Skip("qualified separately with bounded dedicated resources")
	}
	for _, tc := range []struct{ count, keyBytes int }{{100000, 128}, {100000, 256}, {500000, 512}} {
		t.Run(fmt.Sprintf("%d-%d", tc.count, tc.keyBytes), func(t *testing.T) {
			remaining := tc.keyBytes - 22
			parts := []string{}
			for remaining > 120 {
				parts = append(parts, strings.Repeat("p", 120))
				remaining -= 121
			}
			parts = append(parts, strings.Repeat("p", remaining))
			prefix := "/synthetic/" + strings.Join(parts, "/")
			s, w, b := sourceFixture(t, prefix)
			if _, err := s.BeginScan(testContext, w, "source", "large"); err != nil {
				t.Fatal(err)
			}
			c, err := s.ClaimScanFrontier(testContext, w, "large")
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			peakHeap := uint64(0)
			maxPageAlloc := uint64(0)
			early := false
			for offset := 0; offset < tc.count; offset += MaxSourcePage {
				n := min(MaxSourcePage, tc.count-offset)
				page := ScanPage{Entries: make([]SourceDescriptor, n), EOF: offset+n == tc.count}
				for i := range n {
					name := fmt.Sprintf("f-%09d", offset+i)
					page.Entries[i] = SourceDescriptor{Destination: b.Destination + "/" + name, PhysicalPath: b.PhysicalPath + "/" + name, Kind: "file", Presence: "PRESENT", FileIdentity: fmt.Sprintf("fixture:%d", offset+i), SizeBytes: 3}
				}
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				c, err = s.CommitScanPage(testContext, c, page)
				if err != nil {
					t.Fatal(offset, err)
				}
				runtime.ReadMemStats(&after)
				maxPageAlloc = max(maxPageAlloc, after.TotalAlloc-before.TotalAlloc)
				peakHeap = max(peakHeap, after.HeapInuse)
				if offset == 0 {
					work, e := s.VerificationPage(testContext, w, "", 1)
					if e != nil || len(work) != 1 || c.Token == "" {
						t.Fatal("full scan barrier", work, e)
					}
					early = true
				}
				// Fixture-only bounded drain. No content proof/completion is fabricated:
				// this leaves one pending row for the structural keyset lookup probe.
				last := page.Entries[len(page.Entries)-1].Destination
				if page.EOF {
					last = page.Entries[len(page.Entries)-2].Destination
				}
				if _, err = s.store.db.Exec("DELETE FROM source_verification WHERE set_id=? AND destination<=?", w.SetID, last); err != nil {
					t.Fatal(err)
				}
			}
			if err = s.CompleteScanScope(testContext, w, "large"); err != nil {
				t.Fatal(err)
			}
			// One indexed pending row among N entries. This fixture completes no source
			// proof and claims no skip; it probes only work/lookup structure.
			keep := b.Destination + "/" + fmt.Sprintf("f-%09d", tc.count-1)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			probe := time.Now()
			work, err := s.VerificationPage(testContext, w, "", MaxSourcePage)
			elapsed := time.Since(probe)
			runtime.ReadMemStats(&after)
			if err != nil || len(work) != 1 || work[0].Entry.Destination != keep {
				t.Fatal(work, err)
			}
			if peakHeap > 192<<20 || maxPageAlloc > 8<<20 || after.HeapInuse > 64<<20 || after.TotalAlloc-before.TotalAlloc > 4<<20 {
				t.Fatal("bounded memory regression", peakHeap, maxPageAlloc, after.HeapInuse, after.TotalAlloc-before.TotalAlloc)
			}
			plans := []string{}
			rows, err := s.store.db.Query("EXPLAIN QUERY PLAN SELECT e.descriptor_json,e.generation,e.verification_request,e.ambiguous,v.request FROM source_verification v JOIN source_entries e USING(set_id,destination) WHERE v.set_id=? AND v.destination>? ORDER BY v.destination LIMIT ?", w.SetID, "", MaxSourcePage)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var a, b, c int
				var detail string
				if err = rows.Scan(&a, &b, &c, &detail); err != nil {
					t.Fatal(err)
				}
				plans = append(plans, detail)
				if strings.Contains(detail, "SCAN ") || strings.Contains(detail, "TEMP B-TREE") {
					t.Fatal("pending lookup scans whole tree", detail)
				}
			}
			rows.Close()
			var stored int
			s.store.db.QueryRow("SELECT COUNT(*) FROM source_entries").Scan(&stored)
			usage, err := s.DiskUsage(testContext)
			if err != nil || stored != tc.count || usage.Database+usage.WAL+usage.SHM > s.limits.DatabaseBytes || usage.WAL > s.limits.WALBytes {
				t.Fatal(stored, usage, err)
			}
			// cgroup memory.peak also includes reclaimable database page cache; report
			// the test process's actual RSS peak separately from its Go heap.
			status, err := os.ReadFile("/proc/self/status")
			if err != nil || len(status) > 65536 {
				t.Fatal("RSS evidence", err)
			}
			var rssPeak int64
			for _, line := range strings.Split(string(status), "\n") {
				if fields := strings.Fields(line); len(fields) == 3 && fields[0] == "VmHWM:" && fields[2] == "kB" {
					rssPeak, err = strconv.ParseInt(fields[1], 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					rssPeak *= 1024
				}
			}
			if rssPeak <= 0 || rssPeak > 256<<20 {
				t.Fatal("RSS resource regression", rssPeak)
			}
			result := map[string]any{"syntheticReturnedDescriptors": tc.count, "representativeKeyBytes": tc.keyBytes, "actualKeyBytes": len(keep), "readerBatchMax": MaxSourcePage, "firstWorkBeforeEOF": early, "storedEntries": stored, "pendingWork": len(work), "elapsedNS": time.Since(started).Nanoseconds(), "onePendingLookupNS": elapsed.Nanoseconds(), "maxPageAllocatedBytes": maxPageAlloc, "peakObservedHeapInuse": peakHeap, "peakProcessRSSBytes": rssPeak, "finalHeapInuse": after.HeapInuse, "lookupAllocatedBytes": after.TotalAlloc - before.TotalAlloc, "disk": usage, "limits": s.limits, "queryPlans": plans, "engineActivated": false, "realRepeatAccelerationClaim": false}
			raw, _ := json.Marshal(result)
			t.Log(string(raw))
			if dir := os.Getenv("PLUTO_SOURCE_EVIDENCE_DIR"); dir != "" {
				if err = os.WriteFile(filepath.Join(dir, fmt.Sprintf("source-%d-%d.json", tc.count, tc.keyBytes)), append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestSourceDeepFrontierAndLimits(t *testing.T) {
	s, w, b := sourceFixture(t, "/synthetic")
	s.BeginScan(testContext, w, "source", "deep")
	for depth := 0; depth <= MaxSourceDepth; depth++ {
		c, err := s.ClaimScanFrontier(testContext, w, "deep")
		if err != nil {
			t.Fatal(depth, err)
		}
		if depth == MaxSourceDepth {
			d := SourceDescriptor{Destination: c.Destination + "/child", PhysicalPath: c.PhysicalPath + "/child", Kind: "folder", Presence: "PRESENT"}
			if _, err = s.CommitScanPage(testContext, c, ScanPage{Children: []SourceDescriptor{d}, EOF: true}); !errors.Is(err, ErrSourceQuota) && err == nil {
				t.Fatal("depth escaped", err)
			}
			break
		}
		d := SourceDescriptor{Destination: c.Destination + "/d", PhysicalPath: c.PhysicalPath + "/d", Kind: "folder", Presence: "PRESENT", FileIdentity: fmt.Sprint(depth)}
		_, err = s.CommitScanPage(testContext, c, ScanPage{Entries: []SourceDescriptor{d}, Children: []SourceDescriptor{d}, EOF: true})
		if err != nil {
			if depth == MaxSourceDepth-1 {
				break
			}
			t.Fatal(depth, b, err)
		}
	}
	if err := s.CompleteScanScope(testContext, w, "deep"); !errors.Is(err, ErrSourceIncomplete) {
		t.Fatal(err)
	}
	var n int
	s.store.db.QueryRow("SELECT COUNT(*) FROM source_frontier").Scan(&n)
	if n != 1 {
		t.Fatal("frontier not bounded", n)
	}
}
