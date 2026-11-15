package syncstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestArtifactLargeCorruptCatalogRefusalBounded(t *testing.T) {
	if os.Getenv("PLUTO_ARTIFACT_RESOURCE") != "1" {
		t.Skip("dedicated bounded structural resource qualification")
	}
	for _, count := range []int{100000, 500000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, a, _ := artifactFixture(t)
			// This deliberately violates the API's 4096 record invariant. The probe
			// qualifies bounded refusal of oversized imported/corrupt metadata, not
			// a legitimate 500k-file spool or faster real repeat.
			for start := 0; start < count; start += 1000 {
				tx, err := s.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				stmt, err := tx.Prepare("INSERT INTO local_artifacts(artifact_id,filename,phase,expected_bytes) VALUES(?,?,'GONE',0)")
				if err != nil {
					t.Fatal(err)
				}
				for i := start; i < start+1000; i++ {
					id := fmt.Sprintf("%08x-0000-4000-8000-000000000000", i)
					if _, err = stmt.Exec(id, id+".snapshot"); err != nil {
						t.Fatal(err)
					}
				}
				stmt.Close()
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			began := time.Now()
			report, err := a.Reconcile(testContext, artifactTestReader)
			elapsed := time.Since(began)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, ErrArtifactUnreconciled) || report.Admitted || report.Complete || report.Records != MaxArtifactRecords+1 || report.Files != 0 {
				t.Fatal("unbounded or false completeness", report, err)
			}
			allocated := after.TotalAlloc - before.TotalAlloc
			if allocated > 512<<10 {
				t.Fatal("refusal allocated tree data", allocated)
			}
			rows, err := s.db.Query("EXPLAIN QUERY PLAN SELECT COUNT(*),COALESCE(SUM(CASE WHEN phase='GONE' THEN 0 ELSE expected_bytes END),0) FROM (SELECT phase,expected_bytes FROM local_artifacts ORDER BY artifact_id LIMIT 4097)")
			if err != nil {
				t.Fatal(err)
			}
			details := []string{}
			for rows.Next() {
				var id, parent, unused int
				var detail string
				rows.Scan(&id, &parent, &unused, &detail)
				details = append(details, detail)
			}
			rows.Close()
			if strings.Contains(strings.Join(details, " "), "TEMP B-TREE") {
				t.Fatal(details)
			}
			u, err := a.sources.DiskUsage(testContext)
			if err != nil {
				t.Fatal(err)
			}
			rss, _ := os.ReadFile("/proc/self/status")
			peak, _ := os.ReadFile("/sys/fs/cgroup/memory.peak")
			if out := os.Getenv("PLUTO_ARTIFACT_RESOURCE_DIR"); out != "" {
				os.MkdirAll(out, 0700)
				raw, _ := json.MarshalIndent(map[string]any{"syntheticCatalogRecords": count, "recordLimit": MaxArtifactRecords, "examinedRecordBound": report.Records, "directoryEntriesRead": report.Files, "refusalAllocatedBytes": allocated, "elapsedNS": elapsed.Nanoseconds(), "database": u.Database, "wal": u.WAL, "shm": u.SHM, "backup": u.Backup, "processStatus": string(rss), "cgroupMemoryPeak": strings.TrimSpace(string(peak)), "explain": details, "admitted": false, "complete": false, "engineActivated": false, "realRepeatAccelerationClaim": false}, "", "  ")
				os.WriteFile(filepath.Join(out, fmt.Sprintf("catalog-%d.json", count)), append(raw, '\n'), 0600)
			}
		})
	}
}
func TestArtifactPermissionsUnderActualUnprivilegedUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("dedicated actual UID65534 qualification")
	}
	_, a, _ := artifactFixture(t)
	r, v := sealedArtifact(t, a, []byte("permission"))
	if err := r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(v.filename, 0); err != nil {
		t.Fatal(err)
	}
	if report, err := a.Reconcile(testContext, artifactTestReader); !errors.Is(err, ErrArtifactUnreconciled) || report.Admitted {
		t.Fatal("unreadable artifact accepted", report, err)
	}
	if info, err := os.Lstat(v.filename); err != nil || info.Size() != 10 {
		t.Fatal("permission refusal erased bytes", info, err)
	}
	if err := os.Chmod(v.filename, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
}
