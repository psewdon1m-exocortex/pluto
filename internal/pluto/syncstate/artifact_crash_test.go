package syncstate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestArtifactCrashChildFixture(t *testing.T) {
	mode := os.Getenv("PLUTO_ARTIFACT_CRASH_POINT")
	if mode == "" {
		return
	}
	dir := os.Getenv("PLUTO_ARTIFACT_CRASH_DIRECTORY")
	s, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	s.EnableSources(testContext, DefaultSourceLimits())
	a, err := s.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	a.crashPoint = func(point string) {
		if point == mode {
			os.Exit(77)
		}
	}
	r, err := a.Reserve(testContext, 4)
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.Create(testContext)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("four"))
	if mode == "partial" {
		f.Sync()
		os.Exit(77)
	}
	f.Sync()
	f.Chmod(0400)
	f.Close()
	info, _ := os.Stat(f.Name())
	v := &VerifiedSnapshot{filename: f.Name(), sealed: info, evidence: SnapshotEvidence{SnapshotID: r.ID(), SizeBytes: 4, SHA256: hashBytes([]byte("four")), GuardDigest: hashBytes([]byte("fixture guard"))}, limiter: newTestCaptureLimiter(), release: func() {}}
	if err = r.SealSnapshot(testContext, v); err != nil {
		t.Fatal(err)
	}
	if err = r.Dispose(testContext); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash point not reached", mode)
}
func TestArtifactActualProcessCrashBoundaries(t *testing.T) {
	for _, point := range []string{"reserved", "created", "registered", "partial", "sealed", "disposing", "unlinked", "disposed-synced", "gone"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			baseline, err := Open(testContext, dir)
			if err != nil {
				t.Fatal(err)
			}
			// Capture the core-only starting state before the original child enables
			// directory-bound modules. Restoring an already-bound inode is refused.
			if err = baseline.Close(); err != nil {
				t.Fatal(err)
			}
			backup := qualifyClosedFixtureBackup(t, dir, nil, func(restored *Store) {
				if _, err := restored.EnableSources(testContext, DefaultSourceLimits()); err != nil {
					t.Fatal(err)
				}
				a, err := restored.EnableArtifacts(testContext, DefaultArtifactLimits())
				if err != nil {
					t.Fatal(err)
				}
				report, err := a.Reconcile(testContext, artifactTestReader)
				if err != nil || !report.Admitted || !report.Complete || report.Records != 0 || report.Files != 0 {
					t.Fatal("restored empty artifact baseline", report, err)
				}
			})
			command := exec.Command(os.Args[0], "-test.run=^TestArtifactCrashChildFixture$")
			command.Env = append(os.Environ(), "PLUTO_ARTIFACT_CRASH_POINT="+point, "PLUTO_ARTIFACT_CRASH_DIRECTORY="+dir)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatal("fixture didn't crash at selected boundary", string(output), err)
			}
			backup.recordActualExit(t, "TestArtifactCrashChildFixture", command.Process.Pid, exit.ExitCode())
			s, err := Open(testContext, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.EnableSources(testContext, DefaultSourceLimits()); err != nil {
				t.Fatal(err)
			}
			a, err := s.EnableArtifacts(testContext, DefaultArtifactLimits())
			if err != nil {
				t.Fatal(err)
			}
			var id string
			if err = s.db.QueryRow("SELECT artifact_id FROM local_artifacts").Scan(&id); err != nil {
				t.Fatal(err)
			}
			report, err := a.Reconcile(testContext, artifactTestReader)
			if point == "sealed" || point == "gone" {
				if err != nil || !report.Admitted {
					t.Fatal(report, err)
				}
			} else if !errors.Is(err, ErrArtifactUnreconciled) || report.Admitted {
				t.Fatal("incomplete crash authorized work", report, err)
			}
			if point != "gone" && report.ReservedBytes != 4 {
				t.Fatal("restart lost charge", report)
			}
			if point == "created" {
				// File exists before its inode row is committed. No identity guessing.
				if err = a.Dispose(testContext, id); err == nil {
					t.Fatal("created gap blindly deleted")
				}
				if _, err = os.Stat(filepath.Join(a.Directory(), id+".snapshot")); err != nil {
					t.Fatal("unknown creation disappeared", err)
				}
			} else {
				if err = a.Dispose(testContext, id); err != nil {
					t.Fatal("exact lifecycle recovery failed", err)
				}
				if charge, err := a.Charge(testContext); err != nil || charge != 0 {
					t.Fatal(charge, err)
				}
			}
		})
	}
}
