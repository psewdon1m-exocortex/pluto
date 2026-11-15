package syncstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func reopenEmptyRecovery(t *testing.T, s *Store, a *Artifacts) *Artifacts {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(testContext, filepath.Dir(a.Directory()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := next.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err = next.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	b, err := next.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnduranceEmptyCapturingRestart(t *testing.T) {
	for _, nonempty := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "partial-bytes"}[nonempty], func(t *testing.T) {
			s, a, _ := artifactFixture(t)
			r, err := a.Reserve(testContext, 33)
			if err != nil {
				t.Fatal(err)
			}
			f, err := r.Create(testContext)
			if err != nil {
				t.Fatal(err)
			}
			if nonempty {
				if _, err = f.Write([]byte("preserve")); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.Sync(); err != nil {
				t.Fatal(err)
			}
			before, _ := f.Stat()
			f.Close()
			if err = r.Relinquish(); err != nil {
				t.Fatal(err)
			}
			a = reopenEmptyRecovery(t, s, a)
			err = a.RecoverEmptyReservations(testContext)
			report, reconcile := a.Reconcile(testContext, artifactTestReader)
			if nonempty {
				if reconcile == nil || report.Admitted {
					t.Fatal("partial bytes silently discarded")
				}
				data, _ := os.ReadFile(filepath.Join(a.Directory(), r.ID()+".snapshot"))
				if string(data) != "preserve" {
					t.Fatal("partial bytes changed")
				}
			} else {
				if err != nil || reconcile != nil || !report.Admitted || report.ReservedBytes != 0 {
					t.Fatal(report, err, reconcile)
				}
				q, err := os.Lstat(filepath.Join(filepath.Dir(a.Directory()), artifactQuarantineDirectory, r.ID()+".snapshot"))
				if err != nil || !os.SameFile(before, q) {
					t.Fatal("original empty inode not preserved", err)
				}
			}
		})
	}
}

func TestEnduranceEmptyCapturingCrashAfterQuarantine(t *testing.T) {
	s, a, _ := artifactFixture(t)
	r, err := a.Reserve(testContext, 33)
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.Create(testContext)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	a = reopenEmptyRecovery(t, s, a)
	if err = a.quarantineEmptyCreation(testContext, r.ID()); err != nil {
		t.Fatal(err)
	}
	a = reopenEmptyRecovery(t, a.store, a)
	if err = a.RecoverEmptyReservations(testContext); err != nil {
		t.Fatal(err)
	}
	if report, err := a.Reconcile(testContext, artifactTestReader); err != nil || !report.Admitted || report.ReservedBytes != 0 {
		t.Fatal(report, err)
	}
}

func TestEmptyReservationRecoveryPreservesForeignBytesAndLiveOwner(t *testing.T) {
	s, a, _ := artifactFixture(t)
	r, err := a.Reserve(testContext, 33)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.RecoverEmptyReservations(testContext); !errors.Is(err, ErrArtifactInUse) {
		t.Fatal(err)
	}
	if err = r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(a.Directory(), r.ID()+".snapshot")
	if err = os.WriteFile(name, []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	a = reopenEmptyRecovery(t, s, a)
	if err = a.RecoverEmptyReservations(testContext); !errors.Is(err, ErrArtifactUnreconciled) {
		t.Fatal(err)
	}
	b, err := os.ReadFile(name)
	if err != nil || string(b) != "unknown" {
		t.Fatal(string(b), err)
	}
	record, err := a.Record(testContext, r.ID())
	if err != nil || record.Phase != ArtifactReserved {
		t.Fatal(record, err)
	}
}

func TestEmptyCreationGapQuarantinesExactInodeAndResumes(t *testing.T) {
	s, a, _ := artifactFixture(t)
	r, err := a.Reserve(testContext, 33)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(a.Directory(), r.ID()+".snapshot")
	if err = os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	a = reopenEmptyRecovery(t, s, a)
	if err = a.RecoverEmptyReservations(testContext); err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(filepath.Dir(a.Directory()), artifactQuarantineDirectory, r.ID()+".snapshot")
	after, err := os.Lstat(q)
	if err != nil || !os.SameFile(before, after) || after.Size() != 0 {
		t.Fatal(after, err)
	}
	if _, err = os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	report, err := a.Reconcile(testContext, artifactTestReader)
	if err != nil || !report.Admitted || report.ReservedBytes != 0 || report.QuarantinedEmptyFiles != 1 {
		t.Fatal(report, err)
	}
	if err = a.RecoverEmptyReservations(testContext); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(q); err != nil {
		t.Fatal("quarantine evidence lost", err)
	}
}

func TestEmptyCreationGapRefusesAmbiguousObjects(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink", "directory", "collision"} {
		t.Run(kind, func(t *testing.T) {
			s, a, _ := artifactFixture(t)
			r, err := a.Reserve(testContext, 33)
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Relinquish(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(a.Directory(), r.ID()+".snapshot")
			switch kind {
			case "directory":
				err = os.Mkdir(name, 0700)
			case "symlink":
				err = os.Symlink(filepath.Join(t.TempDir(), "foreign"), name)
			default:
				err = os.WriteFile(name, nil, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "hardlink" {
				if err = os.Link(name, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "collision" {
				q := filepath.Join(filepath.Dir(a.Directory()), artifactQuarantineDirectory)
				if err = os.Mkdir(q, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(q, r.ID()+".snapshot"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Lstat(name)
			a = reopenEmptyRecovery(t, s, a)
			if err = a.RecoverEmptyReservations(testContext); err == nil {
				t.Fatal("ambiguous object admitted")
			}
			after, err := os.Lstat(name)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("original changed", err)
			}
		})
	}
}

func TestEmptyCreationGapRestartAfterQuarantineBeforeRetirement(t *testing.T) {
	s, a, _ := artifactFixture(t)
	r, err := a.Reserve(testContext, 33)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(a.Directory(), r.ID()+".snapshot")
	if err = os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	a = reopenEmptyRecovery(t, s, a)
	if err = a.quarantineEmptyCreation(testContext, r.ID()); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the durable rename, before Dispose records GONE.
	q := filepath.Join(filepath.Dir(a.Directory()), artifactQuarantineDirectory, r.ID()+".snapshot")
	before, err := os.Lstat(q)
	if err != nil {
		t.Fatal(err)
	}
	a = reopenEmptyRecovery(t, a.store, a)
	if err = a.RecoverEmptyReservations(testContext); err != nil {
		t.Fatal(err)
	}
	report, err := a.Reconcile(testContext, artifactTestReader)
	if err != nil || !report.Admitted || report.ReservedBytes != 0 {
		t.Fatal(report, err)
	}
	after, err := os.Lstat(q)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("original quarantine inode lost", err)
	}
}
