package syncstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAbandonedCaptureRecoverySurvivesDisposalCrash(t *testing.T) {
	for _, point := range []string{"disposing", "unlinked", "disposed-synced"} {
		t.Run(point, func(t *testing.T) {
			s, a, _ := artifactFixture(t)
			r, err := a.Reserve(testContext, 33)
			if err != nil {
				t.Fatal(err)
			}
			f, err := r.Create(testContext)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write([]byte("incomplete")); err != nil {
				t.Fatal(err)
			}
			if err = f.Sync(); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			if err = r.Relinquish(); err != nil {
				t.Fatal(err)
			}
			a = reopenEmptyRecovery(t, s, a)
			a.crashPoint = func(stage string) {
				if stage == point {
					panic(point)
				}
			}
			func() {
				defer func() {
					if got := recover(); got != point {
						t.Fatalf("expected crash %s, got %v", point, got)
					}
				}()
				_ = a.RecoverAbandonedCaptures(testContext)
			}()
			a = reopenEmptyRecovery(t, a.store, a)
			if err = a.RecoverAbandonedCaptures(testContext); err != nil {
				t.Fatal(err)
			}
			if err = a.RecoverEmptyReservations(testContext); err != nil {
				t.Fatal(err)
			}
			report, err := a.Reconcile(testContext, artifactTestReader)
			if err != nil || !report.Admitted || report.ReservedBytes != 0 {
				t.Fatal(report, err)
			}
			if _, err = os.Lstat(filepath.Join(a.Directory(), r.ID()+".snapshot")); !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err = a.RecoverAbandonedCaptures(testContext); err != nil {
				t.Fatal("repeat", err)
			}
		})
	}
}
