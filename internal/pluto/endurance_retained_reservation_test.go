//go:build linux

package pluto

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"pluto/internal/pluto/syncstate"
)

// Ordinary CI exercises the current recovery mechanism on fresh genuine owned
// originals. The retired October original-inode operator probe remains separate
// archival evidence and has no execution or compatibility credit here.
func TestEnduranceRetainedEmptyReservationRecovery(t *testing.T) {
	if os.Getenv("ENDURANCE_RETAINED_INDEXED") != "" {
		t.Fatal("legacy original-inode input belongs to the archived operator probe; ordinary CI requires the fresh current fixture")
	}
	ctx := context.Background()
	f := emptyCurrentFixture(t, ctx)
	backup := qualifyEmptyReservationBackup(t, f)
	var reports []syncstate.ArtifactReport
	var records []syncstate.ArtifactRecord
	for round := 0; round < 2; round++ {
		store, err := syncstate.Open(ctx, f.state)
		if err != nil {
			t.Fatal(err)
		}
		f.liveStore = store
		if _, err = store.EnableSources(ctx, syncstate.DefaultSourceLimits()); err != nil {
			t.Fatal(err)
		}
		admission, report, err := BootstrapArtifactAdmission(ctx, store, syncstate.DefaultArtifactLimits())
		f.liveAdmission = admission
		if err != nil || !report.Admitted {
			t.Fatal(report, err)
		}
		if report.RecoveryOperations != 4 || report.ReservedBytes != 132 {
			t.Fatalf("original pending bytes/operations changed: %+v", report)
		}
		expectedQuarantined := int64(0)
		if round == 0 {
			expectedQuarantined = 1
		}
		if report.QuarantinedEmptyFiles != expectedQuarantined {
			t.Fatal("unexpected repeated empty quarantine", round, report)
		}
		inspection, err := syncstate.InspectProfile(ctx, f.state)
		if err != nil || inspection.SchemaVersion != 8 {
			t.Fatal("current schema8 required", err)
		}
		emptyAssertOriginals(t, ctx, f, store, admission)
		records = nil
		for _, original := range f.originals {
			record, err := admission.Registry().Record(ctx, original.Evidence.SnapshotID)
			if err != nil || record.Phase != syncstate.ArtifactSealed || record.SizeBytes != 33 || record.ExpectedBytes != 33 || record.OperationID != original.Operation.OperationID || record.SHA256 != original.Evidence.SHA256 {
				t.Fatal("original sealed record changed", err)
			}
			records = append(records, record)
		}
		for _, id := range []string{f.noCreate, f.created} {
			record, err := admission.Registry().Record(ctx, id)
			if err != nil || record.Phase != syncstate.ArtifactGone || record.OperationID != "" || record.SnapshotID != "" || record.SHA256 != "" || record.SizeBytes != 0 || record.ExpectedBytes != 33 {
				t.Fatal("genuine empty reservation not retired", record, err)
			}
			records = append(records, record)
			if _, err = os.Lstat(filepath.Join(f.state, syncstate.ArtifactDirectoryName, id+".snapshot")); !os.IsNotExist(err) {
				t.Fatal("retired artifact path must be absent", err)
			}
		}
		q := filepath.Join(f.state, "sync-artifacts-quarantine-v1", f.created+".snapshot")
		info, err := os.Lstat(q)
		if err != nil || !os.SameFile(f.emptyInfo, info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 0 {
			t.Fatal("exact genuine empty inode must be preserved in quarantine", err)
		}
		physical := emptyFilePhysical(t, q)
		if physical.SHA256 != cHash(nil) {
			t.Fatal("quarantined original must remain empty")
		}
		charge, err := admission.Registry().Charge(ctx)
		if err != nil || charge != 132 {
			t.Fatal("only original pending bytes stay charged", charge, err)
		}
		reports = append(reports, report)
		if err = store.Close(); err != nil {
			t.Fatal(err)
		}
		f.liveStore = nil
		if err = admission.Detach(); err != nil {
			t.Fatal(err)
		}
		f.liveAdmission = nil
	}
	emptyRecordRecovery(t, f, backup, reports, records)
}
