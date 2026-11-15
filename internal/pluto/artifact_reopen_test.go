package pluto

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"pluto/internal/pluto/syncstate"
)

func TestArtifactAdmissionReopensJoinedProfileWithRetainedBytes(t *testing.T) {
	ctx := context.Background()
	store, admission, witness, entry := admissionFixture(t)
	value, err := admission.Capture(ctx, witness, entry)
	if err != nil {
		t.Fatal(err)
	}
	id := value.Evidence().SnapshotID
	if err = value.Retain(); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = admission.Detach(); err != nil {
		t.Fatal(err)
	}

	reopened, err := syncstate.Open(ctx, filepath.Dir(admission.Registry().Directory()))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.EnableSources(ctx, syncstate.DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	next, report, err := BootstrapArtifactAdmission(ctx, reopened, syncstate.DefaultArtifactLimits())
	if err != nil || !report.Admitted {
		t.Fatalf("same profile cannot reopen: report=%+v error=%v", report, err)
	}
	if next.owner == admission.owner {
		t.Fatal("owner generation was reused")
	}
	if copyResources.retainedBytes != entry.SizeBytes || len(copyResources.workers) != 0 {
		t.Fatal("retained accounting lost or live worker leaked")
	}
	record, err := next.Registry().Record(ctx, id)
	if err != nil || record.SHA256 != value.Evidence().SHA256 || record.Phase != syncstate.ArtifactSealed {
		t.Fatal(record, err)
	}
	if err = admission.Detach(); !errors.Is(err, syncstate.ErrArtifactInUse) {
		t.Fatal("stale admission detached current owner", err)
	}
	if err = next.Registry().Dispose(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = copyResources.releaseRetained(next.owner, entry.SizeBytes); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err = next.Detach(); err != nil {
		t.Fatal(err)
	}

	other, err := syncstate.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.EnableSources(ctx, syncstate.DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = BootstrapArtifactAdmission(ctx, other, syncstate.DefaultArtifactLimits()); !errors.Is(err, syncstate.ErrArtifactInUse) {
		t.Fatal("different profile bypassed process owner", err)
	}
}

// A crash after durable Reserve but before Create leaves no captured bytes or
// network operation. Startup must reconcile that exact empty reservation.
func TestArtifactAdmissionReopensAfterCrashBeforeCreate(t *testing.T) {
	ctx := context.Background()
	store, admission, _, _ := admissionFixture(t)
	r, err := admission.Registry().Reserve(ctx, 33)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = admission.Detach(); err != nil {
		t.Fatal(err)
	}
	reopened, err := syncstate.Open(ctx, filepath.Dir(admission.Registry().Directory()))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.EnableSources(ctx, syncstate.DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	next, report, err := BootstrapArtifactAdmission(ctx, reopened, syncstate.DefaultArtifactLimits())
	if err != nil || !report.Admitted {
		t.Fatalf("empty crash reservation blocked recovery: %+v %v", report, err)
	}
	record, err := next.Registry().Record(ctx, r.ID())
	if err != nil || record.Phase != syncstate.ArtifactGone || report.ReservedBytes != 0 {
		t.Fatal(record, report, err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err = next.Detach(); err != nil {
		t.Fatal(err)
	}
}
