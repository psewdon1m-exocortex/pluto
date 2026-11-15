package pluto

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"pluto/internal/pluto/syncstate"
)

func batchAdmissionFixture(t *testing.T, retained int64) (*smallBatchAdmission, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "snapshots")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	b := newCopyBudget(2, 1, 20)
	if err := b.installArtifactOwner("batch-owner", 0, directory); err != nil {
		t.Fatal(err)
	}
	if err := b.completeArtifactBootstrap("batch-owner", retained); err != nil {
		t.Fatal(err)
	}
	return &smallBatchAdmission{budget: b, owner: "batch-owner"}, directory
}
func TestSmallBatchAdmissionBootstrapReservationAndIdempotentRelease(t *testing.T) {
	ctx := context.Background()
	a, directory := batchAdmissionFixture(t, 9)
	old := syncstate.SmallBatchReservation{ID: "existing", Bytes: 3}
	if err := a.InitializeSmallBatches(ctx, []syncstate.SmallBatchReservation{old}); err != nil {
		t.Fatal(err)
	}
	if a.budget.retainedBytes != 9 {
		t.Fatal("startup batch charged twice")
	}
	if err := a.ReserveSmallBatch(ctx, old); err != nil || a.budget.retainedBytes != 9 {
		t.Fatal(err)
	}
	next := syncstate.SmallBatchReservation{ID: "next", Bytes: 4}
	if err := a.ReserveSmallBatch(ctx, next); err != nil || a.budget.retainedBytes != 13 {
		t.Fatal(err)
	}
	if err := a.budget.reserveSpool(ctx, directory, 8); !errors.Is(err, syncstate.ErrArtifactRetained) {
		t.Fatal("aggregate absent from capture budget", err)
	}
	if err := a.ReleaseSmallBatch(ctx, next); err != nil || a.budget.retainedBytes != 9 {
		t.Fatal(err)
	}
	if err := a.ReleaseSmallBatch(ctx, next); err != nil || a.budget.retainedBytes != 9 {
		t.Fatal("double release", err)
	}
	if err := a.ReleaseSmallBatch(ctx, old); err != nil || a.budget.retainedBytes != 6 {
		t.Fatal("released original charge", err)
	}
	if err := a.budget.releaseRetained(a.owner, 6); err != nil {
		t.Fatal(err)
	}
	if err := a.budget.reserveSpool(ctx, directory, 20); err != nil {
		t.Fatal("cleanup left stale capacity", err)
	}
	a.budget.releaseSpool(20)
}
func TestSmallBatchAdmissionRejectsQuotaCancelledAndChangedReservation(t *testing.T) {
	ctx := context.Background()
	a, _ := batchAdmissionFixture(t, 6)
	if err := a.InitializeSmallBatches(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.ReserveSmallBatch(ctx, syncstate.SmallBatchReservation{ID: "oversize", Bytes: 15}); !errors.Is(err, syncstate.ErrSourceQuota) || a.budget.retainedBytes != 6 {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := a.ReserveSmallBatch(canceled, syncstate.SmallBatchReservation{ID: "cancelled", Bytes: 1}); !errors.Is(err, context.Canceled) || len(a.groups) != 0 {
		t.Fatal(err)
	}
	item := syncstate.SmallBatchReservation{ID: "original", Bytes: 3}
	if err := a.ReserveSmallBatch(ctx, item); err != nil {
		t.Fatal(err)
	}
	if err := a.ReserveSmallBatch(ctx, syncstate.SmallBatchReservation{ID: item.ID, Bytes: 4}); !errors.Is(err, syncstate.ErrIdentityConflict) || a.budget.retainedBytes != 9 {
		t.Fatal(err)
	}
	if err := a.ReleaseSmallBatch(ctx, syncstate.SmallBatchReservation{ID: item.ID, Bytes: 4}); !errors.Is(err, syncstate.ErrArtifactUnreconciled) || a.budget.retainedBytes != 9 || a.groups[item.ID] != 3 {
		t.Fatal("changed release lowered charge", err)
	}
}
func TestSmallBatchAdmissionBoundedInventoryAndZeroByteGroups(t *testing.T) {
	ctx := context.Background()
	for _, inventory := range [][]syncstate.SmallBatchReservation{{{ID: "a", Bytes: 7}}, {{ID: "a", Bytes: 1}, {ID: "a", Bytes: 1}}, {{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}, {ID: "e"}}} {
		a, _ := batchAdmissionFixture(t, 6)
		if err := a.InitializeSmallBatches(ctx, inventory); err == nil || a.initialized || a.budget.retainedBytes != 6 {
			t.Fatal("invalid inventory accepted", inventory, err)
		}
	}
	a, _ := batchAdmissionFixture(t, 0)
	if err := a.InitializeSmallBatches(ctx, nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c", "d"} {
		if err := a.ReserveSmallBatch(ctx, syncstate.SmallBatchReservation{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.ReserveSmallBatch(ctx, syncstate.SmallBatchReservation{ID: "e"}); !errors.Is(err, syncstate.ErrSourceQuota) || len(a.groups) != 4 {
		t.Fatal(err)
	}
	if err := a.InitializeSmallBatches(ctx, nil); err == nil {
		t.Fatal("inventory replaced active ledger")
	}
}
