package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"sync"
	"testing"
)

type fixtureSmallBatchBudget struct {
	mu                       sync.Mutex
	groups                   map[string]int64
	initial                  []SmallBatchReservation
	failReserve, failRelease bool
}

func (f *fixtureSmallBatchBudget) InitializeSmallBatches(ctx context.Context, items []SmallBatchReservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.groups != nil {
		return ErrIdentityConflict
	}
	f.groups = map[string]int64{}
	f.initial = append([]SmallBatchReservation(nil), items...)
	for _, item := range items {
		f.groups[item.ID] = item.Bytes
	}
	return nil
}
func (f *fixtureSmallBatchBudget) ReserveSmallBatch(ctx context.Context, item SmallBatchReservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.failReserve {
		return ErrSourceQuota
	}
	if old, ok := f.groups[item.ID]; ok && old != item.Bytes {
		return ErrIdentityConflict
	}
	f.groups[item.ID] = item.Bytes
	return nil
}
func (f *fixtureSmallBatchBudget) ReleaseSmallBatch(ctx context.Context, item SmallBatchReservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.failRelease {
		return ErrArtifactUnreconciled
	}
	if old, ok := f.groups[item.ID]; ok && old != item.Bytes {
		return ErrIdentityConflict
	}
	delete(f.groups, item.ID)
	return nil
}
func (f *fixtureSmallBatchBudget) charge() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var size int64
	for _, n := range f.groups {
		size += n
	}
	return size
}

func TestSmallBatchBudgetExistingInventoryNoRechargeAndNativeRelease(t *testing.T) {
	r, native, ops := nativeSmallBatchFixture(t, 4)
	originals := batchOriginalState(t, r, ops)
	p1 := stateBatchPlan(t, "budget-existing-1", ops[:2])
	p2 := stateBatchPlan(t, "budget-existing-2", ops[2:])
	for _, p := range []*smallBatchPlan{p1, p2} {
		if _, err := native.build(testContext, p); err != nil {
			t.Fatal(err)
		}
	}
	budget := &fixtureSmallBatchBudget{}
	joined, err := newBudgetedSmallBatchArtifacts(testContext, native, budget)
	if err != nil {
		t.Fatal(err)
	}
	if len(budget.initial) != 2 || budget.charge() != 12 {
		t.Fatal(budget.initial, budget.charge())
	}
	if _, err = joined.build(testContext, p1); err != nil {
		t.Fatal(err)
	}
	if budget.charge() != 12 {
		t.Fatal("existing charged twice")
	}
	if err = joined.cleanup(testContext, p1.id); err != nil {
		t.Fatal(err)
	}
	if budget.charge() != 6 {
		t.Fatal(budget.charge())
	}
	if err = joined.cleanup(testContext, p1.id); err != nil {
		t.Fatal(err)
	}
	if budget.charge() != 6 {
		t.Fatal("repeat released other group")
	}
	if err = joined.cleanup(testContext, p2.id); err != nil {
		t.Fatal(err)
	}
	if budget.charge() != 0 || batchOriginalState(t, r, ops) != originals {
		t.Fatal("originals changed")
	}
}
func TestSmallBatchBudgetReserveFailureAndCommitUncertainty(t *testing.T) {
	for _, point := range []string{"admission", "small_batch.reserve.before_commit", "small_batch.reserve.after_commit", "small_batch.created.before_identity", "small_batch.copied_original", "small_batch.ready.after_commit"} {
		t.Run(point, func(t *testing.T) {
			r, native, ops := nativeSmallBatchFixture(t, 2)
			budget := &fixtureSmallBatchBudget{}
			joined, err := newBudgetedSmallBatchArtifacts(testContext, native, budget)
			if err != nil {
				t.Fatal(err)
			}
			p := stateBatchPlan(t, "budget-fault", ops)
			budget.failReserve = point == "admission"
			r.testPoint = func(name string) error {
				if name == point {
					return context.Canceled
				}
				return nil
			}
			if _, err = joined.build(testContext, p); err == nil {
				t.Fatal("injected fault accepted")
			}
			r.testPoint = nil
			saved, readErr := native.state.read(testContext, p.id)
			if point == "admission" || point == "small_batch.reserve.before_commit" {
				if !errors.Is(readErr, sql.ErrNoRows) || budget.charge() != 0 {
					t.Fatal("absent group kept reservation", readErr, budget.charge())
				}
			} else {
				if readErr != nil || budget.charge() != 6 {
					t.Fatal("committed uncertainty lost charge", saved.Phase, readErr, budget.charge())
				}
				cleanup := joined.cleanup(testContext, p.id)
				if point == "small_batch.created.before_identity" {
					if cleanup == nil || budget.charge() != 6 {
						t.Fatal("unknown file released", cleanup)
					}
				} else if cleanup != nil || budget.charge() != 0 {
					t.Fatal(cleanup, budget.charge())
				}
			}
		})
	}
}
func TestSmallBatchBudgetGoneCommitReleaseFailureAndRetry(t *testing.T) {
	r, native, ops := nativeSmallBatchFixture(t, 2)
	budget := &fixtureSmallBatchBudget{}
	joined, err := newBudgetedSmallBatchArtifacts(testContext, native, budget)
	if err != nil {
		t.Fatal(err)
	}
	p := stateBatchPlan(t, "budget-gone", ops)
	if _, err = joined.build(testContext, p); err != nil {
		t.Fatal(err)
	}
	budget.failRelease = true
	r.testPoint = func(point string) error {
		if point == "small_batch.gone.after_commit" {
			return context.Canceled
		}
		return nil
	}
	if err = joined.cleanup(testContext, p.id); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrArtifactUnreconciled) {
		t.Fatal(err)
	}
	r.testPoint = nil
	saved, err := native.state.read(testContext, p.id)
	if err != nil || saved.Phase != "GONE" || budget.charge() != 6 {
		t.Fatal(saved.Phase, err, budget.charge())
	}
	budget.failRelease = false
	if err = joined.cleanup(testContext, p.id); err != nil || budget.charge() != 0 {
		t.Fatal(err, budget.charge())
	}
}
func TestSmallBatchBudgetRejectsInitializationDuringNativeUse(t *testing.T) {
	_, native, ops := nativeSmallBatchFixture(t, 2)
	p := stateBatchPlan(t, "budget-live", ops)
	if _, err := native.build(testContext, p); err != nil {
		t.Fatal(err)
	}
	if err := native.withAttempt(testContext, p.id, func(smallBatchRecord, io.ReadSeeker) error {
		budget := &fixtureSmallBatchBudget{}
		if _, e := newBudgetedSmallBatchArtifacts(testContext, native, budget); !errors.Is(e, ErrArtifactInUse) || budget.groups != nil {
			t.Fatal("initialized with active native reader", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
