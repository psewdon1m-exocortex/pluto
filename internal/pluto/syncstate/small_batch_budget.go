package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

type SmallBatchReservation struct {
	ID    string
	Bytes int64
}

// The process-wide owner installs its existing durable charges without adding
// them twice. New reservations precede file creation; release is idempotent by
// group identity and follows verified native cleanup, never a network Boolean.
type SmallBatchBudget interface {
	InitializeSmallBatches(context.Context, []SmallBatchReservation) error
	ReserveSmallBatch(context.Context, SmallBatchReservation) error
	ReleaseSmallBatch(context.Context, SmallBatchReservation) error
}

type budgetedSmallBatchArtifacts struct {
	native *smallBatchArtifacts
	budget SmallBatchBudget
	mu     sync.Mutex
	live   map[string]bool
}

func newBudgetedSmallBatchArtifacts(ctx context.Context, native *smallBatchArtifacts, budget SmallBatchBudget) (*budgetedSmallBatchArtifacts, error) {
	if native == nil || budget == nil {
		return nil, ErrIdentityConflict
	}
	native.mu.Lock()
	defer native.mu.Unlock()
	if len(native.live) != 0 {
		return nil, ErrArtifactInUse
	}
	if err := native.checkNamespace(ctx); err != nil {
		return nil, err
	}
	rows, err := native.state.remote.store.db.QueryContext(ctx, "SELECT batch_id,expected_bytes FROM small_batch_groups WHERE phase<>'GONE' ORDER BY batch_id LIMIT 5")
	if err != nil {
		return nil, err
	}
	var inventory []SmallBatchReservation
	for rows.Next() {
		var item SmallBatchReservation
		if err = rows.Scan(&item.ID, &item.Bytes); err != nil {
			rows.Close()
			return nil, err
		}
		inventory = append(inventory, item)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	if len(inventory) > 4 {
		return nil, ErrSourceQuota
	}
	if err = budget.InitializeSmallBatches(ctx, inventory); err != nil {
		return nil, err
	}
	return &budgetedSmallBatchArtifacts{native: native, budget: budget, live: map[string]bool{}}, nil
}

func (b *budgetedSmallBatchArtifacts) acquire(id string) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live[id] {
		return nil, ErrArtifactInUse
	}
	if len(b.live) >= 4 {
		return nil, ErrSourceQuota
	}
	b.live[id] = true
	return func() { b.mu.Lock(); delete(b.live, id); b.mu.Unlock() }, nil
}

func (b *budgetedSmallBatchArtifacts) phase(ctx context.Context, id string) (string, int64, error) {
	var phase string
	var size int64
	err := b.native.state.remote.store.db.QueryRowContext(ctx, "SELECT phase,expected_bytes FROM small_batch_groups WHERE batch_id=?", id).Scan(&phase, &size)
	return phase, size, err
}

func (b *budgetedSmallBatchArtifacts) releaseIfRetired(ctx context.Context, reservation SmallBatchReservation) error {
	// A canceled sender still needs to reconcile a local committed reservation.
	// This bounded read cannot initiate network or filesystem cleanup.
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	phase, size, err := b.phase(check, reservation.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return b.budget.ReleaseSmallBatch(check, reservation)
	}
	if err != nil {
		return err
	}
	if size != reservation.Bytes {
		return ErrIdentityConflict
	}
	if phase == "GONE" {
		return b.budget.ReleaseSmallBatch(check, reservation)
	}
	return nil
}

func (b *budgetedSmallBatchArtifacts) build(ctx context.Context, plan *smallBatchPlan) (record smallBatchRecord, err error) {
	if plan == nil {
		return record, ErrIdentityConflict
	}
	release, err := b.acquire(plan.id)
	if err != nil {
		return record, err
	}
	defer release()
	phase, size, err := b.phase(ctx, plan.id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return record, err
	}
	if err == nil && size != plan.dataBytes {
		return record, ErrIdentityConflict
	}
	if phase == "GONE" {
		return b.native.build(ctx, plan)
	}
	reservation := SmallBatchReservation{plan.id, plan.dataBytes}
	if err = b.budget.ReserveSmallBatch(ctx, reservation); err != nil {
		return record, err
	}
	defer func() { err = errors.Join(err, b.releaseIfRetired(ctx, reservation)) }()
	return b.native.build(ctx, plan)
}

func (b *budgetedSmallBatchArtifacts) cleanup(ctx context.Context, id string) (err error) {
	release, err := b.acquire(id)
	if err != nil {
		return err
	}
	defer release()
	_, size, err := b.phase(ctx, id)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, b.releaseIfRetired(ctx, SmallBatchReservation{id, size})) }()
	return b.native.cleanup(ctx, id)
}
