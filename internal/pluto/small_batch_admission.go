package pluto

import (
	"context"
	"errors"

	"pluto/internal/pluto/syncstate"
)

// One instance belongs to the current indexed enumeration. Its ledger survives
// all joined packet workers; durable entries are reconstructed on the next run.
type smallBatchAdmission struct {
	budget      *copyBudget
	owner       string
	initialized bool
	groups      map[string]int64
}

func (a *ArtifactAdmission) smallBatchBudget() syncstate.SmallBatchBudget {
	return &smallBatchAdmission{budget: a.budget, owner: a.owner}
}
func validBatchReservation(item syncstate.SmallBatchReservation) bool {
	return len(item.ID) > 0 && len(item.ID) <= 128 && item.Bytes >= 0 && item.Bytes <= 32<<20
}
func (a *smallBatchAdmission) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b := a.budget
	if b.artifactOwner != a.owner || a.owner == "" || b.artifactBootstrap {
		return syncstate.ErrIdentityConflict
	}
	if b.spoolFailure != nil {
		return b.spoolFailure
	}
	return nil
}
func (a *smallBatchAdmission) InitializeSmallBatches(ctx context.Context, inventory []syncstate.SmallBatchReservation) error {
	b := a.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := a.ready(ctx); err != nil {
		return err
	}
	if a.initialized || len(b.workers) != 0 || len(b.readers) != 0 || b.spoolBytes != 0 || b.liveArtifactBytes != 0 || len(inventory) > 4 {
		return syncstate.ErrArtifactInUse
	}
	groups := make(map[string]int64, len(inventory))
	var total int64
	for _, item := range inventory {
		if !validBatchReservation(item) {
			return syncstate.ErrIdentityConflict
		}
		if _, ok := groups[item.ID]; ok {
			return syncstate.ErrIdentityConflict
		}
		groups[item.ID] = item.Bytes
		total += item.Bytes
	}
	if total > b.retainedBytes {
		return syncstate.ErrIdentityConflict
	}
	a.groups = groups
	a.initialized = true
	// Bootstrap already charged originals AND saved aggregates from SQLite.
	return nil
}
func (a *smallBatchAdmission) ReserveSmallBatch(ctx context.Context, item syncstate.SmallBatchReservation) error {
	b := a.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := a.ready(ctx); err != nil {
		return err
	}
	if !a.initialized || !validBatchReservation(item) {
		return syncstate.ErrIdentityConflict
	}
	if old, ok := a.groups[item.ID]; ok {
		if old != item.Bytes {
			return syncstate.ErrIdentityConflict
		}
		return nil
	}
	if len(a.groups) >= 4 || item.Bytes > b.spoolLimit-b.spoolBytes-b.retainedBytes {
		return syncstate.ErrSourceQuota
	}
	if len(b.artifactDirectories) < 1 {
		return syncstate.ErrIdentityConflict
	}
	directory := b.artifactDirectories[0]
	if err := b.artifactDirectory(directory); err != nil {
		return err
	}
	if err := checkSpoolSpace(directory, b.spoolBytes+b.retainedBytes+item.Bytes+b.metadataBytes); err != nil {
		return err
	}
	a.groups[item.ID] = item.Bytes
	b.retainedBytes += item.Bytes
	return nil
}
func (a *smallBatchAdmission) ReleaseSmallBatch(ctx context.Context, item syncstate.SmallBatchReservation) error {
	b := a.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := a.ready(ctx); err != nil {
		return err
	}
	if !a.initialized || !validBatchReservation(item) {
		return syncstate.ErrIdentityConflict
	}
	old, ok := a.groups[item.ID]
	if !ok {
		return nil
	}
	if old != item.Bytes || old > b.retainedBytes-b.liveArtifactBytes {
		b.spoolFailure = errors.Join(syncstate.ErrArtifactUnreconciled, syncstate.ErrIdentityConflict)
		close(b.changed)
		b.changed = make(chan struct{})
		return b.spoolFailure
	}
	delete(a.groups, item.ID)
	b.retainedBytes -= old
	close(b.changed)
	b.changed = make(chan struct{})
	return nil
}
