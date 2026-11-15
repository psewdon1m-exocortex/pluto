package syncstate

import (
	"context"
	"errors"
	"io"
)

// Exact historical recovery keeps the retained charge and original intent.
// No recapture or new operation identity is admitted.
func (a *Artifacts) WithRecoveryReader(ctx context.Context, op Operation, reader func(context.Context) (func(), error), use func(io.Reader) error) (err error) {
	if reader == nil || use == nil {
		return ErrIdentityConflict
	}
	a.mu.Lock()
	if !a.ready || len(a.live) >= 2 || a.live[op.SnapshotID] != nil {
		a.mu.Unlock()
		return ErrArtifactInUse
	}
	record, e := readArtifact(ctx, a.store.db, op.SnapshotID)
	if e == nil {
		e = a.validate(ctx, a.store.db)
	}
	if e == nil && record.Phase != ArtifactSealed {
		e = ErrIdentityConflict
	}
	var original Operation
	if e == nil {
		original, e = artifactOperation(ctx, a.store.db, record)
	}
	if e != nil || original.Stage != "SUBMITTED" || original.IntentFingerprint != op.IntentFingerprint || original.SealedFingerprint != op.SealedFingerprint || original.OperationID != op.OperationID {
		a.mu.Unlock()
		return errors.Join(ErrIdentityConflict, e)
	}
	r := &ArtifactReservation{registry: a, id: record.ID}
	a.live[record.ID] = r
	a.mu.Unlock()
	defer func() { err = errors.Join(err, r.Relinquish()) }()
	return r.WithReader(ctx, reader, use)
}
