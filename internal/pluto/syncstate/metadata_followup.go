package syncstate

import (
	"context"
	"database/sql"
	"errors"
)

// EnableMetadataFollowups is wired only by the qualified daemon with negotiated
// namespace mutations. A content receipt does not claim that source mtime was
// published. Keep that real remaining operation in the ordinary observer queue.
func (r *RemoteImport) EnableMetadataFollowups(ctx context.Context, w SourceWitness) error {
	if _, err := r.sources.ObserverStatus(ctx, w); err != nil {
		return err
	}
	r.metadataObserver.Store(&w)
	return nil
}

func (r *RemoteImport) afterCapturedContentAck(ctx context.Context, operationID string) error {
	w := r.metadataObserver.Load()
	if w == nil {
		return nil
	}
	if err := r.point("metadata.after_content_ack"); err != nil {
		return err
	}
	return r.queueCapturedMetadata(ctx, *w, operationID)
}

func (r *RemoteImport) queueCapturedMetadata(ctx context.Context, w SourceWitness, operationID string) error {
	var hint *DirtyHint
	err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		set, err := r.sources.checkWitness(ctx, tx, w)
		if err != nil {
			return err
		}
		op, err := readOperation(ctx, tx, operationID)
		if err != nil {
			return err
		}
		if op.Kind != "PUT" || op.Stage != "CLIENT_ACKED" || op.Captured == nil || op.RootID != set.AttachedRootID || op.Captured.Evidence.SetID != w.SetID {
			return nil
		}
		base, err := readJSON[Baseline](ctx, tx, "SELECT descriptor_json FROM baselines WHERE root_id=? AND entry_id=?", op.RootID, op.EntryID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// Replaying an old content receipt cannot dirty a newer agreement.
		if base.OperationID != op.OperationID || base.LocalGeneration != op.LocalGeneration {
			return nil
		}
		evidence := op.Captured.Evidence
		source, err := readSourceEntry(ctx, tx, w.SetID, evidence.Destination)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // Removing a source never deletes its stored copy.
		}
		if err != nil {
			return err
		}
		if source.Ambiguous || source.Generation != evidence.EntryGeneration || source.SourceIncarnation != evidence.SourceIncarnation || source.FileIdentity != op.FileIdentity || base.PublishedMTimeNS == source.MTimeNS {
			return nil
		}
		hint = &DirtyHint{SourceID: source.SourceID, Destination: source.Destination, PhysicalPath: source.PhysicalPath}
		return nil
	})
	if err != nil || hint == nil {
		return err
	}
	// Advancing the hint generation prevents the cycle's old ACK(g) from
	// consuming this followup or a concurrent native g+1. It grants no authority:
	// the normal targeted scanner still rechecks source and CAS before effects.
	if err = r.point("metadata.before_dirty"); err != nil {
		return err
	}
	if err = r.sources.RecordDirty(ctx, w, []DirtyHint{*hint}); err != nil {
		return err
	}
	return r.point("metadata.after_dirty")
}
