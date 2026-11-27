package syncstate

import (
	"context"
	"database/sql"
)

// A read observation is not a replacement source witness or remote authority.
// Only an already accepted mount-only transition can read an unsealed original
// from its new mount. The immutable source descriptor, input and wire witness
// stay unchanged; the existing reader still checks inode/size/mtime/ctime, all
// acknowledged part hashes, and the whole-file hash before sealing.
type streamSourceReadObservation struct {
	root    SourceIncarnationObservation
	witness SourceWitness
	binding SourceBinding
}

func (s *IsolatedHTTPSession) observedStreamSource(ctx context.Context, op Operation) (streamSourceReadObservation, error) {
	var out streamSourceReadObservation
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if op.Stream == nil {
		return out, ErrIdentityConflict
	}
	source := op.Stream.Source
	observed, err := ObserveSourceIncarnation(source.SourceRootPath)
	if err != nil {
		return out, ErrCaptureChanged
	}
	out.root = observed
	if observed.object == source.SourceObject {
		return out, nil
	}
	if !mountOnlyReobservation(source.SourceObject, observed.object) {
		return out, ErrCaptureChanged
	}
	out.witness, out.binding, err = s.acceptedStreamRemount(ctx, op, observed)
	return out, err
}

func (s *IsolatedHTTPSession) acceptedStreamRemount(ctx context.Context, op Operation, observed SourceIncarnationObservation) (SourceWitness, SourceBinding, error) {
	var zero SourceWitness
	var empty SourceBinding
	source := op.Stream.Source
	sources := s.r.sources
	sources.mu.Lock()
	defer sources.mu.Unlock()
	w, ok := sources.owners[source.SetID]
	if !ok || source.Kind != "file" || source.Presence != "PRESENT" || source.Ambiguous || source.SetID != op.Stream.Witness.SetID || w.Revision != op.Stream.Witness.Revision || source.SourceIncarnation < 1 || observed.physical != source.SourceRootPath {
		return zero, empty, ErrCaptureChanged
	}
	tx, err := s.r.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return zero, empty, err
	}
	defer tx.Rollback()
	set, err := sources.checkWitness(ctx, tx, w)
	if err != nil || set.AttachedRootID != op.RootID || op.RootID != s.root {
		return zero, empty, ErrCaptureChanged
	}
	root, err := readRoot(ctx, tx, op.RootID)
	if err != nil || root.SourceIdentity != source.SetID {
		return zero, empty, ErrCaptureChanged
	}
	b, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND revision=? AND active=1", source.SetID, source.SourceID, w.Revision)
	if err != nil || b.ID != source.SourceID || !b.Active || b.Revision != w.Revision || b.PhysicalPath != source.SourceRootPath || b.IncarnationStatus != "LOCAL_OBSERVED" || b.PendingObject != (SourceObject{}) || b.Incarnation <= source.SourceIncarnation || b.Object != observed.object || !mountOnlyReobservation(source.SourceObject, b.Object) {
		return zero, empty, ErrCaptureChanged
	}
	if err = tx.Commit(); err != nil {
		return zero, empty, err
	}
	return w, b, nil
}

func (s *IsolatedHTTPSession) validateStreamSourceRead(ctx context.Context, op Operation, expected streamSourceReadObservation) error {
	current, err := s.observedStreamSource(ctx, op)
	if err != nil {
		return err
	}
	if current != expected {
		return ErrCaptureChanged
	}
	return nil
}
