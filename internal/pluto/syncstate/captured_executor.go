package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"
)

// CapturedSession is an opt-in adapter boundary, not an HTTP contract. Only a
// future qualified package adapter can mint Authority. Raw pages/feed do not do
// so. Publish must use absent or node+metadata version CAS and the separately
// sealed expected content version, with the original immutable idempotency key.
type CapturedSession interface {
	Authority(context.Context) (*RemoteAuthority, error)
	Publish(context.Context, Operation, io.Reader) (CapturedPublication, error)
	// nil means unknown/pending, never absence or permission to replace an ID.
	Recover(context.Context, Operation) (*CapturedPublication, error)
}
type CapturedExecution struct {
	Kind, OperationID           string
	Uploaded, Recovered, Queued bool
}

// ExecuteCaptured composes actual private bytes→intent→transport→receipt→B.
// It is not called by legacy Copy/Serve and cannot accept public shape as
// authority. Every retained outcome keeps its original operation identity.
func (r *RemoteImport) ExecuteCaptured(ctx context.Context, w SourceWitness, root, entry string, v *VerifiedSnapshot, session CapturedSession, now time.Time) (out CapturedExecution, err error) {
	return r.executeCaptured(ctx, w, root, entry, v, session, now, nil)
}
func (r *RemoteImport) executeCaptured(ctx context.Context, w SourceWitness, root, entry string, v *VerifiedSnapshot, session CapturedSession, now time.Time, disposeRecovered func(context.Context, Operation) error) (out CapturedExecution, err error) {
	defer func() {
		if out.OperationID != "" && err != nil {
			var waiting *RetryWait
			if !errors.As(err, &waiting) {
				err = r.store.RecordRetry(ctx, out.OperationID, err)
			}
		}
	}()
	if session == nil {
		return out, ErrRemoteUnqualified
	}
	if v != nil {
		defer func() {
			cleanup := v.Close()
			if errors.Is(cleanup, ErrArtifactRetained) {
				cleanup = v.Retain()
			}
			err = errors.Join(err, cleanup)
		}()
	}
	// Historical status recovery needs the original binding/identity rather
	// than permission to create a new current-root operation.
	d, err := r.DecideCaptured(ctx, w, root, entry, nil, nil, now)
	if err != nil {
		return out, err
	}
	var a *RemoteAuthority
	if d.Kind != "RECOVER" {
		a, err = session.Authority(ctx)
		if err != nil {
			return out, err
		}
		if clock, ok := session.(interface{ ExecutionTime() time.Time }); ok {
			now = clock.ExecutionTime()
		}
		d, err = r.DecideCaptured(ctx, w, root, entry, v, a, now)
		if err != nil {
			return out, err
		}
	}
	out.Kind = d.Kind
	out.OperationID = d.OperationID
	var choice *MutationChoice
	if v != nil {
		if http := httpSession(session); http != nil {
			choice, err = http.chooseMutation(ctx, d, v)
			if err != nil {
				return out, err
			}
		}
	}
	switch d.Kind {
	case "RECOVER":
		if d.OperationID == "" {
			return out, ErrArtifactRetained
		}
		if e := r.store.RetryReady(ctx, d.OperationID); e != nil {
			return out, e
		}
		op, e := r.store.Operation(ctx, d.OperationID)
		if e != nil {
			return out, e
		}
		if op.Captured == nil {
			return out, ErrRemoteUnqualified
		}
		pub, e := session.Recover(ctx, op)
		if e != nil {
			return out, e
		}
		if pub == nil {
			return out, ErrArtifactRetained
		}
		if pub.Receipt.OperationID != op.OperationID {
			return out, ErrInvalidReceipt
		}
		if e = r.AckCaptured(ctx, *pub); e != nil {
			return out, e
		}
		out.Recovered = true
		if e = r.store.ClearRetry(ctx, op.OperationID); e != nil {
			return out, e
		}
		// Dispose only after exact historical receipt ACK. Startup admission owns
		// retained charge reconciliation; a live reservation is closed by defer.
		if v == nil || v.Evidence().SnapshotID != op.SnapshotID {
			if disposeRecovered != nil {
				e = disposeRecovered(ctx, op)
			} else {
				e = r.store.artifacts.Dispose(ctx, op.SnapshotID)
			}
			if e != nil {
				return out, e
			}
		}
		return out, nil
	case "ADOPT_EQUAL":
		return out, r.adoptCaptured(ctx, w, v, a, d, now, true)
	case "NOOP_CAPTURED":
		if choice == nil {
			return out, r.adoptCaptured(ctx, w, v, a, d, now, true)
		}
		fallthrough
	case "CREATE", "OVERWRITE":
		var op Operation
		var e error
		staged := false
		for attempt := 0; attempt < 3; attempt++ {
			id, idErr := NewOperationID()
			if idErr != nil {
				return out, idErr
			}
			op, e = r.planCapturedMutation(ctx, w, v, a, d, id, now, true, choice)
			if e == nil {
				out.OperationID = id
				staged = true
				break
			}
			// A failed local commit may have persisted the exact original ID. Never
			// replace it based on an error alone, even before network invocation.
			_, lookup := r.store.Operation(ctx, id)
			if !errors.Is(lookup, sql.ErrNoRows) || (!errors.Is(e, ErrStaleGeneration) && !errors.Is(e, ErrRemoteUnqualified)) {
				return out, errors.Join(e, lookup)
			}
			a, e = session.Authority(ctx)
			if e != nil {
				return out, e
			}
			if clock, ok := session.(interface{ ExecutionTime() time.Time }); ok {
				now = clock.ExecutionTime()
			}
			d, e = r.DecideCaptured(ctx, w, root, entry, v, a, now)
			if e != nil {
				return out, e
			}
			if d.Kind != "CREATE" && d.Kind != "OVERWRITE" && !(d.Kind == "NOOP_CAPTURED" && choice != nil && choice.Kind == "metadata-patch") {
				return out, ErrStaleGeneration
			}
		}
		if !staged {
			return out, ErrStaleGeneration
		}
		if batch, ok := session.(*smallBatchCaptureSession); ok && batch.deferCaptured(op) {
			// Only retain the durable original here. The scan owner enqueues it
			// after the complete native source/capture scope has returned.
			out.Queued = true
			return out, nil
		}
		var pub CapturedPublication
		publicationStarted := time.Now()
		e = streamCaptured(ctx, v, func(reader io.Reader) error {
			var transportErr error
			pub, transportErr = session.Publish(ctx, op, reader)
			return transportErr
		})
		if e != nil {
			return out, e
		}
		if e = r.AckCaptured(ctx, pub); e != nil {
			return out, e
		}
		out.Uploaded = true
		RecordPublication(op.SizeBytes, time.Since(publicationStarted))
		return out, nil
	case "KEEP_REMOTE":
		return out, nil
	case "VERIFY":
		return out, ErrInvalidReceipt
	default:
		return out, fmt.Errorf("%w: %s", ErrRemoteUnqualified, d.Reason)
	}
}
