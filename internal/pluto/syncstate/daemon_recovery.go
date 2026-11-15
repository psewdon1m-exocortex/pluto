package syncstate

import (
	"context"
	"errors"
	"time"
)

func (r *RemoteImport) RecoverOriginals(ctx context.Context, o CapturedScanOptions) (int64, error) {
	ctx = WithWorkClass(ctx, "recovery")
	var recovered int64
	after := ""
	for {
		page, err := r.store.PendingPage(ctx, o.RootID, after, MaxSourcePage)
		if err != nil {
			return recovered, err
		}
		if len(page) == 0 {
			return recovered, nil
		}
		for _, op := range page {
			after = op.OperationID
			if err = r.store.RetryReady(ctx, op.OperationID); err != nil {
				if deferredRetry(err) {
					continue
				}
				return recovered, err
			}
			started := time.Now()
			if op.FolderHTTP != nil {
				session := httpSession(o.Session)
				if session == nil {
					return recovered, ErrRemoteUnqualified
				}
				raw, e := session.sendFolder(ctx, op)
				if e != nil {
					e = r.store.RecordRetry(ctx, op.OperationID, e)
					if deferredRetry(e) {
						continue
					}
					return recovered, e
				}
				rc, e := readFolderHTTPReceipt(raw, op)
				if e != nil {
					return recovered, e
				}
				if e = r.ackHTTPFolder(ctx, op, rc); e != nil {
					return recovered, e
				}
				if e = r.store.ClearRetry(ctx, op.OperationID); e != nil {
					return recovered, e
				}
				if e = session.Refresh(ctx); e != nil {
					return recovered, e
				}
				recovered++
				continue
			}
			if op.Stream != nil {
				session := httpSession(o.Session)
				if session == nil {
					return recovered, ErrRemoteUnqualified
				}
				if err = session.StreamOriginal(ctx, op, o.AcquireStream); err != nil {
					if deferredRetry(err) {
						continue
					}
					return recovered, err
				}
				recovered++
				continue
			}
			if op.Captured == nil {
				continue
			} // Directory originals are recovered by PrepareParents.
			if err = r.store.RetryReady(ctx, op.OperationID); err != nil {
				if deferredRetry(err) {
					continue
				}
				return recovered, err
			}
			release := func() {}
			if o.AcquireRecovery != nil {
				release, err = o.AcquireRecovery(ctx)
				if err != nil {
					return recovered, err
				}
			}
			pub, e := o.Session.Recover(ctx, op)
			release()
			if e != nil {
				e = r.store.RecordRetry(ctx, op.OperationID, e)
				if deferredRetry(e) {
					continue
				}
				return recovered, e
			}
			if pub == nil {
				e = r.store.RecordRetry(ctx, op.OperationID, ErrArtifactRetained)
				if deferredRetry(e) {
					continue
				}
				return recovered, e
			}
			if pub.Receipt.OperationID != op.OperationID {
				return recovered, ErrInvalidReceipt
			}
			if e = r.AckCaptured(ctx, *pub); e != nil {
				return recovered, e
			}
			if e = r.store.ClearRetry(ctx, op.OperationID); e != nil {
				return recovered, e
			}
			if o.DisposeRecovered != nil {
				e = o.DisposeRecovered(ctx, op)
			} else {
				e = r.store.artifacts.Dispose(ctx, op.SnapshotID)
			}
			if e != nil && !errors.Is(e, ErrArtifactRetained) {
				return recovered, e
			}
			// The historical operation has completed before source enumeration.
			// Claim its destination in this cycle's bounded disk dispatch set,
			// just as packet recovery does, so disabling batching cannot recapture
			// acknowledged originals. A newer source generation remains eligible
			// for the next reconciliation; this is not a persisted success proof.
			if o.Attempts != nil && op.Captured.Evidence.SetID == o.Witness.SetID {
				if _, e = o.Attempts.ClaimAttempt(ctx, op.Captured.Evidence.Destination); e != nil {
					return recovered, e
				}
			}
			recovered++
			RecordPublication(op.SizeBytes, time.Since(started))
		}
	}
}
func deferredRetry(err error) bool { var waiting *RetryWait; return errors.As(err, &waiting) }
