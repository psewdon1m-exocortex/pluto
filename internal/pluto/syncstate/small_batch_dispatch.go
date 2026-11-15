package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"time"
)

// This optional dispatcher consumes durable originals after capture has joined.
// It neither creates a source observation nor substitutes a packet receipt for
// the existing per-operation ACK and L/B/R checks. Normal sessions stay unchanged.
type smallBatchDispatcher struct {
	native                       *smallBatchArtifacts
	session                      *IsolatedHTTPSession
	acquire                      func(context.Context) (func(), error)
	lanes                        chan struct{}
	shared                       *budgetedSmallBatchArtifacts
	dispose                      func(context.Context, Operation) error
	capability, legacyCapability *smallBatchCapability
}

func newSmallBatchDispatcher(native *smallBatchArtifacts, session *IsolatedHTTPSession, acquire func(context.Context) (func(), error)) (*smallBatchDispatcher, error) {
	if native == nil || session == nil || acquire == nil || native.state.remote != session.r || session.recoveryReader == nil {
		return nil, ErrIdentityConflict
	}
	return &smallBatchDispatcher{native: native, session: session, acquire: acquire, lanes: make(chan struct{}, 2), dispose: func(ctx context.Context, op Operation) error {
		err := session.r.store.artifacts.Dispose(ctx, op.SnapshotID)
		if errors.Is(err, sql.ErrNoRows) {
			return session.r.store.artifacts.ConfirmDisposedOriginal(ctx, op)
		}
		return err
	}}, nil
}

func (d *smallBatchDispatcher) build(ctx context.Context, plan *smallBatchPlan) (smallBatchRecord, error) {
	if d.shared != nil {
		return d.shared.build(ctx, plan)
	}
	return d.native.build(ctx, plan)
}
func (d *smallBatchDispatcher) cleanup(ctx context.Context, id string) error {
	if d.shared != nil {
		return d.shared.cleanup(ctx, id)
	}
	return d.native.cleanup(ctx, id)
}

func (d *smallBatchDispatcher) dispatch(ctx context.Context, plan *smallBatchPlan) error {
	if err := d.session.requireSmallBatch(plan); err != nil {
		return err
	}
	select {
	case d.lanes <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-d.lanes }()
	release, err := d.acquire(ctx)
	if err != nil {
		return err
	}
	if release == nil {
		return ErrIdentityConflict
	}
	defer release()
	return d.group(ctx, plan, true)
}

func (d *smallBatchDispatcher) group(ctx context.Context, plan *smallBatchPlan, subset bool) (resultErr error) {
	started := time.Now()
	if err := d.session.requireSmallBatch(plan); err != nil {
		return err
	}
	for _, entry := range plan.entries {
		if err := d.session.r.store.RetryReady(ctx, entry.original.OperationID); err != nil {
			return err
		}
	}
	defer func() {
		if resultErr == nil || deferredRetry(resultErr) {
			return
		}
		cause := resultErr
		for _, entry := range plan.entries {
			current, e := d.session.r.store.Operation(ctx, entry.original.OperationID)
			if e == nil && current.Stage != "CLIENT_ACKED" {
				resultErr = errors.Join(resultErr, d.session.r.store.RecordRetry(ctx, current.OperationID, cause))
			}
		}
	}()
	capability := d.legacyCapability
	var err error
	if plan.executionJob {
		capability = d.capability
		if capability == nil {
			capability, err = d.session.readSmallJobCapability(ctx)
		}
	} else if capability == nil {
		capability, err = d.session.readSmallBatchCapability(ctx)
	}
	if err != nil {
		return err
	}
	if !capability.admits(plan) {
		return ErrRemoteUnqualified
	}
	record, err := d.build(ctx, plan)
	if record.Phase == "GONE" && errors.Is(err, ErrArtifactRetained) {
		return d.disposeAcknowledged(ctx, record.Plan)
	}
	if err != nil {
		return err
	}
	if record.Phase == "GONE" {
		return d.disposeAcknowledged(ctx, record.Plan)
	}
	var outcomes []smallBatchItemOutcome
	originalFallback := false
	err = d.native.withAttemptState(ctx, plan.id, func(saved smallBatchRecord, input io.ReadSeeker, recovery bool) error {
		if saved.Plan.executionJob && capability.singleRequest && !recovery {
			var e error
			outcomes, e = d.session.sendSmallTransfer(ctx, saved.Plan, input, "execute")
			return e
		}
		command := "prepare"
		if recovery {
			command = "status"
		}
		var e error
		outcomes, e = d.session.smallBatchJSON(ctx, saved.Plan, command)
		var failure *guardedHTTPFailure
		prefix := "small-batches"
		if saved.Plan.executionJob {
			prefix = "small-jobs"
		}
		if recovery && errors.As(e, &failure) && failure.status == 404 && failure.code == "batch_missing" && failure.path == prefix+"/status" && failure.binding == d.session.binding && failure.transportPin == d.session.transportPin {
			for _, entry := range saved.Plan.entries {
				if entry.original.HTTPBinding != nil {
					// Missing packet metadata does not invalidate an independently
					// retained original UUID, including an already acknowledged
					// member. Never resubmit the aggregate with that member.
					originalFallback = true
					return nil
				}
			}
			if saved.Plan.executionJob && capability.singleRequest {
				outcomes, e = d.session.sendSmallTransfer(ctx, saved.Plan, input, "execute")
				return e
			}
			outcomes, e = d.session.smallBatchJSON(ctx, saved.Plan, "prepare")
		}
		if e != nil {
			return e
		}
		missing := 0
		for _, outcome := range outcomes {
			if outcome.state == "MISSING" {
				missing++
			}
		}
		jobPending, jobSafe := false, true
		if saved.Plan.executionJob {
			for _, outcome := range outcomes {
				switch outcome.state {
				case "MISSING", "PENDING":
					jobPending = true
				case "PUBLISHED":
				default:
					jobSafe = false
				}
			}
		}
		if missing == len(outcomes) || saved.Plan.executionJob && jobSafe && jobPending {
			outcomes, e = d.session.sendSmallBatch(ctx, saved.Plan, input)
		}
		return e
	})
	if err != nil {
		return err
	} // Unknown transport outcome retains the exact aggregate.
	if originalFallback {
		// The native attempt handle has closed. Cleanup verifies every pending
		// sealed original or full ACK receipt before retiring only the packet.
		if err = d.cleanup(ctx, plan.id); err != nil {
			return err
		}
		var pending error
		for _, entry := range plan.entries {
			pending = errors.Join(pending, d.recoverOriginal(ctx, entry.original))
		}
		return pending
	}
	if err = d.native.state.remote.point("small_batch.before_outcomes"); err != nil {
		return err
	}
	// The HTTP decoder validates the entire ordered outcome before any mutation.
	// Reload bindings as another recovery path may have learned an original UUID.
	record, err = d.native.state.read(ctx, plan.id)
	if err != nil {
		return err
	}
	if err = d.apply(ctx, record.Plan, outcomes); err != nil {
		return err
	}
	var publishedBytes, publishedCount int64
	for n, outcome := range outcomes {
		if outcome.status != nil && outcome.status.publication != nil && record.Plan.entries[n].original.Stage != "CLIENT_ACKED" {
			publishedBytes += record.Plan.entries[n].original.SizeBytes
			publishedCount++
		}
	}
	if publishedCount > 0 {
		recordPublications(publishedBytes, publishedCount, time.Since(started))
	}
	if err = d.native.state.remote.point("small_batch.after_outcomes"); err != nil {
		return err
	}
	var missing []Operation
	var pending error
	for n, outcome := range outcomes {
		op, e := d.session.r.store.Operation(ctx, record.Plan.entries[n].original.OperationID)
		if e != nil {
			return e
		}
		if op.Stage == "CLIENT_ACKED" {
			continue
		}
		if outcome.state == "MISSING" {
			missing = append(missing, op)
			continue
		}
		if outcome.status != nil && outcome.state == "PENDING" && !outcome.status.transferPending && (outcome.status.phase == "transport" || outcome.status.phase == "verified") {
			e = d.recoverOriginal(ctx, op)
		} else {
			e = ErrArtifactRetained
		}
		pending = errors.Join(pending, e)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if pending != nil && len(missing) == 0 {
		return pending
	}
	// No native reader remains. Cleanup first verifies every pending original
	// spool or full ACK receipt, then releases active group membership durably.
	if err = d.cleanup(ctx, plan.id); err != nil {
		return errors.Join(pending, err)
	}
	if err = d.disposeAcknowledged(ctx, record.Plan); err != nil && !errors.Is(err, ErrArtifactRetained) {
		return errors.Join(pending, err)
	}
	if len(missing) > 1 && subset && !plan.executionJob {
		id, e := NewOperationID()
		if e != nil {
			return errors.Join(pending, e)
		}
		next, e := newSmallBatchPlan(id, plan.rules, missing)
		if e == nil {
			e = d.group(ctx, next, false)
		}
		return errors.Join(pending, e)
	}
	// A singleton or a second partial response takes the existing original-ID
	// continuation. Repackaging is bounded to one additional group per invocation.
	for _, op := range missing {
		pending = errors.Join(pending, d.recoverOriginal(ctx, op))
	}
	return pending
}

func (d *smallBatchDispatcher) apply(ctx context.Context, plan *smallBatchPlan, outcomes []smallBatchItemOutcome) error {
	if len(outcomes) != len(plan.entries) {
		return ErrInvalidReceipt
	}
	// Validate current original identities and all known UUID associations first.
	for n, outcome := range outcomes {
		op := plan.entries[n].original
		if outcome.operationID != op.OperationID || outcome.sourceGeneration != op.LocalGeneration || outcome.sourceIdentity != fingerprint(op.Captured) || outcome.state == "MISSING" && op.HTTPBinding != nil {
			return ErrInvalidReceipt
		}
		if outcome.status != nil && (outcome.status.binding == nil || !validHTTPUploadBinding(op, *outcome.status.binding) || op.HTTPBinding != nil && *op.HTTPBinding != *outcome.status.binding) {
			return ErrInvalidReceipt
		}
	}
	if plan.executionJob {
		return d.applySmallJobOutcomes(ctx, plan, outcomes)
	}
	published := false
	for n, outcome := range outcomes {
		if outcome.status == nil {
			continue
		}
		status := outcome.status
		if _, err := d.session.r.BindHTTPUpload(ctx, plan.entries[n].original, status.binding.ServerUploadID, plan.entries[n].input.hash); err != nil {
			return err
		}
		published = published || status.publication != nil
	}
	if published {
		if err := d.session.Refresh(ctx); err != nil {
			return err
		}
	}
	for _, outcome := range outcomes {
		if outcome.status != nil && outcome.status.publication != nil {
			if err := d.session.r.AckCaptured(ctx, *outcome.status.publication); err != nil {
				return err
			}
			if err := d.session.r.store.ClearRetry(ctx, outcome.operationID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *smallBatchDispatcher) recoverOriginal(ctx context.Context, given Operation) error {
	started := time.Now()
	op, err := d.session.r.store.Operation(ctx, given.OperationID)
	if err != nil {
		return err
	}
	if op.Stage != "CLIENT_ACKED" {
		pub, e := d.session.Recover(ctx, op)
		if e != nil {
			return e
		}
		if pub == nil {
			return ErrArtifactRetained
		}
		if e = d.session.r.AckCaptured(ctx, *pub); e != nil {
			return e
		}
		RecordPublication(op.SizeBytes, time.Since(started))
		if e = d.session.r.store.ClearRetry(ctx, op.OperationID); e != nil {
			return e
		}
	}
	return d.dispose(ctx, op)
}

func (d *smallBatchDispatcher) disposeAcknowledged(ctx context.Context, plan *smallBatchPlan) error {
	var pending error
	for _, entry := range plan.entries {
		op, err := d.session.r.store.Operation(ctx, entry.original.OperationID)
		if err != nil {
			return err
		}
		if op.Stage != "CLIENT_ACKED" {
			pending = ErrArtifactRetained
			continue
		}
		if err = d.dispose(ctx, op); err != nil {
			return err
		}
	}
	return pending
}
