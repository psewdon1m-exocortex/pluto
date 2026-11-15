package syncstate

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Empty mode preserves ordinary individual transport. Nonempty modes are an
// explicit local qualification request, not automatic economic activation.
type smallBatchScanEngine struct {
	dispatcher       *smallBatchDispatcher
	shared           *budgetedSmallBatchArtifacts
	session          *smallBatchCaptureSession
	queue            *smallBatchQueue
	capability       *smallBatchCapability
	legacyCapability *smallBatchCapability
	limits           smallBatchQueueLimits
	rules            string
	capture          sync.RWMutex
	retirement       sync.Mutex
	mu               sync.Mutex
	recovered        map[string]bool
	recoveredCount   int64
}
type smallBatchCaptureSession struct {
	*IsolatedHTTPSession
	engine *smallBatchScanEngine
}

func (r *RemoteImport) prepareSmallBatchScan(ctx context.Context, o CapturedScanOptions) (*smallBatchScanEngine, error) {
	if o.SmallBatchMode != "" && o.SmallBatchMode != "bulk" && o.SmallBatchMode != "changes" {
		return nil, ErrIdentityConflict
	}
	var version int
	if err := r.store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if o.SmallBatchMode == "" {
		if version != smallBatchSchemaVersion && version != daemonSchemaVersion {
			return nil, nil
		}
		var pending bool
		if err := r.store.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM small_batch_groups WHERE root_id=? AND phase<>'GONE')", o.RootID).Scan(&pending); err != nil {
			return nil, err
		}
		if !pending {
			return nil, nil
		}
	}
	s, ok := o.Session.(*IsolatedHTTPSession)
	if !ok || s.r != r || s.root != o.RootID || o.AcquireRecovery == nil || o.DisposeRecovered == nil || o.SmallBatchBudget == nil {
		return nil, ErrRemoteUnqualified
	}
	var capability *smallBatchCapability
	var legacy *smallBatchCapability
	var err error
	if o.SmallBatchMode != "" {
		capability, err = s.readSmallBatchCapability(ctx)
	}
	if err != nil {
		var failure *guardedHTTPFailure
		unavailable := errors.As(err, &failure) && failure.status == 404 && failure.path == "small-batches/capabilities" && failure.binding == s.binding && failure.transportPin == s.transportPin
		if !unavailable {
			return nil, err
		}
		capability = nil
	}
	legacy = capability
	if o.SmallBatchMode != "" {
		job, e := s.readSmallJobCapability(ctx)
		if e != nil {
			return nil, e
		}
		if job != nil {
			capability = job
			transportResources.qualifyPipeline(job.jobs)
		}
	}
	if (capability == nil || capability.items < 2) && version != smallBatchSchemaVersion && version != daemonSchemaVersion {
		return nil, nil
	}
	state, err := r.enableSmallBatches(ctx)
	if err != nil {
		return nil, err
	}
	native, err := state.enableArtifacts(ctx)
	if err != nil {
		return nil, err
	}
	shared, err := newBudgetedSmallBatchArtifacts(ctx, native, o.SmallBatchBudget)
	if err != nil {
		return nil, err
	}
	dispatcher, err := newSmallBatchDispatcher(native, s, o.AcquireRecovery)
	if err != nil {
		return nil, err
	}
	dispatcher.shared = shared
	dispatcher.dispose = o.DisposeRecovered
	dispatcher.capability, dispatcher.legacyCapability = capability, legacy
	engine := &smallBatchScanEngine{dispatcher: dispatcher, shared: shared, capability: capability, legacyCapability: legacy, recovered: map[string]bool{}}
	engine.session = &smallBatchCaptureSession{s, engine}
	if err = engine.resume(ctx, o.Witness.SetID); err != nil {
		return engine, err
	}
	if capability == nil || capability.items < 2 {
		return engine, nil
	}
	set, err := r.sources.Set(ctx, o.Witness.SetID)
	if err != nil {
		return engine, err
	}
	engine.rules = "pluto-" + fingerprint(struct {
		Digest   string
		Revision int64
	}{set.ConfigDigest, set.Revision})
	charge, err := r.store.artifacts.Charge(ctx)
	if err != nil {
		return engine, err
	}
	// Two active originals+aggregates, two queued original groups, one current
	// original group, and two maximum captures all share the same disk quota.
	available := r.store.artifacts.limits.PlaintextBytes - charge - 2*smallBatchMaximumFileBytes
	if available < 7 {
		return engine, nil
	}
	engine.limits = smallBatchQueueLimits{capability.items, min(capability.dataBytes, available/7), capability.metadataBytes}
	age := 250 * time.Millisecond
	if o.SmallBatchMode == "bulk" {
		age = time.Second
	}
	engine.queue, err = newSmallBatchQueue(ctx, engine.limits, age, func(ctx context.Context, plan *smallBatchPlan) error {
		if capability.executionJob {
			if job, e := plan.asExecutionJob(); e == nil && capability.admits(job) {
				plan = job
			}
		}
		if len(plan.entries) > 1 || plan.executionJob {
			err := dispatcher.dispatch(ctx, plan)
			// Each joined packet retires a bounded page of physical-absence
			// proven references; a long scan cannot fill the 64-row ledger.
			engine.retirement.Lock()
			_, cleanup := native.compact(ctx, 16)
			engine.retirement.Unlock()
			return errors.Join(err, cleanup)
		}
		release, e := o.AcquireRecovery(ctx)
		if e != nil {
			return e
		}
		defer release()
		return dispatcher.recoverOriginal(ctx, plan.entries[0].original)
	}, capability)
	return engine, err
}

func (b *smallBatchScanEngine) resume(ctx context.Context, set string) error {
	r := b.dispatcher.session.r
	rows, err := r.store.db.QueryContext(ctx, "SELECT batch_id FROM small_batch_groups WHERE root_id=? AND phase<>'GONE' ORDER BY batch_id LIMIT 5", b.dispatcher.session.root)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if len(ids) > 4 {
		return ErrSourceQuota
	}
	for _, id := range ids {
		record, e := b.shared.native.state.read(ctx, id)
		if e != nil {
			return e
		}
		if e = b.dispatcher.session.requireSmallBatch(record.Plan); e != nil {
			return e
		}
		// Before a network attempt (or without the optional capability), the
		// verified originals remain a complete individual recovery fallback.
		retire := record.Phase == "RESERVED" || record.Phase == "BUILDING" || record.Phase == "DISPOSING" || b.capability == nil || !b.capability.admits(record.Plan)
		if retire {
			if e = b.shared.cleanup(ctx, id); e != nil {
				return e
			}
			if e = b.dispatcher.disposeAcknowledged(ctx, record.Plan); e != nil && !errors.Is(e, ErrArtifactRetained) {
				return e
			}
			continue
		}
		e = b.dispatcher.dispatch(ctx, record.Plan)
		for _, entry := range record.Plan.entries {
			if entry.original.Stage == "CLIENT_ACKED" || entry.original.Captured.Evidence.SetID != set {
				continue
			}
			current, readErr := r.store.Operation(ctx, entry.original.OperationID)
			if readErr != nil {
				return errors.Join(e, readErr)
			}
			if current.Stage == "CLIENT_ACKED" && !b.recovered[current.EntryID] {
				b.recovered[current.EntryID] = true
				b.recoveredCount++
			}
		}
		if e != nil && !errors.Is(e, ErrArtifactRetained) && !deferredRetry(e) {
			return e
		}
	}
	for range 4 {
		n, e := b.shared.native.compact(ctx, 16)
		if e != nil {
			return e
		}
		if n < 16 {
			break
		}
	}
	return nil
}

func (b *smallBatchScanEngine) wasRecovered(entry string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.recovered[entry] {
		delete(b.recovered, entry)
		return true
	}
	return false
}
func (b *smallBatchScanEngine) beginCapture(ctx context.Context, size int64) (func(), error) {
	if b.queue == nil {
		return func() {}, nil
	}
	if size <= b.capability.fileBytes && size <= b.limits.data {
		b.capture.RLock()
		if err := ctx.Err(); err != nil {
			b.capture.RUnlock()
			return nil, err
		}
		return b.capture.RUnlock, nil
	}
	// Large/ineligible captures wait without an open source or a data slot.
	b.capture.Lock()
	if err := b.queue.flush(ctx); err != nil {
		b.capture.Unlock()
		return nil, err
	}
	return b.capture.Unlock, nil
}
func (s *smallBatchCaptureSession) deferCaptured(op Operation) bool {
	if op.Mutation != nil || op.Stream != nil {
		return false
	}
	b := s.engine
	if op.SizeBytes > b.limits.data || op.SizeBytes > b.capability.fileBytes {
		return false
	}
	plan, err := newSmallBatchPlan("queue-candidate", b.rules, []Operation{op})
	if err != nil {
		return false
	}
	capability := b.capability
	if capability.executionJob {
		if job, e := plan.asExecutionJob(); e == nil {
			plan = job
		} else {
			capability = b.legacyCapability
		}
	}
	if !capability.admits(plan) {
		return false
	}
	raw, err := plan.prepareBytes()
	retained, marshalErr := json.Marshal(op)
	return err == nil && marshalErr == nil && int64(len(raw)+128) <= b.limits.metadata && int64(len(retained)) <= b.limits.metadata
}

func httpSession(session CapturedSession) *IsolatedHTTPSession {
	switch s := session.(type) {
	case *IsolatedHTTPSession:
		return s
	case *smallBatchCaptureSession:
		return s.IsolatedHTTPSession
	}
	return nil
}
