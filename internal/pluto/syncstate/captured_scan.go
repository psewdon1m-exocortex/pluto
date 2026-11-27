package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// AttemptSet is an ephemeral bounded-disk dispatch set. Claim is called by one
// enumeration owner. It is never B, a success receipt or crash-resume evidence.
type AttemptSet interface {
	ClaimAttempt(context.Context, string) (bool, error)
}
type CapturedScanOptions struct {
	Witness          SourceWitness
	RootID           string
	SourceIDs        []string
	Attempts         AttemptSet
	Capture          func(context.Context, SourceWitness, SourceEntry) (*VerifiedSnapshot, error)
	CaptureAndUse    func(context.Context, SourceWitness, SourceEntry, func(*VerifiedSnapshot) error) error
	Session          CapturedSession
	Now              func() time.Time
	OnPage           func(FrontierClaim) error
	AcquireRecovery  func(context.Context) (func(), error)
	AcquireStream    func(context.Context) (func(), error)
	DisposeRecovered func(context.Context, Operation) error
	SmallBatchMode   string // empty, or explicit qualification: bulk / changes
	SmallBatchBudget SmallBatchBudget
	Hooks            ScanHooks
	Targets          []DirtyHint // nil means a complete reconciliation; bounded hints retain originals.
}
type CapturedScanProblem struct {
	Ordinal             int64
	Destination, Reason string
}
type CapturedScanReport struct {
	Observed, Verified, Uploaded, Adopted, Recovered, Failed int64
	Complete                                                 bool
	Problems                                                 []CapturedScanProblem // first20 by deterministic dispatch ordinal
	SourceGap                                                *CapturedSourceGap    `json:",omitempty"`
	CompletedHints                                           []DirtyHint           `json:"-"`
}
type capturedJob struct {
	work    VerificationWork
	ordinal int64
}

// RunCapturedScan composes real streaming source observation and two bounded
// workers, queue2, indexed verification pages128. Ordinary Linux contents are
// guarded-rehashed each cycle; remote comparison uses imported R, never per-file
// HEAD. Nothing here starts a daemon, changes config or grants server authority.
func (r *RemoteImport) RunCapturedScan(ctx context.Context, o CapturedScanOptions) (report CapturedScanReport, finalErr error) {
	if o.Attempts == nil || (o.Capture == nil) == (o.CaptureAndUse == nil) || o.Session == nil || len(o.SourceIDs) < 1 || len(o.SourceIDs) > MaxSources {
		return report, ErrIdentityConflict
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	// Exact complete configured source-set, including duplicates/overlap, is
	// validated before scanning or a network side effect. No silent subset.
	r.sources.mu.Lock()
	tx, err := r.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err == nil {
		set, e := r.sources.checkWitness(ctx, tx, o.Witness)
		err = e
		if err == nil && set.AttachedRootID != o.RootID {
			err = ErrIdentityConflict
		}
		var count int
		if err == nil {
			err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM source_bindings WHERE set_id=? AND active=1", o.Witness.SetID).Scan(&count)
			if err == nil && count != len(o.SourceIDs) {
				err = ErrIdentityConflict
			}
		}
		seen := make(map[string]bool, MaxSources)
		for _, id := range o.SourceIDs {
			if err != nil {
				break
			}
			if seen[id] {
				err = ErrIdentityConflict
				break
			}
			seen[id] = true
			var n int
			err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM source_bindings WHERE set_id=? AND source_id=? AND active=1 AND revision=?)", o.Witness.SetID, id, o.Witness.Revision).Scan(&n)
			if err == nil && n != 1 {
				err = ErrIdentityConflict
			}
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback()
		}
	}
	r.sources.mu.Unlock()
	if err != nil {
		return report, err
	}
	batch, err := r.prepareSmallBatchScan(ctx, o)
	if batch != nil {
		report.Recovered = batch.recoveredCount
	}
	if err != nil {
		return report, err
	}
	if batch != nil && batch.queue != nil {
		o.Session = batch.session
	}
	// Recovery does not require an active source path. Removed/excluded sources
	// retain their original operation IDs and can still receive historical ACKs.
	// A full scan needs the same original recovery as an indexed/targeted
	// scan. In particular, a retained stream cannot enter executeCaptured's
	// ordinary PUT recovery, and a deleted source will never be enumerated.
	if o.Targets != nil || o.Hooks.Before != nil || httpSession(o.Session) != nil {
		if n, e := r.RecoverOriginals(ctx, o); e != nil {
			return report, e
		} else {
			report.Recovered += n
		}
	}
	jobs := make(chan capturedJob, 2)
	workerContext, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
	var wg, tasks sync.WaitGroup
	var mu sync.Mutex
	var firstFailure error
	var sourceGap atomic.Bool
	stopOnChangedWitness := func() bool {
		if sourceGap.Load() {
			return true
		}
		if ctx.Err() == nil && !r.sources.sourceWitnessCurrent(ctx, o.Witness) {
			sourceGap.Store(true)
			stopWorkers()
			return true
		}
		return false
	}
	problem := func(ordinal int64, path string, e error) {
		if errors.Is(e, ErrStaleGeneration) {
			stopOnChangedWitness()
		}
		mu.Lock()
		defer mu.Unlock()
		report.Failed++
		if firstFailure == nil {
			firstFailure = e
		}
		p := CapturedScanProblem{ordinal, path, e.Error()}
		report.Problems = append(report.Problems, p)
		sort.Slice(report.Problems, func(i, j int) bool { return report.Problems[i].Ordinal < report.Problems[j].Ordinal })
		if len(report.Problems) > 20 {
			report.Problems = report.Problems[:20]
		}
	}
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				func() {
					ctx := workerContext
					defer tasks.Done()
					work := job.work
					path := work.Entry.Destination
					if e := ctx.Err(); e != nil {
						problem(job.ordinal, path, e)
						return
					}
					entry, e := r.ProjectSourcePath(ctx, o.Witness, o.RootID, work.Entry)
					if e != nil {
						problem(job.ordinal, path, e)
						return
					}
					if batch != nil && batch.wasRecovered(entry) {
						return
					}
					// Recover an immutable prior attempt before capturing a replacement file.
					d, e := r.DecideCaptured(ctx, o.Witness, o.RootID, entry, nil, nil, o.Now())
					if e != nil {
						problem(job.ordinal, path, e)
						return
					}
					if d.Kind == "RECOVER" {
						original, lookup := r.store.Operation(ctx, d.OperationID)
						if lookup != nil {
							problem(job.ordinal, path, lookup)
							return
						}
						if original.Stream != nil {
							transport := httpSession(o.Session)
							if transport == nil {
								problem(job.ordinal, path, ErrRemoteUnqualified)
								return
							}
							// A deferred historical stream still has its own transport,
							// retry deadline and data/source admission. It cannot enter
							// catalog recovery with a nil captured artifact.
							if e = transport.StreamOriginal(ctx, original, o.AcquireStream); e != nil {
								problem(job.ordinal, path, e)
							} else {
								mu.Lock()
								report.Recovered++
								mu.Unlock()
							}
							return
						}
						release := func() {}
						if o.AcquireRecovery != nil {
							release, e = o.AcquireRecovery(ctx)
							if e != nil {
								problem(job.ordinal, path, e)
								return
							}
						}
						out, e := r.executeCaptured(ctx, o.Witness, o.RootID, entry, nil, o.Session, o.Now(), o.DisposeRecovered)
						release()
						if e != nil {
							problem(job.ordinal, path, e)
						} else {
							mu.Lock()
							if out.Recovered {
								report.Recovered++
							}
							mu.Unlock()
						}
						return
					}
					if parents, ok := o.Session.(interface {
						PrepareParents(context.Context, SourceWitness, string, string) error
					}); ok {
						if e = parents.PrepareParents(ctx, o.Witness, o.RootID, entry); e != nil {
							problem(job.ordinal, path, e)
							return
						}
					}
					if batch != nil {
						release, e := batch.beginCapture(ctx, work.Entry.SizeBytes)
						if e != nil {
							problem(job.ordinal, path, e)
							return
						}
						defer release()
					}
					if transport := httpSession(o.Session); transport != nil && o.AcquireStream != nil {
						handled, uploaded, streamErr := transport.tryStream(ctx, o.Witness, work.Entry, entry, o.AcquireStream)
						if streamErr != nil {
							problem(job.ordinal, path, streamErr)
							return
						}
						if handled {
							mu.Lock()
							report.Verified++
							if uploaded {
								report.Uploaded++
							} else {
								report.Adopted++
							}
							mu.Unlock()
							return
						}
					}
					var v *VerifiedSnapshot
					queued := ""
					reported := false
					apply := func(value *VerifiedSnapshot) error {
						v = value
						if e = r.sources.RecordVerifiedSnapshot(ctx, o.Witness, v); e != nil {
							cleanup := v.Close()
							if errors.Is(cleanup, ErrArtifactRetained) {
								cleanup = v.Retain()
							}
							problem(job.ordinal, path, errors.Join(e, cleanup))
							reported = true
							return e
						}
						mu.Lock()
						report.Verified++
						mu.Unlock()
						if e = r.ProjectCapturedEntry(ctx, o.Witness, o.RootID, entry, v); e != nil {
							cleanup := v.Close()
							if errors.Is(cleanup, ErrArtifactRetained) {
								cleanup = v.Retain()
							}
							problem(job.ordinal, path, errors.Join(e, cleanup))
							reported = true
							return e
						}
						out, e := r.ExecuteCaptured(ctx, o.Witness, o.RootID, entry, v, o.Session, o.Now())
						if out.Queued {
							queued = out.OperationID
						}
						if e != nil {
							problem(job.ordinal, path, e)
							reported = true
						} else {
							mu.Lock()
							if out.Uploaded {
								report.Uploaded++
							}
							if out.Kind == "NOOP_CAPTURED" || out.Kind == "ADOPT_EQUAL" {
								report.Adopted++
							}
							if out.Recovered {
								report.Recovered++
							}
							mu.Unlock()
						}
						return e
					}
					if o.CaptureAndUse != nil {
						e = o.CaptureAndUse(ctx, o.Witness, work.Entry, apply)
					} else {
						v, e = o.Capture(ctx, o.Witness, work.Entry)
						if e == nil {
							e = WithValidatedCapture(ctx, v, func() error { return apply(v) })
						}
					}
					// Scope admission/cleanup errors are outside inner per-entry effects.
					if e != nil {
						var cleanup error
						if v != nil {
							cleanup = v.Close()
							if errors.Is(cleanup, ErrArtifactRetained) {
								cleanup = v.Retain()
							}
						}
						// The closure records its own deterministic error; admission has not.
						if !reported {
							problem(job.ordinal, path, errors.Join(e, cleanup))
						}
					} else if queued != "" {
						// No source FD, private validation scope or capture data slot
						// remains while waiting for packet admission/backpressure.
						op, readErr := r.store.Operation(ctx, queued)
						if readErr != nil {
							problem(job.ordinal, path, readErr)
							return
						}
						id, order, destination := queued, job.ordinal, path
						complete := func(sendErr error) {
							current, lookup := r.store.Operation(ctx, id)
							if lookup == nil && current.Stage == "CLIENT_ACKED" {
								mu.Lock()
								report.Uploaded++
								mu.Unlock()
								return
							}
							problem(order, destination, errors.Join(sendErr, lookup, ErrArtifactRetained))
						}
						if e = batch.queue.enqueue(ctx, op, batch.rules, complete); e != nil {
							problem(order, destination, e)
						}
					}
				}()
			}
		}()
	}
	defer func() {
		close(jobs)
		wg.Wait()
		if batch != nil && batch.queue != nil {
			if e := batch.queue.close(); e != nil {
				report.Complete = false
				finalErr = errors.Join(finalErr, e)
			}
		}
		if report.Failed > 0 {
			finalErr = errors.Join(finalErr, firstFailure, fmt.Errorf("captured scan has %d failed/reconciliation items", report.Failed))
		}
	}()
	ordinal := int64(0)
	if session := httpSession(o.Session); session != nil && (o.Hooks.Before != nil || o.Targets != nil) {
		o.Hooks.Directory = func(ctx context.Context, path string) error {
			entry, e := r.sources.SourceEntry(ctx, o.Witness.SetID, path)
			var id string
			if e == nil {
				id, e = r.ProjectSourcePath(ctx, o.Witness, o.RootID, entry)
			}
			if e == nil {
				e = session.PrepareParents(ctx, o.Witness, o.RootID, id)
			}
			if e != nil {
				ordinal++
				problem(ordinal, path, e)
			}
			return nil
		}
	}
	after := ""
	currentScans := make(map[string]bool, len(o.SourceIDs)) // <=128 configured sources
	drain := func(scanID string, historical bool) error {
		for {
			var page []VerificationWork
			var e error
			if historical {
				page, e = r.sources.VerificationPage(ctx, o.Witness, after, MaxSourcePage)
			} else {
				page, e = r.sources.VerificationPageForScan(ctx, o.Witness, scanID, after, MaxSourcePage)
			}
			if e != nil {
				return e
			}
			if len(page) == 0 {
				return nil
			}
			for _, work := range page {
				after = work.Entry.Destination
				if o.Hooks.Include != nil && !o.Hooks.Include(after) {
					continue
				}
				if historical {
					seen, e := r.sources.seenInCurrentScans(ctx, o.Witness, after, currentScans)
					if e != nil {
						return e
					}
					if !seen {
						admitted, e := o.Attempts.ClaimAttempt(ctx, after)
						if e != nil {
							return e
						}
						if !admitted {
							continue
						}
						ordinal++
						problem(ordinal, after, ErrSourceIncomplete)
						continue // Retain UNKNOWN old work/B/intents; no capture or deletion.
					}
				}
				admitted, e := o.Attempts.ClaimAttempt(ctx, after)
				if e != nil {
					return e
				}
				if !admitted {
					continue
				}
				if ordinal == math.MaxInt64 {
					return ErrSourceQuota
				}
				ordinal++
				mu.Lock()
				report.Observed++
				mu.Unlock()
				tasks.Add(1)
				select {
				case jobs <- capturedJob{work, ordinal}:
				case <-ctx.Done():
					tasks.Done()
					return ctx.Err()
				}
			}
		}
	}
	complete := true

	workSources := o.SourceIDs
	if o.Targets != nil {
		workSources = make([]string, len(o.Targets))
		for i, h := range o.Targets {
			workSources[i] = h.SourceID
		}
	}
sourceLoop:
	for targetIndex, id := range workSources {
		mu.Lock()
		failuresBefore := report.Failed
		mu.Unlock()
		if o.Hooks.Include != nil {
			b, e := r.sources.Binding(ctx, o.Witness.SetID, id)
			if e != nil {
				return report, e
			}
			if !o.Hooks.Include(b.Destination) {
				continue
			}
		}
		if sourceGap.Load() {
			complete = false
			break
		}
		if err = ctx.Err(); err != nil {
			finalErr = err
			complete = false
			break
		}
		scanID, e := NewOperationID()
		if e != nil {
			finalErr = e
			complete = false
			break
		}
		if o.Targets != nil {
			_, e = r.sources.BeginTargetScan(ctx, o.Witness, o.Targets[targetIndex], scanID)
		} else {
			var existing Scan
			existing, e = r.sources.RetryScan(ctx, o.Witness, id)
			if e == nil {
				scanID = existing.ID
			} else if errors.Is(e, sql.ErrNoRows) {
				_, e = r.sources.BeginScan(ctx, o.Witness, id, scanID)
			}
		}
		if e != nil {
			ordinal++
			problem(ordinal, id, e)
			complete = false
			if stopOnChangedWitness() {
				break sourceLoop
			}
			continue
		}
		currentScans[scanID] = true
		after = ""
		for {
			claim, e := r.sources.ClaimScanFrontier(ctx, o.Witness, scanID)
			if errors.Is(e, sql.ErrNoRows) {
				break
			}
			if e != nil {
				ordinal++
				problem(ordinal, id, e)
				complete = false
				if stopOnChangedWitness() {
					break sourceLoop
				}
				break
			}
			e = r.sources.ScanClaimWithHooks(ctx, claim, func(c FrontierClaim) error {
				if e := drain(scanID, false); e != nil {
					return e
				}
				if o.OnPage != nil {
					return o.OnPage(c)
				}
				return nil
			}, o.Hooks)
			if e != nil {
				ordinal++
				problem(ordinal, claim.Destination, e)
				complete = false
				if stopOnChangedWitness() {
					// A mid-scan gap invalidates queued work. Do not silently
					// adopt a new witness or run stale-witness final sweeps.
					break sourceLoop
				}
				break
			}
		}
		// Unsorted directory pages can admit keys below the previous page key.
		// Sweep this exact scan before joining and observing overlapping sources.
		after = ""
		if e = drain(scanID, false); e != nil {
			finalErr = errors.Join(finalErr, e)
			complete = false
			if stopOnChangedWitness() {
				break sourceLoop
			}
		}
		// Join this source's work before observing an overlapping later source.
		// Otherwise that observation would invalidate a queued capture request.
		tasks.Wait()
		if batch != nil && batch.queue != nil {
			if e := batch.queue.flush(ctx); e != nil {
				finalErr = errors.Join(finalErr, e)
				complete = false
			}
		}
		if e = r.sources.CompleteScanScope(ctx, o.Witness, scanID); e != nil {
			ordinal++
			problem(ordinal, id, e)
			complete = false
			if stopOnChangedWitness() {
				break sourceLoop
			}
		}
		mu.Lock()
		if o.Targets != nil && report.Failed == failuresBefore {
			report.CompletedHints = append(report.CompletedHints, o.Targets[targetIndex])
		}
		mu.Unlock()
	}
	// ReadDir is unsorted. One final keyset sweep catches entries admitted before
	// the previous lexical key; the disk set prevents repeats without an N map.
	after = ""
	if !sourceGap.Load() && o.Targets == nil {
		if err = drain("", true); err != nil {
			finalErr = errors.Join(finalErr, err)
			complete = false
			stopOnChangedWitness()
		}
	}
	// Verified captures can consume source work before prepare/ACK. Join all
	// effects, then report unseen original pending outcomes; preserve their
	// bytes/history without inventing source absence or a replacement intent.
	tasks.Wait()
	if batch != nil && batch.queue != nil {
		if e := batch.queue.flush(ctx); e != nil {
			finalErr = errors.Join(finalErr, e)
			complete = false
		}
	}
	pendingAfter := ""
	retainedPending := false
	for {
		page, e := r.store.PendingPage(ctx, o.RootID, pendingAfter, MaxSourcePage)
		if e != nil {
			finalErr = errors.Join(finalErr, e)
			complete = false
			break
		}
		if len(page) == 0 {
			break
		}
		retainedPending = true
		complete = false // A folder/other pending destination cannot be scoped success.
		for _, op := range page {
			pendingAfter = op.OperationID
			if waitErr := r.store.RetryReady(ctx, op.OperationID); waitErr != nil {
				finalErr = errors.Join(finalErr, waitErr)
			}
			if sourceGap.Load() {
				continue // Historical outcomes remain retained without stale source reads.
			}
			if op.Captured == nil || op.Captured.Evidence.SetID != o.Witness.SetID {
				continue
			}
			path := op.Captured.Evidence.Destination
			seen, e := r.sources.seenInCurrentScans(ctx, o.Witness, path, currentScans)
			if e != nil {
				finalErr = errors.Join(finalErr, e)
				complete = false
				stopOnChangedWitness()
				continue
			}
			if seen {
				continue
			}
			admitted, e := o.Attempts.ClaimAttempt(ctx, path)
			if e != nil {
				finalErr = errors.Join(finalErr, e)
				complete = false
				continue
			}
			if admitted {
				ordinal++
				problem(ordinal, path, ErrSourceIncomplete)
			}
		}
	}
	if retainedPending {
		finalErr = errors.Join(finalErr, ErrArtifactRetained)
	}
	if sourceGap.Load() {
		complete = false
		observed := r.sources.sourceGapDiagnostic(ctx, o.Witness)
		report.SourceGap = &observed
	}
	report.Complete = complete
	return
}
