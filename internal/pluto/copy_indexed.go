package pluto

import (
	"context"
	"database/sql"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"

	"pluto/internal/pluto/syncstate"
)

type indexedAttempts struct{ state *copyEnumerationState }

func (s indexedAttempts) ClaimAttempt(ctx context.Context, key string) (bool, error) {
	exists, err := s.state.hasCompleted(ctx, key)
	if err != nil || exists {
		return false, err
	}
	if err = s.state.markCompleted(ctx, key); err != nil {
		return false, err
	}
	return true, nil
}

// CopyIndexed is shared by the explicit isolated CLI and activated daemon.
// Its session cannot mint authority from public READY/feed shapes. It reuses
// the actual global2data/1source-reader/256MiB plaintext budgets and the existing
// private1GiB metadata disk cap plus rollback journal/disk-reserve admission.
func CopyIndexed(ctx context.Context, r *syncstate.RemoteImport, admission *ArtifactAdmission, o syncstate.CapturedScanOptions) (report syncstate.CapturedScanReport, err error) {
	if r == nil || admission == nil || admission.registry == nil || admission.budget != copyResources || o.Capture != nil || o.CaptureAndUse != nil || o.Attempts != nil || o.SmallBatchBudget != nil {
		return report, syncstate.ErrIdentityConflict
	}
	spool := filepath.Join(filepath.Dir(admission.registry.Directory()), "spool")
	// Create only the exact admitted profile's child, before resource admission
	// expects that directory. No recursive creation or path-following profile.
	profile := filepath.Dir(spool)
	fd, e := unix.Open(profile, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return report, e
	}
	parent := os.NewFile(uintptr(fd), profile)
	info, e := parent.Stat()
	copyResources.mu.Lock()
	same := e == nil && copyResources.artifactOwner == admission.owner && os.SameFile(info, copyResources.artifactProfile)
	copyResources.mu.Unlock()
	if !same {
		parent.Close()
		return report, errors.Join(syncstate.ErrIdentityConflict, e)
	}
	e = unix.Mkdirat(fd, "spool", 0700)
	parent.Close()
	if e != nil && !errors.Is(e, unix.EEXIST) {
		return report, e
	}
	if err = copyResources.acquireEnumeration(ctx, spool, copyMetadataDatabaseBytes); err != nil {
		return report, err
	}
	defer copyResources.releaseEnumeration()
	state, err := newCopyEnumerationState(ctx, spool, copyMetadataDatabaseBytes)
	if err != nil {
		return report, err
	}
	defer func() {
		cleanup := state.close()
		if cleanup != nil {
			copyResources.blockSpool(cleanup)
		}
		err = errors.Join(err, cleanup)
	}()
	o.Attempts = indexedAttempts{state}
	o.CaptureAndUse = func(ctx context.Context, w syncstate.SourceWitness, e syncstate.SourceEntry, use func(*syncstate.VerifiedSnapshot) error) error {
		if _, err := admission.registry.PruneDisposed(ctx, syncstate.MaxSourcePage); err != nil {
			return err
		}
		return admission.CaptureAndUse(ctx, w, e, use)
	}
	if o.AcquireRecovery != nil || o.DisposeRecovered != nil || o.AcquireStream != nil {
		return report, syncstate.ErrIdentityConflict
	}
	o.AcquireStream = func(ctx context.Context) (func(), error) {
		if err := copyResources.acquireWorker(ctx); err != nil {
			return nil, err
		}
		const bytes = 2 * (syncstate.StreamChunkBytes + syncstate.HTTPMetadataBytes + 4)
		if err := copyResources.reserveSpool(ctx, admission.registry.Directory(), bytes); err != nil {
			copyResources.releaseWorker()
			return nil, err
		}
		if err := copyResources.acquireReader(ctx); err != nil {
			copyResources.releaseSpool(bytes)
			copyResources.releaseWorker()
			return nil, err
		}
		return func() {
			copyResources.releaseReader()
			copyResources.releaseSpool(bytes)
			copyResources.releaseWorker()
		}, nil
	}
	o.AcquireRecovery = func(ctx context.Context) (func(), error) {
		if err := copyResources.acquireWorker(ctx); err != nil {
			return nil, err
		}
		return copyResources.releaseWorker, nil
	}
	o.DisposeRecovered = func(ctx context.Context, op syncstate.Operation) error {
		record, err := admission.registry.Record(ctx, op.SnapshotID)
		if errors.Is(err, sql.ErrNoRows) {
			// A previous original recovery already released the retained budget.
			// Prove full durable ACK and native absence; never release it twice.
			return admission.registry.ConfirmDisposedOriginal(ctx, op)
		}
		if err != nil {
			return err
		}
		if record.Phase == syncstate.ArtifactGone {
			return nil
		}
		if err = admission.registry.Dispose(ctx, op.SnapshotID); err != nil {
			return err
		}
		if err = copyResources.releaseRetained(admission.owner, record.ExpectedBytes); err != nil {
			copyResources.blockSpool(err)
		}
		return err
	}
	// Also permits retiring persisted aggregates before individual recovery when
	// the operator disables the optional transport on a v7 profile.
	o.SmallBatchBudget = admission.smallBatchBudget()
	return r.RunCapturedScan(ctx, o)
}
