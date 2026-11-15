package pluto

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"pluto/internal/pluto/syncstate"
)

// ArtifactAdmission is deliberately not connected to Serve/Copy. Future active
// startup must call it before legacy cleanup or any work in this profile.
type ArtifactAdmission struct {
	registry *syncstate.Artifacts
	owner    string
	budget   *copyBudget
}

// Detach only after all callbacks joined and the state writer closed. Retained
// bytes remain charged; only a bootstrap of this same profile may resume work.
func (a *ArtifactAdmission) Detach() error {
	b := a.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.artifactOwner != a.owner || b.spoolBytes != 0 || b.liveArtifactBytes != 0 || len(b.workers) != 0 || len(b.readers) != 0 || len(b.enumerators) != 0 {
		return syncstate.ErrArtifactInUse
	}
	b.artifactDetached = true
	b.artifactBootstrap = true
	return nil
}

func BootstrapArtifactAdmission(ctx context.Context, store *syncstate.Store, limits syncstate.ArtifactLimits) (*ArtifactAdmission, syncstate.ArtifactReport, error) {
	registry, err := store.EnableArtifacts(ctx, limits)
	if err != nil {
		return nil, syncstate.ArtifactReport{}, err
	}
	admission := &ArtifactAdmission{registry: registry, owner: registry.Scope(), budget: copyResources}
	legacySpool := filepath.Join(filepath.Dir(registry.Directory()), "spool")
	if err = admission.budget.installArtifactScope(admission.owner, registry.ProfileScope(), 0, registry.Directory(), legacySpool); err != nil {
		return nil, syncstate.ArtifactReport{}, err
	}
	// A crash before Seal can leave owned temporary bytes without any immutable
	// operation. Retire only those exact unsubmitted captures; submitted and
	// sealed originals still require their ordinary recovery proofs.
	if err = registry.RecoverAbandonedCaptures(ctx); err != nil {
		admission.budget.blockSpool(err)
		return nil, syncstate.ArtifactReport{}, err
	}
	// Reservation-before-Create and empty creation gaps use the separate,
	// evidence-preserving empty-inode recovery.
	if err = registry.RecoverEmptyReservations(ctx); err != nil {
		admission.budget.blockSpool(err)
		return nil, syncstate.ArtifactReport{}, err
	}
	report, err := registry.Reconcile(ctx, admission.reader)
	if err == nil {
		err = inspectLegacySpool(ctx, legacySpool, &report)
	}
	if err != nil {
		admission.budget.blockSpool(errors.Join(syncstate.ErrArtifactUnreconciled, err))
		return nil, report, err
	}
	if err = admission.budget.completeArtifactBootstrap(admission.owner, report.ReservedBytes); err != nil {
		admission.budget.blockSpool(err)
		return nil, report, err
	}
	return admission, report, nil
}
func inspectLegacySpool(ctx context.Context, filename string, report *syncstate.ArtifactReport) error {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return syncstate.ErrIdentityConflict
	}
	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), filename)
	defer dir.Close()
	opened, err := dir.Stat()
	st, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !os.SameFile(info, opened) || !ok || st.Uid != uint32(os.Geteuid()) {
		return errors.Join(syncstate.ErrIdentityConflict, err)
	}
	entries, err := dir.ReadDir(128)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(entries) > 0 {
		report.Admitted = false
		report.Complete = false
		report.Problems = append(report.Problems, "legacy spool contains unregistered retained objects; preserve and reconcile before work")
		return syncstate.ErrArtifactUnreconciled
	}
	return nil
}
func (a *ArtifactAdmission) reader(ctx context.Context) (func(), error) {
	if err := a.budget.acquireReader(ctx); err != nil {
		return nil, err
	}
	return a.budget.releaseReader, nil
}
func (a *ArtifactAdmission) Registry() *syncstate.Artifacts { return a.registry }
func (a *ArtifactAdmission) Capture(ctx context.Context, w syncstate.SourceWitness, entry syncstate.SourceEntry) (*syncstate.VerifiedSnapshot, error) {
	if a == nil || a.registry == nil {
		return nil, syncstate.ErrIdentityConflict
	}
	return syncstate.CaptureGuarded(ctx, w, entry, a.registry.Directory(), &registryCaptureBudget{admission: a})
}

func (a *ArtifactAdmission) CaptureAndUse(ctx context.Context, w syncstate.SourceWitness, entry syncstate.SourceEntry, use func(*syncstate.VerifiedSnapshot) error) error {
	if a == nil || a.registry == nil {
		return syncstate.ErrIdentityConflict
	}
	return syncstate.CaptureAndUseGuarded(ctx, w, entry, a.registry.Directory(), &registryCaptureBudget{admission: a}, use)
}

type registryCaptureBudget struct {
	admission   *ArtifactAdmission
	reservation *syncstate.ArtifactReservation
	size        int64
	mu          sync.Mutex
	finished    bool
}

func (b *registryCaptureBudget) finish(retain bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.finished {
		return nil
	}
	var result error
	if b.reservation != nil {
		if retain {
			result = b.reservation.Relinquish()
			if result != nil {
				return result
			}
			result = b.admission.budget.finishArtifactCapture(b.admission.owner, b.size, true)
		} else {
			result = b.reservation.Dispose(context.Background())
			if result == nil {
				result = b.admission.budget.finishArtifactCapture(b.admission.owner, b.size, false)
			} else {
				if joined := b.reservation.Relinquish(); joined != nil {
					return errors.Join(result, joined)
				}
				b.admission.budget.blockSpool(result)
				result = errors.Join(result, b.admission.budget.finishArtifactCapture(b.admission.owner, b.size, true))
			}
		}
	}
	if result != nil {
		b.admission.budget.blockSpool(result)
	}
	b.finished = true
	b.admission.budget.releaseWorker()
	return result
}
func (b *registryCaptureBudget) ReserveCapture(ctx context.Context, dir string, size int64) (func(), error) {
	if filepath.Clean(dir) != b.admission.registry.Directory() || b.reservation != nil {
		return nil, syncstate.ErrIdentityConflict
	}
	budget := b.admission.budget
	if err := budget.acquireWorker(ctx); err != nil {
		return nil, err
	}
	if err := budget.reserveSpool(ctx, dir, size); err != nil {
		budget.releaseWorker()
		return nil, err
	}
	r, err := b.admission.registry.Reserve(ctx, size)
	if err != nil {
		budget.releaseSpool(size)
		budget.releaseWorker()
		if errors.Is(err, syncstate.ErrArtifactUnreconciled) {
			budget.blockSpool(err)
		}
		return nil, err
	}
	b.reservation, b.size = r, size
	if err = budget.retainReservation(b.admission.owner, size); err != nil {
		budget.blockSpool(err)
		budget.releaseWorker()
		return nil, err
	}
	return func() { _ = b.finish(false) }, nil
}
func (b *registryCaptureBudget) CreateCaptureArtifact(ctx context.Context, dir string) (*os.File, string, error) {
	if b.reservation == nil || dir != b.admission.registry.Directory() {
		return nil, "", syncstate.ErrIdentityConflict
	}
	f, err := b.reservation.Create(ctx)
	return f, b.reservation.ID(), err
}
func (b *registryCaptureBudget) RegisterCaptureArtifact(filename string, size int64) error {
	if b.reservation == nil || filename != filepath.Join(b.admission.registry.Directory(), b.reservation.ID()+".snapshot") || size != b.size {
		return syncstate.ErrIdentityConflict
	}
	return nil
}
func (b *registryCaptureBudget) AcquireCaptureReader(ctx context.Context) (func(), error) {
	return b.admission.reader(ctx)
}
func (b *registryCaptureBudget) SealCaptureArtifact(ctx context.Context, v *syncstate.VerifiedSnapshot) error {
	return b.reservation.SealSnapshot(ctx, v)
}
func (b *registryCaptureBudget) DisposeCaptureArtifact(ctx context.Context, filename string) error {
	if filename != filepath.Join(b.admission.registry.Directory(), b.reservation.ID()+".snapshot") {
		return syncstate.ErrIdentityConflict
	}
	err := b.reservation.Dispose(ctx)
	if err != nil {
		// Pending operation is a recoverable retained state, not unknown bytes.
		if !errors.Is(err, syncstate.ErrArtifactRetained) {
			_ = b.finish(true)
			b.admission.budget.blockSpool(err)
		}
		return err
	}
	return b.finish(false)
}
func (b *registryCaptureBudget) RetainCaptureArtifact(ctx context.Context, filename string) error {
	if b.reservation == nil || filename != filepath.Join(b.admission.registry.Directory(), b.reservation.ID()+".snapshot") {
		return syncstate.ErrIdentityConflict
	}
	return b.finish(true)
}
