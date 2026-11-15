package pluto

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
)

func admissionFixture(t *testing.T) (*syncstate.Store, *ArtifactAdmission, syncstate.SourceWitness, syncstate.SourceEntry) {
	t.Helper()
	old := copyResources
	copyResources = newCopyBudget(2, 1, MaxFileBytes)
	t.Cleanup(func() { copyResources = old })
	source := t.TempDir()
	name := filepath.Join(source, "file")
	if err := os.WriteFile(name, []byte("exact bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := syncstate.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err = store.EnableSources(context.Background(), syncstate.DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	a, report, err := BootstrapArtifactAdmission(context.Background(), store, syncstate.DefaultArtifactLimits())
	if err != nil || !report.Admitted {
		t.Fatal(report, err)
	}
	description, err := syncstate.DescribeSource(name, "file", 0)
	if err != nil {
		t.Fatal(err)
	}
	incarnation, err := syncstate.ObserveSourceIncarnation(source)
	if err != nil {
		t.Fatal(err)
	}
	w := syncstate.SourceWitness{SetID: "fixture-source", OwnerID: "fixture-owner", Revision: 1}
	e := syncstate.SourceEntry{SourceDescriptor: description, SetID: w.SetID, SourceID: "source", SourceRootPath: source, SourceObject: incarnation.Object(), SourceIncarnation: 1, Generation: 1, VerificationRequest: 1}
	return store, a, w, e
}

type readerWaitCaptureBudget struct {
	*registryCaptureBudget
	reached chan struct{}
}

func (b *readerWaitCaptureBudget) AcquireCaptureReader(ctx context.Context) (func(), error) {
	close(b.reached)
	return b.registryCaptureBudget.AcquireCaptureReader(ctx)
}

func TestArtifactAdmissionReusesCaptureAndSharedLegacyBudget(t *testing.T) {
	store, a, w, e := admissionFixture(t)
	v, err := a.Capture(context.Background(), w, e)
	if err != nil {
		t.Fatal(err)
	}
	id := v.Evidence().SnapshotID
	record, err := a.registry.Record(context.Background(), id)
	if err != nil || record.Phase != syncstate.ArtifactSealed || record.SizeBytes != e.SizeBytes {
		t.Fatal(record, err)
	}
	if copyResources.retainedBytes != e.SizeBytes || copyResources.spoolBytes != 0 || len(copyResources.workers) != 1 {
		t.Fatal("independent budget or slot", copyResources.retainedBytes, copyResources.spoolBytes, len(copyResources.workers))
	}
	if err = store.Close(); !errors.Is(err, syncstate.ErrArtifactInUse) {
		t.Fatal("live capture lost owner", err)
	}
	// Real legacy reservation must fit remaining retained bytes, not a second cap.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err = copyResources.reserveSpool(ctx, a.registry.Directory(), MaxFileBytes)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("retained bytes bypassed", err)
	}
	if err = copyResources.acquireReader(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Cancel only after the private file and its SQL identity are registered.
	// A short wall-clock timeout could instead interrupt that registration;
	// such unknown bytes must remain charged for reconciliation, not be erased.
	ctx, cancel = context.WithCancel(context.Background())
	waiting := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, captureErr := syncstate.CaptureGuarded(ctx, w, e, a.registry.Directory(), &readerWaitCaptureBudget{registryCaptureBudget: &registryCaptureBudget{admission: a}, reached: waiting})
		done <- captureErr
	}()
	select {
	case <-waiting:
		cancel()
	case captureErr := <-done:
		cancel()
		copyResources.releaseReader()
		t.Fatal("capture did not reach occupied reader", captureErr)
	case <-time.After(10 * time.Second):
		cancel()
		captureErr := <-done
		copyResources.releaseReader()
		t.Fatal("capture did not reach reader before fixture deadline", captureErr)
	}
	err = <-done // All capture users join before the reader/budget assertions.
	copyResources.releaseReader()
	if !errors.Is(err, context.Canceled) {
		t.Fatal("reader bypass", err)
	}
	if len(copyResources.workers) != 1 || copyResources.retainedBytes != e.SizeBytes {
		t.Fatal("cancelled capture leaked", len(copyResources.workers), copyResources.retainedBytes)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	if copyResources.retainedBytes != 0 || len(copyResources.workers) != 0 {
		t.Fatal("joined disposal not released")
	}
	if err = copyResources.reserveSpool(context.Background(), a.registry.Directory(), MaxFileBytes); err != nil {
		t.Fatal(err)
	}
	copyResources.releaseSpool(MaxFileBytes)
}
func TestArtifactAdmissionRetainSurvivesHandleAndNoNewScope(t *testing.T) {
	store, a, w, e := admissionFixture(t)
	v, err := a.Capture(context.Background(), w, e)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Retain(); err != nil {
		t.Fatal(err)
	}
	if len(copyResources.workers) != 0 || copyResources.retainedBytes != e.SizeBytes {
		t.Fatal("retained charge vanished")
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	record, err := a.registry.Record(context.Background(), v.Evidence().SnapshotID)
	if err != nil || record.Phase != syncstate.ArtifactSealed {
		t.Fatal(record, err)
	}
	if _, _, err = BootstrapArtifactAdmission(context.Background(), store, syncstate.DefaultArtifactLimits()); !errors.Is(err, syncstate.ErrArtifactInUse) {
		t.Fatal("second owner accepted", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err = copyResources.reserveSpool(ctx, a.registry.Directory(), MaxFileBytes)
	cancel()
	if !errors.Is(err, syncstate.ErrArtifactRetained) {
		t.Fatal("close discarded durable charge", err)
	}
}
func TestArtifactAdmissionUnknownBlocksLegacyBeforeAnyCapture(t *testing.T) {
	old := copyResources
	copyResources = newCopyBudget(2, 1, MaxFileBytes)
	defer func() { copyResources = old }()
	store, err := syncstate.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.EnableSources(context.Background(), syncstate.DefaultSourceLimits())
	a, err := store.EnableArtifacts(context.Background(), syncstate.DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(a.Directory(), "unknown")
	if err = os.WriteFile(name, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	_, report, err := BootstrapArtifactAdmission(context.Background(), store, syncstate.DefaultArtifactLimits())
	if !errors.Is(err, syncstate.ErrArtifactUnreconciled) || report.Admitted {
		t.Fatal(report, err)
	}
	if err = copyResources.reserveSpool(context.Background(), t.TempDir(), 1); !errors.Is(err, syncstate.ErrArtifactUnreconciled) {
		t.Fatal("legacy bypass", err)
	}
	if raw, _ := os.ReadFile(name); string(raw) != "preserve" {
		t.Fatal("unknown removed")
	}
}
func TestArtifactBootstrapGateNoWorkDuringReaderAndExistingWorkRefusal(t *testing.T) {
	b := newCopyBudget(2, 1, MaxFileBytes)
	directory := t.TempDir()
	if err := b.acquireWorker(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.installArtifactOwner("scope", 1); !errors.Is(err, syncstate.ErrArtifactInUse) {
		t.Fatal(err)
	}
	b.releaseWorker()
	if err := b.installArtifactOwner("scope", 1, directory); err != nil {
		t.Fatal(err)
	}
	if err := b.acquireWorker(context.Background()); !errors.Is(err, syncstate.ErrArtifactUnreconciled) {
		t.Fatal(err)
	}
	if err := b.acquireEnumeration(context.Background(), directory, 1<<20); !errors.Is(err, syncstate.ErrArtifactUnreconciled) {
		t.Fatal(err)
	}
	if err := b.reserveSpool(context.Background(), directory, 1); !errors.Is(err, syncstate.ErrArtifactUnreconciled) {
		t.Fatal(err)
	}
	if err := b.acquireReader(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.releaseReader()
	if err := b.completeArtifactBootstrap("scope", MaxFileBytes); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := b.reserveSpool(ctx, directory, 1)
	cancel()
	if !errors.Is(err, syncstate.ErrArtifactRetained) {
		t.Fatal(err)
	}
}
func TestArtifactLegacySpoolUnknownPreservedBeforeAnyWork(t *testing.T) {
	for _, kind := range []string{"copy-prefix", "foreign", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			old := copyResources
			copyResources = newCopyBudget(2, 1, MaxFileBytes)
			defer func() { copyResources = old }()
			dir := t.TempDir()
			store, err := syncstate.Open(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			store.EnableSources(context.Background(), syncstate.DefaultSourceLimits())
			spool := filepath.Join(dir, "spool")
			if err = os.Mkdir(spool, 0700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(spool, "copy-fixture")
			if kind == "foreign" {
				name = filepath.Join(spool, "foreign")
			}
			if kind == "symlink" {
				if err = os.Symlink(filepath.Join(t.TempDir(), "outside"), name); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.WriteFile(name, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Lstat(name)
			_, report, err := BootstrapArtifactAdmission(context.Background(), store, syncstate.DefaultArtifactLimits())
			if !errors.Is(err, syncstate.ErrArtifactUnreconciled) || report.Admitted || report.Complete {
				t.Fatal(report, err)
			}
			after, _ := os.Lstat(name)
			if after == nil || !os.SameFile(before, after) {
				t.Fatal("legacy retained object changed")
			}
			if err = copyResources.reserveSpool(context.Background(), spool, 1); !errors.Is(err, syncstate.ErrArtifactUnreconciled) {
				t.Fatal("legacy/new budget bypass", err)
			}
		})
	}
}
func TestArtifactAdmittedProfileRejectsOtherSpoolAndSubstitution(t *testing.T) {
	_, a, _, _ := admissionFixture(t)
	other := t.TempDir()
	if err := copyResources.reserveSpool(context.Background(), other, 1); !errors.Is(err, syncstate.ErrIdentityConflict) {
		t.Fatal("uninspected external spool accepted", err)
	}
	if err := copyResources.acquireEnumeration(context.Background(), other, 1<<20); !errors.Is(err, syncstate.ErrIdentityConflict) {
		t.Fatal("external metadata work accepted", err)
	}
	legacy := filepath.Join(filepath.Dir(a.registry.Directory()), "spool")
	outside := t.TempDir()
	if err := os.Symlink(outside, legacy); err != nil {
		t.Fatal(err)
	}
	if err := copyResources.reserveSpool(context.Background(), legacy, 1); !errors.Is(err, syncstate.ErrIdentityConflict) {
		t.Fatal("symlink spool accepted", err)
	}
}
func TestArtifactAdmissionRestartChild(t *testing.T) {
	dir := os.Getenv("PLUTO_ARTIFACT_ADMISSION_RESTART")
	if dir == "" {
		return
	}
	store, err := syncstate.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnableSources(context.Background(), syncstate.DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	a, report, err := BootstrapArtifactAdmission(context.Background(), store, syncstate.DefaultArtifactLimits())
	if err != nil || a == nil || !report.Admitted {
		t.Fatal(report, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err = copyResources.reserveSpool(ctx, a.registry.Directory(), MaxFileBytes)
	cancel()
	if !errors.Is(err, syncstate.ErrArtifactRetained) {
		t.Fatal("restarted legacy bypassed retained bytes", err)
	}
	raw, _ := json.Marshal(map[string]any{"retainedBytes": copyResources.retainedBytes, "legacyBlocked": true, "admitted": report.Admitted})
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout.Write(append(raw, '\n'))
	os.Exit(0)
}
func TestArtifactActualRestartAccountsBeforeLegacyWork(t *testing.T) {
	store, a, w, e := admissionFixture(t)
	v, err := a.Capture(context.Background(), w, e)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Retain(); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	backup := qualifyAdmissionRestartBackup(t, filepath.Dir(a.registry.Directory()), e, v)
	cmd := exec.Command(os.Args[0], "-test.run=^TestArtifactAdmissionRestartChild$")
	cmd.Env = append(os.Environ(), "PLUTO_ARTIFACT_ADMISSION_RESTART="+filepath.Dir(a.registry.Directory()))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(output), err)
	}
	var result struct {
		RetainedBytes           int64
		LegacyBlocked, Admitted bool
	}
	if err = json.Unmarshal(output, &result); err != nil || result.RetainedBytes != e.SizeBytes || !result.LegacyBlocked || !result.Admitted {
		t.Fatal(string(output), err)
	}
	backup.recordOrderlyWait(t, cmd.Process.Pid, cmd.ProcessState.ExitCode(), output)
}
func TestArtifactTwoCapturesStillUseTwoDataOneReader(t *testing.T) {
	_, a, w, e := admissionFixture(t)
	if err := copyResources.acquireReader(context.Background()); err != nil {
		t.Fatal(err)
	}
	type result struct {
		v   *syncstate.VerifiedSnapshot
		err error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() { v, err := a.Capture(context.Background(), w, e); done <- result{v, err} }()
	}
	deadline := time.Now().Add(time.Second)
	for len(copyResources.workers) != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := copyResources.acquireWorker(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("third worker", err)
	}
	copyResources.releaseReader()
	for range 2 {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		if err = r.v.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(copyResources.workers) != 0 || len(copyResources.readers) != 0 || copyResources.retainedBytes != 0 {
		t.Fatal("concurrent capture leaked budgets")
	}
}
