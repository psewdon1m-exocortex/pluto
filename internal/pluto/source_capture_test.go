package pluto

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
)

func TestSourceCaptureSharesLegacyProcessBudgets(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	if err := os.WriteFile(name, []byte("four"), 0600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := syncstate.DescribeSource(name, "file", 0)
	if err != nil {
		t.Fatal(err)
	}
	object, err := syncstate.ObserveSourceIncarnation(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry := syncstate.SourceEntry{SourceDescriptor: descriptor, SetID: "source-set", SourceID: "source", SourceRootPath: dir, SourceObject: object.Object(), SourceIncarnation: 1, Generation: 1, VerificationRequest: 1}
	w := syncstate.SourceWitness{SetID: entry.SetID, OwnerID: "owner", Revision: 1}
	// A real legacy reader slot prevents the new capture from acquiring another.
	if err = copyResources.acquireReader(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err = CaptureSourceSnapshot(ctx, w, entry, t.TempDir())
	cancel()
	copyResources.releaseReader()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("new reader bypassed legacy", err)
	}
	// Both data slots remain the existing shared two; a third admission fails.
	for range 2 {
		if err = copyResources.acquireWorker(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
	err = copyResources.acquireWorker(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("third data slot", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err = CaptureSourceSnapshot(ctx, w, entry, t.TempDir())
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("capture bypassed both legacy data slots", err)
	}
	for range 2 {
		copyResources.releaseWorker()
	}
	v, err := CaptureSourceSnapshot(context.Background(), w, entry, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(copyResources.workers) != 1 || len(copyResources.readers) != 0 {
		t.Fatal("capture did not retain shared data slot")
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	// Borrow almost the full legacy plaintext budget; four new bytes cannot pass
	// the remaining three-byte admission, even though they use a different name.
	if err = copyResources.reserveSpool(context.Background(), t.TempDir(), MaxFileBytes-3); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err = CaptureSourceSnapshot(ctx, w, entry, t.TempDir())
	cancel()
	copyResources.releaseSpool(MaxFileBytes - 3)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("separate spool budget appeared", err)
	}
	copyResources.mu.Lock()
	bytes := copyResources.spoolBytes
	copyResources.mu.Unlock()
	if bytes != 0 {
		t.Fatal("spool remained charged", bytes)
	}
}

func sourceAdapterFixture(t *testing.T, bytes []byte) (syncstate.SourceWitness, syncstate.SourceEntry) {
	t.Helper()
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	if err := os.WriteFile(name, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := syncstate.DescribeSource(name, "file", 0)
	if err != nil {
		t.Fatal(err)
	}
	object, err := syncstate.ObserveSourceIncarnation(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry := syncstate.SourceEntry{SourceDescriptor: descriptor, SetID: "source-set", SourceID: "source", SourceRootPath: dir, SourceObject: object.Object(), SourceIncarnation: 1, Generation: 1, VerificationRequest: 1}
	return syncstate.SourceWitness{SetID: entry.SetID, OwnerID: "owner", Revision: 1}, entry
}
func TestSourceCaptureZeroByteArtifactsBounded(t *testing.T) {
	w, entry := sourceAdapterFixture(t, nil)
	dir := t.TempDir()
	first, err := CaptureSourceSnapshot(context.Background(), w, entry, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := CaptureSourceSnapshot(context.Background(), w, entry, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err = CaptureSourceSnapshot(ctx, w, entry, dir)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unbounded empty snapshots", err)
	}
	items, err := os.ReadDir(dir)
	if err != nil || len(items) != 2 {
		t.Fatal("unbounded private artifacts", len(items), err)
	}
}
func TestSourceCaptureOrphanSurvivesProcessRestart(t *testing.T) {
	if directory := os.Getenv("PLUTO_SOURCE_ORPHAN_RESTORE_PROBE"); directory != "" {
		verifySourceOrphanRestored(t, directory)
		return
	}
	if directory := os.Getenv("PLUTO_SOURCE_ORPHAN_FIXTURE"); directory != "" {
		w, entry := sourceAdapterFixture(t, []byte("retained"))
		captured, err := CaptureSourceSnapshot(context.Background(), w, entry, directory)
		if err != nil {
			t.Fatal(err)
		}
		qualifySourceOrphanBackup(t, w, entry, captured, directory)
		os.Exit(86) // A real process exit leaves the sealed artifact, no deferred Close.
	}
	dir := t.TempDir()
	// This assertion exercises the production fail-closed process latch. Restore
	// only this test's isolated global afterward; runtime has no reset shortcut.
	defer func() { copyResources.mu.Lock(); copyResources.spoolFailure = nil; copyResources.mu.Unlock() }()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestSourceCaptureOrphanSurvivesProcessRestart$")
	cmd.Env = append(os.Environ(), "PLUTO_SOURCE_ORPHAN_FIXTURE="+dir)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatalf("restart fixture: %v %s", err, output)
	}
	items, err := os.ReadDir(dir)
	if err != nil || len(items) != 1 {
		t.Fatal("missing orphan", len(items), err)
	}
	name := filepath.Join(dir, items[0].Name())
	before, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	w, entry := sourceAdapterFixture(t, []byte("fresh"))
	if _, err = CaptureSourceSnapshot(context.Background(), w, entry, dir); !errors.Is(err, ErrSourceCaptureArtifactsUnreconciled) {
		t.Fatal("orphan admitted", err)
	}
	if err = copyResources.reserveSpool(context.Background(), t.TempDir(), 1); !errors.Is(err, ErrSourceCaptureArtifactsUnreconciled) {
		t.Fatal("legacy Copy ignored retained unknown plaintext", err)
	}
	after, err := os.ReadFile(name)
	if err != nil || string(before) != "retained" || string(after) != string(before) {
		t.Fatal("unknown artifact modified", err)
	}
	copyResources.mu.Lock()
	charged := copyResources.spoolBytes
	copyResources.mu.Unlock()
	if charged != 0 || len(copyResources.workers) != 0 {
		t.Fatal("rejected new admission leaked reservation", charged)
	}
	recordSourceOrphanCrashWait(t, cmd.Process.Pid, exit.ExitCode(), dir, before, after, charged)
}
