package syncstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func nativeSmallBatchFixture(t *testing.T, count int) (*RemoteImport, *smallBatchArtifacts, []Operation) {
	t.Helper()
	r, ops := smallBatchStateFixture(t, count)
	// testing.TempDir creates this child as 0755. The optional native spool
	// requires the same private 0700 state parent as a qualified installation.
	if err := os.Chmod(filepath.Dir(r.store.filename), 0700); err != nil {
		t.Fatal(err)
	}
	state, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	native, err := state.enableArtifacts(testContext)
	if err != nil {
		parent, _ := os.Stat(filepath.Dir(r.store.filename))
		t.Fatalf("native enable: %v; state directory mode=%v", err, parent.Mode())
	}
	return r, native, ops
}
func reopenNativeSmallBatch(t *testing.T, directory string) (*RemoteImport, *smallBatchArtifacts) {
	t.Helper()
	store, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err = store.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = artifacts.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
	r, err := store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	state, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	native, err := state.enableArtifacts(testContext)
	if err != nil {
		t.Fatal(err)
	}
	return r, native
}
func TestSmallBatchArtifactsNativeBuildAttemptCleanupPreservesOriginals(t *testing.T) {
	r, native, ops := nativeSmallBatchFixture(t, 3)
	originals := batchOriginalState(t, r, ops)
	metrics := CaptureMetricSnapshot()
	p := stateBatchPlan(t, "native-roundtrip", ops)
	record, err := native.build(testContext, p)
	if err != nil {
		t.Fatalf("native build: %v", err)
	}
	if record.Phase != "READY" || record.SHA256 != hashBytes([]byte("oneoneone")) || record.FileIdentity == "" || record.DirectoryIdentity == "" {
		t.Fatal(record.Phase, record.SHA256)
	}
	if charge, err := r.store.artifacts.Charge(testContext); err != nil || charge != 18 {
		t.Fatal(charge, err)
	}
	err = native.withAttempt(testContext, p.id, func(saved smallBatchRecord, input io.ReadSeeker) error {
		if saved.Phase != "ATTEMPTED" {
			t.Fatal(saved.Phase)
		}
		durable, e := native.state.read(testContext, p.id)
		if e != nil || durable.Phase != "ATTEMPTED" {
			t.Fatal("attempt not committed", e)
		}
		if e = r.store.Close(); !errors.Is(e, ErrArtifactInUse) {
			t.Fatal("store closed with native user", e)
		}
		if e = native.cleanup(testContext, p.id); !errors.Is(e, ErrArtifactInUse) {
			t.Fatal("cleanup raced reader", e)
		}
		stream, e := newSmallBatchStream(testContext, saved.Plan, input, nil)
		if e != nil {
			return e
		}
		defer stream.Close()
		raw, e := io.ReadAll(stream)
		if e != nil {
			return e
		}
		checkBatchMIME(t, raw, stream.contentType, p, [][]byte{[]byte("one"), []byte("one"), []byte("one")})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = native.cleanup(testContext, p.id); err != nil {
		t.Fatal(err)
	}
	if err = native.cleanup(testContext, p.id); err != nil {
		t.Fatal("cleanup replay", err)
	}
	saved, err := native.state.read(testContext, p.id)
	if err != nil || saved.Phase != "GONE" {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(native.path)
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
	if charge, err := r.store.artifacts.Charge(testContext); err != nil || charge != 9 {
		t.Fatal(charge, err)
	}
	if n, err := native.compact(testContext, 16); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err = native.state.read(testContext, p.id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if batchOriginalState(t, r, ops) != originals {
		t.Fatal("native transport changed original authority")
	}
	if used := CaptureMetricSnapshot().Since(metrics); used.SourceReads != 0 || used.SourceHashBytes != 0 {
		t.Fatal("recaptured user's source", used)
	}
}
func TestSmallBatchArtifactsRestartRetainsAttemptAndNativeIdentity(t *testing.T) {
	r, native, ops := nativeSmallBatchFixture(t, 2)
	p := stateBatchPlan(t, "native-restart", ops)
	record, err := native.build(testContext, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = native.withAttempt(testContext, p.id, func(smallBatchRecord, io.ReadSeeker) error { return context.Canceled }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	directory := filepath.Dir(r.store.filename)
	before := batchOriginalState(t, r, ops)
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	next, native := reopenNativeSmallBatch(t, directory)
	reused, err := native.build(testContext, p)
	if err != nil || reused.Phase != "ATTEMPTED" || reused.FileIdentity != record.FileIdentity || reused.Name != record.Name {
		t.Fatal(reused.Phase, err)
	}
	if err = native.withAttempt(testContext, p.id, func(_ smallBatchRecord, input io.ReadSeeker) error {
		raw, e := io.ReadAll(input)
		if e == nil && !bytes.Equal(raw, []byte("oneone")) {
			e = ErrIdentityConflict
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if batchOriginalState(t, next, ops) != before {
		t.Fatal("restart changed originals")
	}
	if err = native.cleanup(testContext, p.id); err != nil {
		t.Fatal(err)
	}
}
func TestSmallBatchArtifactsBuildCrashPointsAndUnknownCustody(t *testing.T) {
	for _, point := range []string{"small_batch.created.before_identity", "small_batch.building.before_commit", "small_batch.building.after_commit", "small_batch.copied_original", "small_batch.ready.before_commit", "small_batch.ready.after_commit"} {
		t.Run(point, func(t *testing.T) {
			r, native, ops := nativeSmallBatchFixture(t, 2)
			p := stateBatchPlan(t, "build-crash", ops)
			before := batchOriginalState(t, r, ops)
			once := true
			r.testPoint = func(name string) error {
				if once && name == point {
					once = false
					return context.Canceled
				}
				return nil
			}
			if _, err := native.build(testContext, p); !errors.Is(err, context.Canceled) {
				t.Fatal(point, err)
			}
			r.testPoint = nil
			record, err := native.state.read(testContext, p.id)
			if err != nil {
				t.Fatal(err)
			}
			if record.Phase == "RESERVED" {
				file := filepath.Join(native.path, record.Name)
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = native.build(testContext, p); err == nil {
					t.Fatal("unknown inode adopted")
				}
				if err = native.cleanup(testContext, p.id); err == nil {
					t.Fatal("unknown inode deleted")
				}
				after, err := os.ReadFile(file)
				if err != nil || !bytes.Equal(raw, after) {
					t.Fatal("unknown bytes changed", err)
				}
			} else {
				if _, err = native.build(testContext, p); err != nil {
					t.Fatal("owned build did not resume", err)
				}
				if err = native.cleanup(testContext, p.id); err != nil {
					t.Fatal(err)
				}
			}
			if batchOriginalState(t, r, ops) != before {
				t.Fatal("build crash lost original state")
			}
		})
	}
}
func TestSmallBatchArtifactsAttemptAndCleanupCrashPoints(t *testing.T) {
	for _, point := range []string{"small_batch.attempted.before_commit", "small_batch.attempted.after_commit", "small_batch.disposing.before_commit", "small_batch.disposing.after_commit", "small_batch.quarantined", "small_batch.unlinked", "small_batch.gone.before_commit", "small_batch.gone.after_commit"} {
		t.Run(point, func(t *testing.T) {
			r, native, ops := nativeSmallBatchFixture(t, 2)
			p := stateBatchPlan(t, "lifecycle-crash", ops)
			if _, err := native.build(testContext, p); err != nil {
				t.Fatal(err)
			}
			before := batchOriginalState(t, r, ops)
			once := true
			r.testPoint = func(name string) error {
				if once && name == point {
					once = false
					return context.Canceled
				}
				return nil
			}
			called := false
			if strings.Contains(point, "attempted") {
				err := native.withAttempt(testContext, p.id, func(smallBatchRecord, io.ReadSeeker) error { called = true; return nil })
				if !errors.Is(err, context.Canceled) || called {
					t.Fatal("network crossed ambiguous attempt commit", err, called)
				}
			} else {
				if err := native.cleanup(testContext, p.id); !errors.Is(err, context.Canceled) {
					t.Fatal(point, err)
				}
			}
			r.testPoint = nil
			if err := native.cleanup(testContext, p.id); err != nil {
				t.Fatal("joined cleanup recovery", err)
			}
			if batchOriginalState(t, r, ops) != before {
				t.Fatal("originals changed")
			}
		})
	}
}
func TestSmallBatchArtifactsReservationAndFallbackCannotDeleteUnknownBytes(t *testing.T) {
	r, native, ops := nativeSmallBatchFixture(t, 2)
	p := stateBatchPlan(t, "reserved-cleanup", ops)
	if _, err := native.state.reserve(testContext, p); err != nil {
		t.Fatal(err)
	}
	if err := native.cleanup(testContext, p.id); err != nil {
		t.Fatal("never-created reservation", err)
	}
	p = stateBatchPlan(t, "replacement-cleanup", ops)
	record, err := native.build(testContext, p)
	if err != nil {
		t.Fatal(err)
	}
	drop := filepath.Join(native.path, strings.TrimSuffix(record.Name, ".batch")+".drop")
	saved := drop + ".saved"
	foreign := []byte("retain")
	r.testPoint = func(point string) error {
		if point == "small_batch.quarantined" {
			if err := os.Rename(drop, saved); err != nil {
				return err
			}
			return os.WriteFile(drop, foreign, 0400)
		}
		return nil
	}
	if err = native.cleanup(testContext, p.id); err == nil {
		t.Fatal("foreign replacement removed")
	}
	r.testPoint = nil
	if raw, err := os.ReadFile(drop); err != nil || !bytes.Equal(raw, foreign) {
		t.Fatal("foreign bytes lost", err)
	}
	if raw, err := os.ReadFile(saved); err != nil || !bytes.Equal(raw, []byte("oneone")) {
		t.Fatal("original quarantine lost", err)
	}
	for _, op := range ops {
		if _, err = r.store.artifacts.Record(testContext, op.SnapshotID); err != nil {
			t.Fatal(err)
		}
	}
}
func TestSmallBatchArtifactsRejectMutationLinksAndUnexpectedNamespace(t *testing.T) {
	for _, kind := range []string{"same-bytes-replacement", "changed-bytes", "hardlink", "symlink", "unknown-file"} {
		t.Run(kind, func(t *testing.T) {
			_, native, ops := nativeSmallBatchFixture(t, 2)
			p := stateBatchPlan(t, "native-drift", ops)
			record, err := native.build(testContext, p)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(native.path, record.Name)
			switch kind {
			case "same-bytes-replacement":
				if err = os.Rename(file, file+".saved"); err != nil {
					t.Fatal(err)
				}
				err = os.WriteFile(file, []byte("oneone"), 0400)
			case "changed-bytes":
				if err = os.Chmod(file, 0600); err == nil {
					err = os.WriteFile(file, []byte("badbad"), 0600)
				}
				if err == nil {
					err = os.Chmod(file, 0400)
				}
			case "hardlink":
				err = os.Link(file, file+".linked")
			case "symlink":
				if err = os.Rename(file, file+".saved"); err == nil {
					err = os.Symlink(file+".saved", file)
				}
			case "unknown-file":
				err = os.WriteFile(filepath.Join(native.path, "foreign"), []byte("keep"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if err = native.withAttempt(testContext, p.id, func(smallBatchRecord, io.ReadSeeker) error { called = true; return nil }); err == nil || called {
				t.Fatal("mutated custody reached network", err, called)
			}
			if kind != "unknown-file" {
				if err = native.cleanup(testContext, p.id); err == nil {
					t.Fatal("mutated custody cleaned")
				}
			}
		})
	}
}
func TestSmallBatchArtifactsFourJoinedReadersAndCancellation(t *testing.T) {
	r, native, ops := nativeSmallBatchFixture(t, 4)
	var plans []*smallBatchPlan
	for n, op := range ops {
		p := stateBatchPlan(t, "reader-"+remoteDecimal(int64(n)), []Operation{op})
		if _, err := native.build(testContext, p); err != nil {
			t.Fatal(err)
		}
		plans = append(plans, p)
	}
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	failures := make(chan error, 4)
	var joined sync.WaitGroup
	for _, p := range plans {
		joined.Add(1)
		go func(id string) {
			defer joined.Done()
			failures <- native.withAttempt(testContext, id, func(_ smallBatchRecord, input io.ReadSeeker) error {
				entered <- struct{}{}
				<-release
				_, err := io.Copy(io.Discard, input)
				return err
			})
		}(p.id)
	}
	for range plans {
		select {
		case <-entered:
		case err := <-failures:
			close(release)
			joined.Wait()
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			close(release)
			joined.Wait()
			t.Fatal("readers did not enter")
		}
	}
	if err := r.store.Close(); !errors.Is(err, ErrArtifactInUse) {
		t.Fatal(err)
	}
	if done, err := native.acquire(testContext, "fifth-reader"); err == nil {
		done()
		t.Fatal("fifth native user admitted")
	}
	close(release)
	joined.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if err := native.withAttempt(ctx, plans[0].id, func(smallBatchRecord, io.ReadSeeker) error { t.Fatal("canceled callback"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, p := range plans {
		if err := native.cleanup(testContext, p.id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSmallBatchArtifactsRejectPublicParentWithoutChangingItsMode(t *testing.T) {
	r, _ := smallBatchStateFixture(t, 1)
	state, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(r.store.filename)
	if err = os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = state.enableArtifacts(testContext); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("private capability changed parent mode", err)
	}
	if _, err = os.Lstat(filepath.Join(parent, smallBatchDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("spool created before parent qualification", err)
	}
}

func TestSmallBatchArtifactsActualMixedPayloadAndInteropExport(t *testing.T) {
	r, _, witness, session, _, source := actualHTTPFixture(t, 4)
	payloads := [][]byte{nil, {0}, bytes.Repeat([]byte{0xE9, 0, 0xFF, 0xF0}, 256), bytes.Repeat([]byte{0xAE}, 256*1024)}
	for n, data := range payloads {
		if err := os.WriteFile(filepath.Join(source, fmt.Sprintf("file-%03d", n)), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(r.store.filename), 0700); err != nil {
		t.Fatal(err)
	}
	report, err := r.RunCapturedScan(testContext, CapturedScanOptions{Witness: witness, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: pendingSmallBatchSession{session}, Capture: func(ctx context.Context, w SourceWitness, e SourceEntry) (*VerifiedSnapshot, error) {
		return CaptureGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	}})
	if report.Failed != 4 || report.Uploaded != 0 {
		t.Fatal(report, err)
	}
	rows, err := r.store.db.Query("SELECT operation_id FROM operations WHERE kind='PUT' ORDER BY json_extract(intent_json,'$.Name')")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if len(ids) != 4 {
		t.Fatal(len(ids))
	}
	var ops []Operation
	for n, id := range ids {
		op, err := r.store.Operation(testContext, id)
		if err != nil || op.Stage != "SUBMITTED" || op.SizeBytes != int64(len(payloads[n])) || op.SHA256 != hashBytes(payloads[n]) {
			t.Fatal(n, err)
		}
		ops = append(ops, op)
	}
	state, err := r.enableSmallBatches(testContext)
	if err != nil {
		t.Fatal(err)
	}
	native, err := state.enableArtifacts(testContext)
	if err != nil {
		t.Fatal(err)
	}
	plan := stateBatchPlan(t, "native-mixed-content", ops)
	before := CaptureMetricSnapshot()
	record, err := native.build(testContext, plan)
	if err != nil || record.ExpectedBytes != 263169 || record.SHA256 != hashBytes(bytes.Join(payloads, nil)) {
		t.Fatal(record.ExpectedBytes, err)
	}
	err = native.withAttempt(testContext, plan.id, func(saved smallBatchRecord, input io.ReadSeeker) error {
		stream, e := newSmallBatchStream(testContext, saved.Plan, input, nil)
		if e != nil {
			return e
		}
		defer stream.Close()
		raw, e := io.ReadAll(stream)
		if e != nil {
			return e
		}
		checkBatchMIME(t, raw, stream.contentType, plan, payloads)
		if directory := os.Getenv("PLUTO_BATCH_NATIVE_FIXTURE"); directory != "" {
			if e = os.MkdirAll(directory, 0700); e != nil {
				return e
			}
			for name, content := range map[string][]byte{"body.bin": raw, "content-type.txt": []byte(stream.contentType), "manifest.json": plan.manifestBytes()} {
				file, e := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if e != nil {
					return e
				}
				_, writeErr := file.Write(content)
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					return errors.Join(writeErr, closeErr)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = native.cleanup(testContext, plan.id); err != nil {
		t.Fatal(err)
	}
	if used := CaptureMetricSnapshot().Since(before); used.SourceReads != 0 || used.SourceHashBytes != 0 {
		t.Fatal("aggregate path recaptured source", used)
	}
}
