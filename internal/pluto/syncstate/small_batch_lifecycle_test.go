package syncstate

import (
	"io"
	"testing"
	"time"
)

// Real native creation is paused between O_EXCL and recording birth identity.
// Other lifecycle operations must not mistake this owned transition for drift.
func TestSmallBatchLifecycleNamespaceTransitionIsAtomic(t *testing.T) {
	for _, action := range []string{"build", "read", "cleanup", "compact"} {
		t.Run(action, func(t *testing.T) {
			r, native, ops := nativeSmallBatchFixture(t, 4)
			first := stateBatchPlan(t, "lifecycle-first", ops[:2])
			other := stateBatchPlan(t, "lifecycle-other", ops[2:])
			if action != "build" {
				if _, err := native.build(testContext, other); err != nil {
					t.Fatal(err)
				}
			}
			if action == "compact" {
				if err := native.cleanup(testContext, other.id); err != nil {
					t.Fatal(err)
				}
			}
			entered, release := make(chan struct{}), make(chan struct{})
			firstDone := make(chan error, 1)
			r.testPoint = func(point string) error {
				if point == "small_batch.created.before_identity" {
					select {
					case <-entered:
					default:
						close(entered)
						<-release
					}
				}
				return nil
			}
			go func() { _, err := native.build(testContext, first); firstDone <- err }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("creation point missing")
			}
			otherDone := make(chan error, 1)
			go func() {
				var err error
				switch action {
				case "build":
					_, err = native.build(testContext, other)
				case "read":
					err = native.withAttempt(testContext, other.id, func(_ smallBatchRecord, input io.ReadSeeker) error { _, err := io.Copy(io.Discard, input); return err })
				case "cleanup":
					err = native.cleanup(testContext, other.id)
				case "compact":
					_, err = native.compact(testContext, 16)
				}
				otherDone <- err
			}()
			var early bool
			var earlyErr error
			select {
			case earlyErr = <-otherDone:
				early = true
			case <-time.After(75 * time.Millisecond):
			}
			close(release)
			select {
			case err := <-firstDone:
				if err != nil {
					t.Error("first build", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("first build not joined")
			}
			if early {
				t.Fatalf("%s crossed incomplete native namespace: %v", action, earlyErr)
			}
			select {
			case err := <-otherDone:
				if err != nil {
					t.Fatal(action, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("other lifecycle did not join")
			}
			if native.inUse() {
				t.Fatal("native users remain")
			}
		})
	}
}

func TestSmallBatchLifecycleMoreThan64PacketsRetiresJoinedReferences(t *testing.T) {
	sizes := make([]int, 140)
	for n := range sizes {
		sizes[n] = 1
	}
	r, w, f, _ := engineFixture(t, sizes, true, 2)
	before := CaptureMetricSnapshot()
	report, err := runEngineFixture(t, testContext, r, w, f, "bulk")
	if err != nil || !report.Complete || report.Uploaded != 140 || report.Failed != 0 || CaptureMetricSnapshot().Since(before).SourceReads != 140 {
		t.Fatal(report, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls["data"] <= 64 || f.calls["data"] > 70 {
		t.Fatal("did not cross the 64-reference boundary with native packets", f.calls)
	}
	t.Logf("140 source captures and publications; %d native packets, %d age-flushed individual files", f.calls["data"], 140-2*f.calls["data"])
	var retained int
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM small_batch_groups").Scan(&retained); err != nil || retained != 0 {
		t.Fatal("terminal references not retired", retained, err)
	}
	if native := r.store.batches; native.inUse() {
		t.Fatal("joined run retained native users")
	}
}
