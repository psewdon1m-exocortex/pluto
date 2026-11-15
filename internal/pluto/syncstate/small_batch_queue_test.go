package syncstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic original identities exercise queue bounds; this fixture makes no
// claim of 500 native captures or backend publications. Native coverage is in
// the dispatcher/artifact tests.
func queueOriginals(t *testing.T, count int, size int64) []Operation {
	t.Helper()
	base, _ := smallBatchWireFixture(t, 1)
	ops := make([]Operation, count)
	digest := hashBytes(bytes.Repeat([]byte{'z'}, int(size)))
	for n := range ops {
		op := cloneSmallBatchOperation(t, base[0])
		op.Stage = "SUBMITTED"
		op.HTTPBinding = nil
		op.OperationID = remoteVersion(10000 + n)
		op.Name = fmt.Sprintf("queued-%04d", n)
		op.NameKey = op.Name
		op.SizeBytes = size
		op.SHA256 = digest
		op.Captured.Evidence.SizeBytes = size
		op.Captured.Evidence.SHA256 = digest
		op.Captured.Evidence.Destination = "tree/nested/" + op.Name
		op.Captured.Transport.RequestPath = "/" + op.Captured.Evidence.Destination
		resealSmallBatchOperation(&op)
		ops[n] = op
	}
	return ops
}
func defaultQueueLimits() smallBatchQueueLimits {
	return smallBatchQueueLimits{500, smallBatchMaximumDataBytes, smallBatchMaximumMetadataBytes}
}

func TestSmallBatchQueueOldestAgeAndExplicitBarrier(t *testing.T) {
	ops := queueOriginals(t, 3, 3)
	for _, age := range []time.Duration{250 * time.Millisecond, time.Second} {
		t.Run(age.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(testContext)
			defer cancel()
			type sent struct {
				count int
				at    time.Time
			}
			sends := make(chan sent, 4)
			var completed atomic.Int32
			q, err := newSmallBatchQueue(ctx, defaultQueueLimits(), age, func(_ context.Context, p *smallBatchPlan) error {
				sends <- sent{len(p.entries), time.Now()}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer q.close()
			complete := func(err error) {
				if err != nil {
					t.Error(err)
				}
				completed.Add(1)
			}
			start := time.Now()
			if err = q.enqueue(ctx, ops[0], "rules-1", complete); err != nil {
				t.Fatal(err)
			}
			time.Sleep(age / 2)
			if err = q.enqueue(ctx, ops[1], "rules-1", complete); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-sends:
				if got.count != 2 || got.at.Sub(start) < age-30*time.Millisecond || got.at.Sub(start) > age+2*time.Second {
					t.Fatal("age flush", got.count, got.at.Sub(start))
				}
			case <-time.After(3 * time.Second):
				t.Fatal("age did not flush")
			}
			if err = q.enqueue(ctx, ops[2], "rules-1", complete); err != nil {
				t.Fatal(err)
			}
			if err = q.flush(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-sends:
				if got.count != 1 {
					t.Fatal(got)
				}
			default:
				t.Fatal("barrier returned before last dispatch")
			}
			if completed.Load() != 3 {
				t.Fatal("barrier did not join callbacks", completed.Load())
			}
		})
	}
}

func TestSmallBatchQueueItemDataAndMetadataLimits(t *testing.T) {
	ops := queueOriginals(t, 501, 3)
	single, err := newSmallBatchPlan("queue-candidate", "rules-1", ops[:1])
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := single.prepareBytes()
	retained, _ := json.Marshal(ops[0])
	twoMetadata := int64(2*max(len(raw)+128, len(retained)) + 128)
	for _, tc := range []struct {
		name   string
		count  int
		limits smallBatchQueueLimits
		sizes  []int
	}{
		{"items500", 501, defaultQueueLimits(), nil},
		{"items2", 5, smallBatchQueueLimits{2, smallBatchMaximumDataBytes, smallBatchMaximumMetadataBytes}, []int{1, 2, 2}},
		{"data6", 5, smallBatchQueueLimits{500, 6, smallBatchMaximumMetadataBytes}, []int{1, 2, 2}},
		{"metadata", 5, smallBatchQueueLimits{500, smallBatchMaximumDataBytes, twoMetadata}, []int{1, 2, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(testContext)
			defer cancel()
			sizes := make(chan int, tc.count)
			var completed atomic.Int32
			q, e := newSmallBatchQueue(ctx, tc.limits, time.Second, func(_ context.Context, p *smallBatchPlan) error {
				wire, err := p.prepareBytes()
				if err != nil || len(p.entries) > tc.limits.items || p.dataBytes > tc.limits.data || int64(len(wire)) > tc.limits.metadata {
					return ErrSourceQuota
				}
				sizes <- len(p.entries)
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			for _, op := range ops[:tc.count] {
				if e = q.enqueue(ctx, op, "rules-1", func(err error) {
					if err != nil {
						t.Error(err)
					}
					completed.Add(1)
				}); e != nil {
					t.Fatal(e)
				}
			}
			if e = q.close(); e != nil {
				t.Fatal(e)
			}
			close(sizes)
			var got []int
			for count := range sizes {
				got = append(got, count)
			}
			sort.Ints(got)
			if tc.sizes != nil && !reflect.DeepEqual(got, tc.sizes) || tc.sizes == nil && len(got) < 2 || int(completed.Load()) != tc.count {
				t.Fatal("queue bounds/joins", got, completed.Load())
			}
		})
	}
}

func TestSmallBatchQueueRulesPartitionFrozenCallerAndDuplicateRefusal(t *testing.T) {
	ops := queueOriginals(t, 4, 0)
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	plans := make(chan *smallBatchPlan, 4)
	var completed atomic.Int32
	q, err := newSmallBatchQueue(ctx, defaultQueueLimits(), time.Second, func(_ context.Context, p *smallBatchPlan) error { plans <- p; return nil })
	if err != nil {
		t.Fatal(err)
	}
	complete := func(err error) {
		if err != nil {
			t.Error(err)
		}
		completed.Add(1)
	}
	if err = q.enqueue(ctx, ops[0], "rules-1", complete); err != nil {
		t.Fatal(err)
	}
	if err = q.enqueue(ctx, ops[0], "rules-1", func(error) { t.Error("rejected duplicate owned a callback") }); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("duplicate accepted", err)
	}
	originalPath := ops[0].Captured.Evidence.Destination
	ops[0].Captured.Evidence.Destination = "mutated-after-enqueue"
	if err = q.enqueue(ctx, ops[1], "rules-1", complete); err != nil {
		t.Fatal(err)
	}
	for _, op := range ops[2:] {
		if err = q.enqueue(ctx, op, "rules-2", complete); err != nil {
			t.Fatal(err)
		}
	}
	if err = q.close(); err != nil {
		t.Fatal(err)
	}
	close(plans)
	seen := map[string]int{}
	for p := range plans {
		seen[p.rules] += len(p.entries)
		for _, entry := range p.entries {
			if entry.original.OperationID == ops[0].OperationID && entry.original.Captured.Evidence.Destination != originalPath {
				t.Fatal("caller changed queued proof")
			}
		}
	}
	if seen["rules-1"] != 2 || seen["rules-2"] != 2 || len(seen) != 2 || completed.Load() != 4 {
		t.Fatal(seen, completed.Load())
	}
}

func TestSmallBatchQueueBackpressureCancellationAndTwoJoinedWorkers(t *testing.T) {
	ops := queueOriginals(t, 5, 1)
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	started := make(chan struct{}, 2)
	var active, peak, completed atomic.Int32
	q, err := newSmallBatchQueue(ctx, smallBatchQueueLimits{1, 1024, smallBatchMaximumMetadataBytes}, time.Second, func(ctx context.Context, _ *smallBatchPlan) error {
		current := active.Add(1)
		for old := peak.Load(); current > old; old = peak.Load() {
			if peak.CompareAndSwap(old, current) {
				break
			}
		}
		defer active.Add(-1)
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	complete := func(err error) {
		if !errors.Is(err, context.Canceled) {
			t.Error("canceled job reported success", err)
		}
		completed.Add(1)
	}
	for _, op := range ops[:2] {
		if err = q.enqueue(ctx, op, "rules", complete); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("workers not started")
		}
	}
	for _, op := range ops[2:4] {
		if err = q.enqueue(ctx, op, "rules", complete); err != nil {
			t.Fatal(err)
		}
	}
	blocked := make(chan error, 1)
	go func() { blocked <- q.enqueue(ctx, ops[4], "rules", complete) }()
	select {
	case err = <-blocked:
		t.Fatal("unbounded producer admission", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err = <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked producer not joined")
	}
	accepted := int32(5)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		accepted = 4
	}
	if err = q.close(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if active.Load() != 0 || peak.Load() != 2 || completed.Load() != accepted {
		t.Fatal("worker/callback leak", active.Load(), peak.Load(), completed.Load(), accepted)
	}
}

func TestSmallBatchQueueWorkerFailureRetainedThroughClose(t *testing.T) {
	ops := queueOriginals(t, 5, 1)
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	failure := errors.New("original outcomes retained")
	var completed atomic.Int32
	q, err := newSmallBatchQueue(ctx, smallBatchQueueLimits{2, 1024, smallBatchMaximumMetadataBytes}, time.Second, func(context.Context, *smallBatchPlan) error { return failure })
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if err = q.enqueue(ctx, op, "rules", func(err error) {
			if !errors.Is(err, failure) {
				t.Error(err)
			}
			completed.Add(1)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = q.flush(ctx); !errors.Is(err, failure) {
		t.Fatal("flush masked failure", err)
	}
	if err = q.close(); !errors.Is(err, failure) {
		t.Fatal("close masked failure", err)
	}
	if completed.Load() != 5 {
		t.Fatal(completed.Load())
	}
}

func TestSmallBatchQueueRejectsInvalidLimitsAndOversizeBeforeOwnership(t *testing.T) {
	ops := queueOriginals(t, 1, 4)
	limits := defaultQueueLimits()
	run := func(context.Context, *smallBatchPlan) error { t.Error("rejected item dispatched"); return nil }
	for _, bad := range []smallBatchQueueLimits{{0, 32, 1024}, {501, 32, 1024}, {1, 0, 1024}, {1, smallBatchMaximumDataBytes + 1, 1024}, {1, 32, 1023}, {1, 32, smallBatchMaximumMetadataBytes + 1}} {
		if _, err := newSmallBatchQueue(testContext, bad, time.Second, run); err == nil {
			t.Fatal("invalid limit", bad)
		}
	}
	if _, err := newSmallBatchQueue(testContext, limits, time.Minute, run); err == nil {
		t.Fatal("invalid age")
	}
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	limits.data = 3
	q, err := newSmallBatchQueue(ctx, limits, time.Second, run)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.enqueue(ctx, ops[0], "rules", func(error) { t.Error("rejected item callback") }); !errors.Is(err, ErrSourceQuota) {
		t.Fatal(err)
	}
	if err = q.close(); err != nil {
		t.Fatal(err)
	}
	if err = q.enqueue(ctx, ops[0], "rules", func(error) {}); err == nil {
		t.Fatal("closed queue accepted")
	}
}
