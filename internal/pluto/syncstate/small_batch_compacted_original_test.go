package syncstate

import (
	"context"
	"errors"
	"testing"
)

// A normal independent original recovery can ACK/dispose/compact the members
// while its optional packet is still ATTEMPTED. Resume must not re-delete them.
func TestSmallBatchResumeAfterOriginalArtifactsCompacted(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "packet-present", true: "packet-missing"}[missing], func(t *testing.T) {
			d, f, p, _ := dispatchFixture(t, 3)
			d.session.r.testPoint = func(point string) error {
				if point == "small_batch.after_outcomes" {
					return context.Canceled
				}
				return nil
			}
			if err := d.dispatch(testContext, p); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			d.session.r.testPoint = nil
			for _, entry := range p.entries {
				op, err := d.session.r.store.Operation(testContext, entry.original.OperationID)
				if err != nil || op.Stage != "CLIENT_ACKED" {
					t.Fatal("fixture not ACKed", err)
				}
				if err = d.session.r.store.artifacts.Dispose(testContext, op.SnapshotID); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := d.session.r.store.artifacts.CompactGone(testContext, 128); err != nil || n != 3 {
				t.Fatal("fixture did not compact originals", n, err)
			}
			if missing {
				delete(f.groups, p.id)
			}
			before := d.session.Metrics().DataBytes
			if err := d.dispatch(testContext, p); err != nil {
				t.Fatal("durable ACK and compacted artifact must resume", err)
			}
			assertDispatchedOriginals(t, d, p, false)
			if d.session.Metrics().DataBytes != before || f.calls["prepare"] != 1 || f.calls["data"] != 1 {
				t.Fatal("compacted originals resent", f.calls)
			}
			record, err := d.native.state.read(testContext, p.id)
			if err != nil || record.Phase != "GONE" {
				t.Fatal("packet custody did not retire", err)
			}
		})
	}
}
