package syncstate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

// A packet can be absent while original catalog outcomes remain authoritative.
// Losing that optional packet must not authorize resending any known original.
func TestSmallBatchMissingPacketRecoversAcknowledgedAndBoundOriginals(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 3)
	hits := 0
	d.session.r.testPoint = func(point string) error {
		if point == "capture.before_ack" {
			hits++
			if hits == 2 {
				return context.Canceled
			}
		}
		return nil
	}
	if err := d.dispatch(testContext, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	d.session.r.testPoint = nil
	first, _ := d.session.r.store.Operation(testContext, p.entries[0].original.OperationID)
	second, _ := d.session.r.store.Operation(testContext, p.entries[1].original.OperationID)
	if first.Stage != "CLIENT_ACKED" || second.Stage == "CLIENT_ACKED" || second.HTTPBinding == nil {
		t.Fatal("fixture did not retain mixed original outcomes")
	}
	delete(f.groups, p.id)
	before := d.session.Metrics().DataBytes
	if err := d.dispatch(testContext, p); err != nil {
		t.Fatal(err)
	}
	assertDispatchedOriginals(t, d, p, false)
	if d.session.Metrics().DataBytes != before || f.calls["prepare"] != 1 || f.calls["data"] != 1 || f.calls["status"] != 1 {
		t.Fatal("packet or published originals resent", f.calls)
	}
	after, _ := d.session.r.store.Operation(testContext, second.OperationID)
	if *after.HTTPBinding != *second.HTTPBinding {
		t.Fatal("original HTTP UUID changed")
	}
	record, err := d.native.state.read(testContext, p.id)
	if err != nil || record.Phase != "GONE" {
		t.Fatal("optional packet not retired", err)
	}
}

func TestSmallBatchMissingPacketRejectsInvalidAcknowledgementBeforeFallback(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 2)
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
	delete(f.groups, p.id)
	if _, err := d.session.r.store.db.Exec("UPDATE operations SET receipt_json='{}' WHERE operation_id=?", p.entries[0].original.OperationID); err != nil {
		t.Fatal(err)
	}
	before := f.base.requests["catalog-uploads/inspect"]
	if err := d.dispatch(testContext, p); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("invalid ACK accepted", err)
	}
	if f.base.requests["catalog-uploads/inspect"] != before || f.calls["prepare"] != 1 || f.calls["data"] != 1 {
		t.Fatal("invalid original reached recovery")
	}
	record, err := d.native.state.read(testContext, p.id)
	if err != nil || record.Phase != "ATTEMPTED" {
		t.Fatal("invalid original lost aggregate custody", err)
	}
}

func TestSmallBatchMissingPacketFallbackRequiresExactAuthenticatedMissing(t *testing.T) {
	for _, code := range []int{403, 409, 429} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			d, f, p, _ := dispatchFixtureWithHandler(t, 2, func(f *dispatchHTTPFixture) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/sync/v1/roots/"+f.base.binding.RootID+"/small-batches/status" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(code)
						f.base.json(w, map[string]any{"code": "batch_missing"})
						return
					}
					f.ServeHTTP(w, r)
				})
			})
			if _, err := d.native.build(testContext, p); err != nil {
				t.Fatal(err)
			}
			if err := d.native.withAttempt(testContext, p.id, func(smallBatchRecord, io.ReadSeeker) error { return context.Canceled }); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if err := d.dispatch(testContext, p); err == nil {
				t.Fatal("wrong status accepted")
			}
			if f.calls["prepare"] != 0 || f.calls["data"] != 0 {
				t.Fatal("wrong response retried packet", f.calls)
			}
			record, err := d.native.state.read(testContext, p.id)
			if err != nil || record.Phase != "ATTEMPTED" {
				t.Fatal("custody changed", err)
			}
		})
	}
}
