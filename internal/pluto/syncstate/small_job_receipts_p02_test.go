package syncstate

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestSmallJobP02ReceiptGroupRollbackThenExactReplay(t *testing.T) {
	for _, point := range []string{"http_binding.before_commit", "capture.before_ack"} {
		t.Run(point, func(t *testing.T) {
			d, f, p, _ := dispatchFixtureWithHandler(t, 16, func(f *dispatchHTTPFixture) http.Handler { f.jobProtocol = true; return f })
			job, err := p.asExecutionJob()
			if err != nil {
				t.Fatal(err)
			}
			hits := 0
			r := d.session.r
			r.testPoint = func(value string) error {
				if value == point {
					hits++
					if hits == 16 {
						return context.Canceled
					}
				}
				return nil
			}
			if err = d.dispatch(testContext, job); !errors.Is(err, context.Canceled) {
				t.Fatal("late crash not reached", hits, err)
			}
			r.testPoint = nil
			var bound, acked int
			if err = r.store.db.QueryRow("SELECT count(*) FILTER (WHERE http_binding_json IS NOT NULL),count(*) FILTER (WHERE stage='CLIENT_ACKED') FROM operations WHERE kind='PUT'").Scan(&bound, &acked); err != nil {
				t.Fatal(err)
			}
			if acked != 0 || point == "http_binding.before_commit" && bound != 0 || point == "capture.before_ack" && bound != 16 {
				t.Fatalf("partial receipt transaction: bound%d acked%d", bound, acked)
			}
			before := d.session.Metrics().DataBytes
			if err = d.dispatch(testContext, job); err != nil {
				t.Fatal("exact status replay", err)
			}
			assertDispatchedOriginals(t, d, job, false)
			if d.session.Metrics().DataBytes != before || f.calls["job-execute"] != 1 || f.calls["job-status"] != 1 {
				t.Fatal("recovery resent payload or changed original", f.calls)
			}
		})
	}
}
