package syncstate

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestEnduranceExpiredRecoveryStartRetainsPublicationOriginals(t *testing.T) {
	for _, route := range []string{"snapshots/start", "snapshots/step", "snapshots/ready"} {
		t.Run(route, func(t *testing.T) {
			for _, repeated := range []bool{false, true} {
				t.Run(map[bool]string{false: "recover", true: "bounded-repeated-expiry"}[repeated], func(t *testing.T) {
					r, _, w, s, g, _ := rebootstrapFixture(t, 1)
					g.f.lostPrepare = true
					if report, err := runActualHTTPFixture(t, r, w, s); err == nil || report.Failed != 1 {
						t.Fatal(report, err)
					}
					digest := retainedRecoveryDigest(t, r)
					r.testPoint = func(point string) error {
						if point == "http_rebootstrap.after_commit" {
							return context.Canceled
						}
						return nil
					}
					g.expire = 1
					if err := s.Refresh(testContext); err == nil {
						t.Fatal("checkpoint interruption missed")
					}
					before, err := r.Candidate(testContext, "root")
					if err != nil || before.HTTPRebootstrap == nil {
						t.Fatal(before, err)
					}
					r.testPoint = nil
					g.expireStarts = 1
					g.expireReadPath = route
					if repeated {
						g.expireStarts = 2
					}
					s.Close()
					next := rebootstrapSession(t, r, s, s.origin, nil)
					err = next.InitializeRemote(testContext)
					if repeated {
						if !errors.Is(err, ErrHTTPRebootstrapLimit) {
							t.Fatalf("unbounded or unclassified recovery: %v", err)
						}
						current, _ := r.Candidate(testContext, "root")
						if current.Valid || current.HTTPRebootstrap == nil {
							t.Fatal("expired replacement became authority")
						}
						if _, err = next.Authority(testContext); err == nil {
							t.Fatal("expired authority admitted")
						}
					} else if err != nil {
						t.Fatal(err)
					}
					if len(g.starts) != 2 || g.starts[0] != before.HTTPRebootstrap.SnapshotID || g.starts[0] == g.starts[1] {
						t.Fatalf("expected bounded read UUID retirement, got %v", g.starts)
					}
					if digest != retainedRecoveryDigest(t, r) {
						t.Fatal("read recovery changed original operations/B/artifacts/debt")
					}
					if repeated {
						next.Close()
						next = rebootstrapSession(t, r, s, s.origin, nil)
						if err = next.InitializeRemote(testContext); err != nil {
							t.Fatal("restart should reuse retained replacement", err)
						}
						if g.starts[2] != g.starts[1] {
							t.Fatal("restart reminted read UUID without expiry proof")
						}
					}
					if report, err := runActualHTTPFixture(t, r, w, next); err != nil || report.Recovered != 1 {
						t.Fatal(report, err)
					}
				})
			}
		})
	}
}

func TestEnduranceRecoveryReadRetirementRejectsAmbiguityAndPreparedPages(t *testing.T) {
	for _, mode := range []string{"lost-response", "wrong-path", "wrong-binding", "wrong-pin", "prepared", "crash-before-commit"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, s, _, _ := rebootstrapFixture(t, 1)
			c, err := r.Candidate(testContext, "root")
			if err != nil {
				t.Fatal(err)
			}
			c, err = s.beginHTTPRebootstrap(testContext, c, s.httpFailure(410, "changes", "application/json", []byte(`{"code":"cursor_expired"}`)))
			if err != nil {
				t.Fatal(err)
			}
			failure := &guardedHTTPFailure{status: 410, code: "cursor_expired", path: "snapshots/start", binding: s.binding, transportPin: s.transportPin}
			var cause error = failure
			switch mode {
			case "lost-response":
				cause = context.DeadlineExceeded
			case "wrong-path":
				failure.path = "entries"
			case "wrong-binding":
				failure.binding.ServerEpoch = remoteVersion(999)
			case "wrong-pin":
				failure.transportPin = hashBytes([]byte("other transport"))
			case "prepared":
				if _, err = s.startRebootstrapSnapshot(testContext, c, *c.HTTPRebootstrap); err != nil {
					t.Fatal(err)
				}
			case "crash-before-commit":
				r.testPoint = func(p string) error {
					if p == "http_rebootstrap.retire_expired_before_commit" {
						return context.Canceled
					}
					return nil
				}
			}
			digest := retainedRecoveryDigest(t, r)
			if _, err = s.retireExpiredRecoveryStart(testContext, c, cause); err == nil {
				t.Fatal("unsafe read retirement")
			}
			after, _ := r.Candidate(testContext, "root")
			if !reflect.DeepEqual(after, c) || digest != retainedRecoveryDigest(t, r) {
				t.Fatal("rejected retirement changed retained state")
			}
		})
	}
}
