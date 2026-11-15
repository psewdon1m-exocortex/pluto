package syncstate

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
)

type countedCaptureLimiter struct {
	CaptureLimiter
	CaptureArtifacts
	reads atomic.Int64
}

func (c *countedCaptureLimiter) AcquireCaptureReader(ctx context.Context) (func(), error) {
	c.reads.Add(1)
	return c.CaptureLimiter.AcquireCaptureReader(ctx)
}

func TestValidatedCaptureOnePrivateReadAndExactBoundaries(t *testing.T) {
	r, w, v, entry, c := capturedRemoteFixture(t)
	key := v.Evidence().Destination
	if e := v.Close(); e != nil {
		t.Fatal(e)
	}
	scanSource(t, r.sources, w, "scope-next", nil)
	source, e := r.sources.SourceEntry(testContext, w.SetID, key)
	if e != nil {
		t.Fatal(e)
	}
	v, e = CaptureGuarded(testContext, w, source, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	if e != nil {
		t.Fatal(e)
	}
	seedCapturedParentBases(t, r, entry, c)
	counter := &countedCaptureLimiter{CaptureLimiter: v.limiter, CaptureArtifacts: v.limiter.(CaptureArtifacts)}
	v.limiter = counter
	e = WithValidatedCapture(testContext, v, func() error {
		if e := r.sources.RecordVerifiedSnapshot(testContext, w, v); e != nil {
			return e
		}
		if e := r.ProjectCapturedEntry(testContext, w, "root", entry, v); e != nil {
			return e
		}
		d, e := r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(c), remoteNow)
		if e != nil {
			return e
		}
		return r.AdoptCaptured(testContext, w, v, fixtureRemoteAuthority(c), d, remoteNow)
	})
	if e != nil || counter.reads.Load() != 1 {
		t.Fatal(e, counter.reads.Load())
	}
	if e = v.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestValidatedCaptureTamperCloseAndNestedScope(t *testing.T) {
	for _, mode := range []string{"bytes-restored-mtime", "replace", "permission", "close"} {
		t.Run(mode, func(t *testing.T) {
			_, _, v, _, _ := capturedRemoteFixture(t)
			e := WithValidatedCapture(testContext, v, func() error {
				if e := WithValidatedCapture(testContext, v, func() error { return nil }); !errors.Is(e, ErrIdentityConflict) {
					t.Fatal("nested", e)
				}
				v.mu.Lock()
				name := v.filename
				info := v.sealed
				v.mu.Unlock()
				switch mode {
				case "bytes-restored-mtime":
					if e := os.Chmod(name, 0600); e != nil {
						return e
					}
					if e := os.WriteFile(name, []byte("two"), 0400); e != nil {
						return e
					}
					if e := os.Chmod(name, 0400); e != nil {
						return e
					}
					if e := os.Chtimes(name, info.ModTime(), info.ModTime()); e != nil {
						return e
					}
				case "replace":
					if e := os.Rename(name, name+".old"); e != nil {
						return e
					}
					if e := os.WriteFile(name, []byte("one"), 0400); e != nil {
						return e
					}
					defer os.Remove(name + ".old")
				case "permission":
					if e := os.Chmod(name, 0600); e != nil {
						return e
					}
				case "close":
					if e := v.Close(); e != nil {
						return e
					}
					if _, e := os.Lstat(name); e != nil {
						t.Fatal("released before joined scope", e)
					}
				}
				v.mu.Lock()
				defer v.mu.Unlock()
				return v.integrity(testContext)
			})
			if !errors.Is(e, ErrInvalidReceipt) {
				t.Fatal(mode, e)
			}
			// Altered registered captures remain unknown; never clean an unverified
			// replacement using the original registry's expected identity.
			if mode == "close" {
				if _, e := os.Lstat(v.filename); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("joined close", e)
				}
			}
		})
	}
}
