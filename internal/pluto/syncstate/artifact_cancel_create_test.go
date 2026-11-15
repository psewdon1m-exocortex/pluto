package syncstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactCanceledCreateKeepsIdentityForJoinedCleanup(t *testing.T) {
	for _, point := range []string{"before-create", "created", "registered"} {
		t.Run(point, func(t *testing.T) {
			_, a, _ := artifactFixture(t)
			r, err := a.Reserve(testContext, 33)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(testContext)
			defer cancel()
			a.crashPoint = func(p string) {
				if p == point {
					cancel()
				}
			}
			if point == "before-create" {
				cancel()
			}
			f, err := r.Create(ctx)
			if f != nil {
				defer f.Close()
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			record, err := a.Record(testContext, r.ID())
			if err != nil {
				t.Fatal(err)
			}
			if point != "before-create" {
				if f == nil {
					t.Fatal("created descriptor was lost")
				}
				info, e := f.Stat()
				if e != nil {
					t.Fatal(e)
				}
				if record.Phase != ArtifactCapturing || record.FileIdentity != artifactIdentity(info) {
					t.Fatalf("cancelled create lost durable identity: phase=%s identity=%q", record.Phase, record.FileIdentity)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err = r.Dispose(testContext); err != nil {
				t.Fatalf("joined cancellation cannot dispose own artifact: %v", err)
			}
			if _, err = os.Lstat(filepath.Join(a.Directory(), r.ID()+".snapshot")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if charge, err := a.Charge(testContext); err != nil || charge != 0 {
				t.Fatal(charge, err)
			}
		})
	}
}

func TestArtifactCanceledCreateDoesNotAdoptReplacement(t *testing.T) {
	_, a, _ := artifactFixture(t)
	r, err := a.Reserve(testContext, 33)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	name := filepath.Join(a.Directory(), r.ID()+".snapshot")
	kept := filepath.Join(t.TempDir(), "original")
	a.crashPoint = func(p string) {
		if p != "created" {
			return
		}
		if err := os.Rename(name, kept); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("foreign"), 0600); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
	f, err := r.Create(ctx)
	if f != nil {
		if e := f.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if err == nil {
		t.Fatal("replacement was accepted")
	}
	if err = r.Dispose(testContext); err == nil {
		t.Fatal("foreign object was disposed")
	}
	if err = r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(name); err != nil || string(b) != "foreign" {
		t.Fatal(string(b), err)
	}
	if b, err := os.ReadFile(kept); err != nil || len(b) != 0 {
		t.Fatal(b, err)
	}
	if report, err := a.Reconcile(testContext, artifactTestReader); err == nil || report.Admitted {
		t.Fatal("foreign namespace admitted", report, err)
	}
}
