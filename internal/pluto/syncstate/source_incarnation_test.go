package syncstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceIncarnationReplacementRequiresExplicitReconciliation(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "source")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "file"), []byte("one"), 0600)
	s, w, _ := sourceFixture(t, dir)
	scanSource(t, s, w, "first", nil)
	binding, _ := s.Binding(testContext, w.SetID, "source")
	if binding.Incarnation != 1 || binding.Object.BootIdentity == "" || binding.IncarnationStatus != "LOCAL_OBSERVED" {
		t.Fatal(binding)
	}
	// Keep the old inode alive at another path so the replacement cannot reuse it.
	os.Rename(dir, dir+"-old")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "file"), []byte("two"), 0600)
	if _, err := s.BeginScan(testContext, w, "source", "changed"); err != nil {
		t.Fatal(err)
	}
	c, _ := s.ClaimScanFrontier(testContext, w, "changed")
	if err := s.ScanClaim(testContext, c, nil); !errors.Is(err, ErrSourceIncomplete) {
		t.Fatal("replacement silently accepted", err)
	}
	set, _ := s.Set(testContext, w.SetID)
	next := witness(set)
	if next.GapGeneration != w.GapGeneration+1 {
		t.Fatal(next)
	}
	binding, _ = s.Binding(testContext, w.SetID, "source")
	if binding.IncarnationStatus != "UNKNOWN" || binding.Incarnation != 1 {
		t.Fatal(binding)
	}
	observation, err := ObserveSourceIncarnation(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AcceptSourceIncarnation(testContext, w, "source", 1, observation); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("old gap reconciled", err)
	}
	if err = s.AcceptSourceIncarnation(testContext, next, "source", 1, SourceIncarnationObservation{}); err == nil {
		t.Fatal("fabricated incarnation accepted")
	}
	if err = s.AcceptSourceIncarnation(testContext, next, "source", 1, observation); err != nil {
		t.Fatal(err)
	}
	scanSource(t, s, next, "reconciled-local", nil)
	binding, _ = s.Binding(testContext, w.SetID, "source")
	if binding.Incarnation != 2 || binding.IncarnationStatus != "LOCAL_OBSERVED" {
		t.Fatal(binding)
	}
}
