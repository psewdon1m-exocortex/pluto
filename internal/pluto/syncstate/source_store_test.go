package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func sourceFixture(t *testing.T, path string) (*Sources, SourceWitness, SourceBinding) {
	t.Helper()
	store, err := Open(testContext, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sources, err := store.EnableSources(testContext, DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	set, err := sources.BindSourceSet(testContext, "source-set", hashBytes([]byte("config")), 0, []SourceSpec{{ID: "source", SelectedPath: path}})
	if err != nil {
		t.Fatal(err)
	}
	w, err := sources.BeginSourceOwner(testContext, set.ID, set.Revision, "owner1")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sources.Binding(testContext, set.ID, "source")
	if err != nil {
		t.Fatal(err)
	}
	return sources, w, binding
}
func scanSource(t *testing.T, s *Sources, w SourceWitness, id string, onPage func(FrontierClaim) error) {
	t.Helper()
	if _, err := s.BeginScan(testContext, w, "source", id); err != nil {
		t.Fatal(err)
	}
	for {
		c, err := s.ClaimScanFrontier(testContext, w, id)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = s.ScanClaim(testContext, c, onPage); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CompleteScanScope(testContext, w, id); err != nil {
		t.Fatal(err)
	}
}

func TestSourceModuleLocalBeforeHandshakeAndAttachment(t *testing.T) {
	source := t.TempDir()
	s, w, b := sourceFixture(t, source)
	var n int
	if err := s.store.db.QueryRow("SELECT COUNT(*) FROM roots").Scan(&n); err != nil || n != 0 {
		t.Fatal("fabricated remote root", n, err)
	}
	set, _ := s.Set(testContext, w.SetID)
	if set.AttachedRootID != "" {
		t.Fatal(set)
	}
	binding := testBinding
	binding.SourceIdentity = w.SetID
	if err := s.store.BindRoot(testContext, binding); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachSourceSet(testContext, w.SetID, w.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	rootBefore, _ := s.store.Root(testContext, "root")
	next, err := s.RecordSourceGap(testContext, w, "read page lost before commit")
	if err != nil {
		t.Fatal(err)
	}
	rootAfter, _ := s.store.Root(testContext, "root")
	if rootBefore != rootAfter || rootAfter.EngineReady || next.GapGeneration != w.GapGeneration+1 {
		t.Fatal("gap rotated remote trust", rootBefore, rootAfter, next)
	}
	if b.Destination != sourceDestination(source) {
		t.Fatal("legacy mapping changed", b)
	}
}
func TestSourceBindingBoundsVirtualPrefixesAndRevision(t *testing.T) {
	s, w, _ := sourceFixture(t, t.TempDir())
	before, _ := s.Set(testContext, w.SetID)
	specs := make([]SourceSpec, 129)
	for i := range specs {
		specs[i] = SourceSpec{ID: fmt.Sprintf("s%d", i), SelectedPath: fmt.Sprintf("/synthetic/%d/a", i)}
	}
	if _, err := s.BindSourceSet(testContext, w.SetID, hashBytes([]byte("bad")), w.Revision, specs); err == nil {
		t.Fatal("129 admitted")
	}
	after, _ := s.Set(testContext, w.SetID)
	if before != after {
		t.Fatal("rejected projection changed state")
	}
	specs = specs[:128]
	set, err := s.BindSourceSet(testContext, w.SetID, hashBytes([]byte("new")), w.Revision, specs)
	if err != nil {
		t.Fatal(err)
	}
	if set.ID != before.ID || set.Revision != before.Revision+1 {
		t.Fatal(set)
	}
	newWitness, err := s.BeginSourceOwner(testContext, set.ID, set.Revision, "owner2")
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		if err = s.PrepareSourcePrefixes(testContext, newWitness, spec.ID); err != nil {
			t.Fatal(err)
		}
	}
	var prefixes int
	if err = s.store.db.QueryRow("SELECT COUNT(*) FROM source_prefixes WHERE set_id=? AND destination='synthetic'", set.ID).Scan(&prefixes); err != nil || prefixes != 128 {
		t.Fatal(prefixes, err)
	}
	if _, err = s.BeginScan(testContext, w, "source", "old-revision"); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale revision accepted", err)
	}
	if _, err = s.BindSourceSet(testContext, "contains-state", hashBytes(nil), 0, []SourceSpec{{ID: "s", SelectedPath: filepath.Dir(s.store.filename)}}); err == nil {
		t.Fatal("state self-source silently accepted")
	}
}
func TestSourceOwnerGapStaleClaimAndNoAbsence(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	s, w, _ := sourceFixture(t, source)
	if _, err := s.BeginScan(testContext, w, "source", "scan"); err != nil {
		t.Fatal(err)
	}
	c, err := s.ClaimScanFrontier(testContext, w, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteScanScope(testContext, w, "scan"); !errors.Is(err, ErrSourceIncomplete) {
		t.Fatal(err)
	}
	newOwner, err := s.BeginSourceOwner(testContext, w.SetID, w.Revision, "owner2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CommitScanPage(testContext, c, ScanPage{EOF: true}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("late claim committed", err)
	}
	scan, _ := s.Scan(testContext, "scan")
	if scan.Status != "INCOMPLETE" {
		t.Fatal(scan)
	}
	scanSource(t, s, newOwner, "healthy", nil)
	entry, err := s.SourceEntry(testContext, w.SetID, sourceDestination(filepath.Join(source, "file")))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BeginScan(testContext, newOwner, "source", "missing"); err != nil {
		t.Fatal(err)
	}
	c, _ = s.ClaimScanFrontier(testContext, newOwner, "missing")
	if err = s.ScanClaim(testContext, c, nil); err == nil {
		t.Fatal("missing source successful")
	}
	after, _ := s.SourceEntry(testContext, w.SetID, entry.Destination)
	if after.Presence != "PRESENT" || after.Generation != entry.Generation {
		t.Fatal("incomplete treated as absent", after)
	}
	if err = s.CompleteScanScope(testContext, newOwner, "missing"); !errors.Is(err, ErrSourceIncomplete) {
		t.Fatal(err)
	}
}
func TestSourceScanPageAtomicityCASAndCancellation(t *testing.T) {
	s, w, b := sourceFixture(t, "/synthetic")
	s.BeginScan(testContext, w, "source", "scan")
	c, _ := s.ClaimScanFrontier(testContext, w, "scan")
	d := SourceDescriptor{Destination: b.Destination + "/one", PhysicalPath: b.PhysicalPath + "/one", Kind: "file", Presence: "PRESENT", FileIdentity: "fixture", SizeBytes: 3}
	broken := d
	broken.Destination = b.Destination + "/two"
	broken.PhysicalPath = b.PhysicalPath + "/two"
	broken.ExpectedGeneration = 9
	if _, err := s.CommitScanPage(testContext, c, ScanPage{Entries: []SourceDescriptor{d, broken}, EOF: true}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	if _, err := s.SourceEntry(testContext, w.SetID, d.Destination); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("partial transaction persisted", err)
	}
	var wg sync.WaitGroup
	successes := make(chan bool, 2)
	for range 2 {
		wg.Go(func() {
			_, err := s.CommitScanPage(testContext, c, ScanPage{Entries: []SourceDescriptor{d}, EOF: true})
			successes <- err == nil
		})
	}
	wg.Wait()
	close(successes)
	n := 0
	for ok := range successes {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatal("claim was consumed twice", n)
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err := s.BeginScan(ctx, w, "source", "cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.CompleteScanScope(testContext, w, "scan"); err != nil {
		t.Fatal(err)
	}
}
func TestSourceOverlapDuplicateRelativeMappingAndNoInodeCollapse(t *testing.T) {
	s, w, _ := sourceFixture(t, "/same")
	set, err := s.BindSourceSet(testContext, w.SetID, hashBytes([]byte("overlap")), w.Revision, []SourceSpec{{ID: "absolute", SelectedPath: "/same"}, {ID: "relative", SelectedPath: "same", WorkingDirectory: "/other"}, {ID: "duplicate", SelectedPath: "/same"}})
	if err != nil {
		t.Fatal(err)
	}
	w, err = s.BeginSourceOwner(testContext, set.ID, set.Revision, "owner2")
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"absolute", "duplicate", "relative"} {
		scan := fmt.Sprintf("scan%d", i)
		s.BeginScan(testContext, w, id, scan)
		c, _ := s.ClaimScanFrontier(testContext, w, scan)
		var g int64
		if old, e := s.SourceEntry(testContext, w.SetID, c.Destination); e == nil {
			g = old.Generation
		}
		identity := "inode1"
		if id == "relative" {
			identity = "inode2"
		}
		_, err = s.CommitScanPage(testContext, c, ScanPage{Entries: []SourceDescriptor{{Destination: c.Destination, PhysicalPath: c.PhysicalPath, Kind: "file", Presence: "PRESENT", FileIdentity: identity, ExpectedGeneration: g}}, EOF: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	entry, err := s.SourceEntry(testContext, w.SetID, "same")
	if err != nil || !entry.Ambiguous {
		t.Fatal("alias collision guessed", entry, err)
	}
	var memberships int
	s.store.db.QueryRow("SELECT COUNT(*) FROM source_membership WHERE set_id=? AND destination='same'", w.SetID).Scan(&memberships)
	if memberships != 3 {
		t.Fatal(memberships)
	}
}
func TestSourceRealHardlinkAliasDoesNotMergeDifferentBindings(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(first, "file"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(first, "file"), filepath.Join(second, "file")); err != nil {
		t.Fatal(err)
	}
	s, w, _ := sourceFixture(t, first)
	set, err := s.BindSourceSet(testContext, w.SetID, hashBytes([]byte("hardlink-bindings")), w.Revision, []SourceSpec{{ID: "first", SelectedPath: "file", WorkingDirectory: first}, {ID: "second", SelectedPath: "file", WorkingDirectory: second}})
	if err != nil {
		t.Fatal(err)
	}
	w, err = s.BeginSourceOwner(testContext, set.ID, set.Revision, "new-owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second"} {
		if _, err = s.BeginScan(testContext, w, id, id); err != nil {
			t.Fatal(err)
		}
		claim, err := s.ClaimScanFrontier(testContext, w, id)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.ScanClaim(testContext, claim, nil); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := s.SourceEntry(testContext, w.SetID, "file")
	if err != nil || !entry.Ambiguous {
		t.Fatal("inode silently collapsed different bindings", entry, err)
	}
	if _, err = CaptureGuarded(testContext, w, entry, t.TempDir(), newTestCaptureLimiter()); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("ambiguous hardlink capture", err)
	}
}
