package syncstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRemountBinding(t *testing.T, s *Sources, w SourceWitness, b SourceBinding) {
	t.Helper()
	raw, _ := json.Marshal(b)
	if _, e := s.store.db.Exec("UPDATE source_bindings SET descriptor_json=? WHERE set_id=? AND source_id=?", string(raw), w.SetID, b.ID); e != nil {
		t.Fatal(e)
	}
}
func remountSourceFixture(t *testing.T) (*Sources, SourceWitness, SourceBinding) {
	t.Helper()
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "file"), []byte("one"), 0600); e != nil {
		t.Fatal(e)
	}
	s, w, _ := sourceFixture(t, dir)
	scanSource(t, s, w, "initial", nil)
	b, e := s.Binding(testContext, w.SetID, "source")
	if e != nil || !b.Object.MountKnown {
		t.Fatal("native mount fixture", b, e)
	}
	return s, w, b
}
func freshRemountOwner(t *testing.T, s *Sources, w SourceWitness) SourceWitness {
	t.Helper()
	id, e := NewOperationID()
	if e != nil {
		t.Fatal(e)
	}
	next, e := s.BeginSourceOwner(testContext, w.SetID, w.Revision, id)
	if e != nil {
		t.Fatal(e)
	}
	return next
}
func TestOwnerMountSameNativeReopenDoesNotFabricateContinuity(t *testing.T) {
	s, w, b := remountSourceFixture(t)
	w = freshRemountOwner(t, s, w)
	next, e := s.RequalifyOwnerMounts(testContext, w, []string{"source"})
	if e != nil || next != w {
		t.Fatal(next, e)
	}
	after, _ := s.Binding(testContext, w.SetID, "source")
	if after != b {
		t.Fatal("same mount altered binding", after, b)
	}
	scanSource(t, s, next, "reopened", nil)
	var requests int
	if e = s.store.db.QueryRow("SELECT COUNT(*) FROM source_verification WHERE set_id=?", w.SetID).Scan(&requests); e != nil || requests != 1 {
		t.Fatal("full content work must remain", requests, e)
	}
}
func TestOwnerMountOnlyNativeRequalificationAndRepeatedPending(t *testing.T) {
	for _, repeated := range []bool{false, true} {
		t.Run(fmt.Sprint(repeated), func(t *testing.T) {
			s, w, b := remountSourceFixture(t)
			native, e := ObserveSourceIncarnation(b.PhysicalPath)
			if e != nil {
				t.Fatal(e)
			}
			b.Object.MountID = "900000001"
			writeRemountBinding(t, s, w, b)
			w = freshRemountOwner(t, s, w)
			oldGap := w.GapGeneration
			if repeated {
				oldPending := native
				oldPending.object.MountID = "900000002"
				w, e = s.RecordSourceIncarnation(testContext, w, b.ID, oldPending)
				if !errors.Is(e, ErrSourceIncomplete) {
					t.Fatal(e)
				}
				oldGap = w.GapGeneration
			}
			next, e := s.RequalifyOwnerMounts(testContext, w, []string{b.ID})
			if e != nil || next.GapGeneration != oldGap+1 || next.OwnerID != w.OwnerID {
				t.Fatal(next, w, e)
			}
			after, _ := s.Binding(testContext, w.SetID, b.ID)
			if after.Object != native.object || after.Incarnation != 2 || after.IncarnationStatus != "LOCAL_OBSERVED" || after.PendingObject != (SourceObject{}) {
				t.Fatal(after)
			}
			var gaps int
			if e = s.store.db.QueryRow("SELECT COUNT(*) FROM source_gaps WHERE set_id=?", w.SetID).Scan(&gaps); e != nil || int64(gaps) != next.GapGeneration {
				t.Fatal("gap erased", gaps, next, e)
			}
			if repeated {
				var reason string
				s.store.db.QueryRow("SELECT reason FROM source_gaps WHERE set_id=? AND generation=?", w.SetID, next.GapGeneration).Scan(&reason)
				if !strings.Contains(reason, "old=") || !strings.Contains(reason, "pending=") || !strings.Contains(reason, "new=") {
					t.Fatal(reason)
				}
			}
			scanSource(t, s, next, "fresh-full", nil)
		})
	}
}
func TestOwnerMountRequalificationRefusesChangedRootAndUnknownMount(t *testing.T) {
	for _, kind := range []string{"file", "link", "boot", "mount-unknown", "pending-replacement", "missing", "actual-replacement", "actual-symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, w, b := remountSourceFixture(t)
			b.Object.MountID = "900000001"
			switch kind {
			case "file":
				b.Object.FileIdentity = "other-device:inode:mode"
			case "link":
				b.Object.LinkGuard = "other-link"
			case "boot":
				b.Object.BootIdentity = "other-boot"
			case "mount-unknown":
				b.Object.MountKnown = false
			case "pending-replacement":
				b.PendingObject = b.Object
				b.PendingObject.FileIdentity = "changed"
				b.IncarnationStatus = "UNKNOWN"
			}
			writeRemountBinding(t, s, w, b)
			w = freshRemountOwner(t, s, w)
			if kind == "missing" {
				os.Rename(b.PhysicalPath, b.PhysicalPath+"-old")
			}
			if kind == "actual-replacement" {
				os.Rename(b.PhysicalPath, b.PhysicalPath+"-old")
				os.Mkdir(b.PhysicalPath, 0700)
				os.WriteFile(filepath.Join(b.PhysicalPath, "file"), []byte("two"), 0600)
			}
			if kind == "actual-symlink" {
				os.Rename(b.PhysicalPath, b.PhysicalPath+"-old")
				os.Symlink(b.PhysicalPath+"-old", b.PhysicalPath)
			}
			_, e := s.RequalifyOwnerMounts(testContext, w, []string{b.ID})
			if e == nil {
				t.Fatal("changed root admitted", kind)
			}
			after, _ := s.Binding(testContext, w.SetID, b.ID)
			if after.Incarnation != 1 {
				t.Fatal("replacement accepted", after)
			}
		})
	}
}
func TestOwnerMountRequalificationCASAndObservationChanges(t *testing.T) {
	for _, kind := range []string{"owner", "revision", "gap", "pending", "cancel", "observation", "path"} {
		t.Run(kind, func(t *testing.T) {
			s, w, b := remountSourceFixture(t)
			native, e := ObserveSourceIncarnation(b.PhysicalPath)
			if e != nil {
				t.Fatal(e)
			}
			b.Object.MountID = "900000001"
			b.PendingObject = native.object
			b.PendingObject.MountID = "900000002"
			b.IncarnationStatus = "UNKNOWN"
			writeRemountBinding(t, s, w, b)
			w = freshRemountOwner(t, s, w)
			ctx, cancel := context.WithCancel(testContext)
			defer cancel()
			n := 0
			probe := func(path string) (SourceIncarnationObservation, error) {
				n++
				value, e := ObserveSourceIncarnation(path)
				if n == 1 {
					switch kind {
					case "owner":
						freshRemountOwner(t, s, w)
					case "revision":
						s.store.db.Exec("UPDATE source_sets SET revision=revision+1 WHERE set_id=?", w.SetID)
					case "gap":
						s.RecordSourceGap(testContext, w, "fixture gap")
					case "pending":
						changed := b
						changed.PendingObject.LinkGuard = "changed"
						writeRemountBinding(t, s, w, changed)
					case "cancel":
						cancel()
					}
				}
				if n == 2 && kind == "observation" {
					value.object.MountID = "other"
				}
				if kind == "path" {
					value.physical += "-alias"
				}
				return value, e
			}
			_, e = s.requalifyOwnerMounts(ctx, w, []string{b.ID}, probe)
			if e == nil {
				t.Fatal("stale observation admitted", kind)
			}
			after, _ := s.Binding(testContext, w.SetID, b.ID)
			if after.Incarnation != 1 {
				t.Fatal(after)
			}
		})
	}
}
func TestOwnerMountBoundedWholeSetAdmissionBeforeEffects(t *testing.T) {
	for _, kind := range []string{"oversize", "duplicate", "missing", "descriptor"} {
		t.Run(kind, func(t *testing.T) {
			s, w, _ := remountSourceFixture(t)
			ids := []string{"source"}
			switch kind {
			case "oversize":
				ids = make([]string, MaxSources+1)
			case "duplicate":
				ids = []string{"source", "source"}
			case "missing":
				ids = []string{"other"}
			case "descriptor":
				s.store.db.Exec("UPDATE source_bindings SET descriptor_json=? WHERE set_id=?", strings.Repeat("x", MaxSourcePageBytes+1), w.SetID)
			}
			calls := 0
			_, e := s.requalifyOwnerMounts(testContext, w, ids, func(string) (SourceIncarnationObservation, error) {
				calls++
				return SourceIncarnationObservation{}, nil
			})
			if e == nil || calls != 0 {
				t.Fatal(kind, e, calls)
			}
		})
	}
	dir := t.TempDir()
	s, w, _ := sourceFixture(t, dir)
	specs := make([]SourceSpec, MaxSources)
	ids := make([]string, MaxSources)
	for i := range specs {
		ids[i] = fmt.Sprintf("source-%03d", i)
		specs[i] = SourceSpec{ID: ids[i], SelectedPath: dir, WorkingDirectory: dir}
	}
	set, e := s.BindSourceSet(testContext, w.SetID, hashBytes([]byte("128 sources")), w.Revision, specs)
	if e != nil {
		t.Fatal(e)
	}
	w, e = s.BeginSourceOwner(testContext, set.ID, set.Revision, "owner-128")
	if e != nil {
		t.Fatal(e)
	}
	reads := 0
	next, e := s.requalifyOwnerMounts(testContext, w, ids, func(path string) (SourceIncarnationObservation, error) {
		reads++
		return ObserveSourceIncarnation(path)
	})
	if e != nil || next != w || reads != 256 {
		t.Fatal(next, e, reads)
	}
	t.Logf("bounded configured roots=%d native observations=%d no source-file reads", len(ids), reads)
}

type retainEveryAckSession struct{ *fixtureCapturedSession }

func (s retainEveryAckSession) Publish(ctx context.Context, op Operation, r io.Reader) (CapturedPublication, error) {
	p, e := s.fixtureCapturedSession.Publish(ctx, op, r)
	if e != nil {
		return p, e
	}
	return p, io.ErrUnexpectedEOF
}
func TestOwnerMountFiveOriginalSealsRecoverWithoutRecaptureAndKeepNewDirty(t *testing.T) {
	r, w, session, dir := scanExecutorFixture(t, 5)
	options := scanOptions(t, r, w, session)
	options.Session = retainEveryAckSession{session}
	first, e := r.RunCapturedScan(testContext, options)
	if e == nil || first.Failed != 5 || session.writes.Load() != 5 {
		t.Fatal(first, e)
	}
	originals, e := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if e != nil || len(originals) != 5 {
		t.Fatal(originals, e)
	}
	b, _ := r.sources.Binding(testContext, w.SetID, "source")
	b.Object.MountID = "900000001"
	writeRemountBinding(t, r.sources, w, b)
	w = freshRemountOwner(t, r.sources, w)
	w, e = r.sources.RequalifyOwnerMounts(testContext, w, []string{"source"})
	if e != nil {
		t.Fatal(e)
	}
	// A same-size source edit cannot turn the historical original receipt into
	// evidence for current bytes. Recovery uses its sealed original, then the
	// next complete scan guarded-rehashes the g+1 source.
	file := filepath.Join(dir, "file-0000")
	info, _ := os.Stat(file)
	os.WriteFile(file, []byte("two"), 0600)
	os.Chtimes(file, info.ModTime(), info.ModTime())
	options = scanOptions(t, r, w, session)
	captures := 0
	options.Capture = func(context.Context, SourceWitness, SourceEntry) (*VerifiedSnapshot, error) {
		captures++
		return nil, errors.New("original recovery must not recapture")
	}
	recovered, e := r.RunCapturedScan(testContext, options)
	if e != nil || recovered.Recovered != 5 || recovered.Verified != 0 || captures != 0 || session.writes.Load() != 5 {
		t.Fatal(recovered, e, captures)
	}
	for _, before := range originals {
		after, e := r.store.Operation(testContext, before.OperationID)
		if e != nil || after.Stage != "CLIENT_ACKED" || after.IntentFingerprint != before.IntentFingerprint || after.SealedFingerprint != before.SealedFingerprint || after.SnapshotID != before.SnapshotID {
			t.Fatal(after, e)
		}
		var dirty int
		if e = r.store.db.QueryRow("SELECT COUNT(*) FROM dirty_entries WHERE root_id=? AND entry_id=?", after.RootID, after.EntryID).Scan(&dirty); e != nil || dirty != 1 {
			t.Fatal("historical ACK cleared current dirty", dirty, e)
		}
	}
	fresh, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, session))
	if e != nil || fresh.Verified != 5 || fresh.Uploaded != 1 || fresh.Adopted != 4 {
		t.Fatal("fresh bytes not rehashed", fresh, e)
	}
}
func TestOwnerMountRepeatedPendingTransitionInterruptedTransaction(t *testing.T) {
	s, w, b := remountSourceFixture(t)
	native, _ := ObserveSourceIncarnation(b.PhysicalPath)
	b.Object.MountID = "900000001"
	b.PendingObject = native.object
	b.PendingObject.MountID = "900000002"
	b.IncarnationStatus = "UNKNOWN"
	writeRemountBinding(t, s, w, b)
	w = freshRemountOwner(t, s, w)
	// Exercise the real transaction rollback path through canceled context;
	// unknown pending and incarnation must remain unchanged.
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, e := s.replacePendingOwnerMount(ctx, w, b, native); e == nil {
		t.Fatal("canceled transition committed")
	}
	after, _ := s.Binding(testContext, w.SetID, b.ID)
	if after != b {
		t.Fatal("partial transition", after, b)
	}
	var n int
	s.store.db.QueryRow("SELECT COUNT(*) FROM source_gaps WHERE set_id=? AND generation>?", w.SetID, w.GapGeneration).Scan(&n)
	if n != 0 {
		t.Fatal("partial gap", n)
	}
	// Force a failure after pending/state updates inside the real transaction.
	if _, e := s.store.db.Exec("CREATE TRIGGER remount_fixture_abort BEFORE INSERT ON source_gaps WHEN NEW.reason LIKE 'pre-scan mount re-observation%' BEGIN SELECT RAISE(ABORT,'fixture interrupted pending transition'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.replacePendingOwnerMount(testContext, w, b, native); e == nil {
		t.Fatal("interrupted transaction committed")
	}
	after, _ = s.Binding(testContext, w.SetID, b.ID)
	set, _ := s.Set(testContext, w.SetID)
	if after != b || witness(set) != w || !s.sourceWitnessCurrent(testContext, w) {
		t.Fatal("partial pending/owner/gap after transaction rollback", after, set)
	}
}

func TestOwnerMountMidScanGapStopsJoinedWorkersWithoutRequalification(t *testing.T) {
	r, w, session, _ := scanExecutorFixture(t, 3)
	o := scanOptions(t, r, w, session)
	pages := 0
	o.OnPage = func(FrontierClaim) error {
		pages++
		if pages == 1 {
			_, e := r.sources.RecordSourceGap(testContext, w, "fixture midscan gap")
			return e
		}
		return nil
	}
	report, e := r.RunCapturedScan(testContext, o)
	if e == nil || report.Complete || report.Uploaded != 0 || report.Verified != 0 || session.writes.Load() != 0 {
		t.Fatal(report, e)
	}
	set, _ := r.sources.Set(testContext, w.SetID)
	if set.GapGeneration != w.GapGeneration+1 {
		t.Fatal(set)
	}
	var n int
	r.store.db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&n)
	if n != 0 {
		t.Fatal("effect after gap", n)
	}
}

func TestOwnerMountGapAtCompletedDirectoryEOFStopsWithoutStaleSweeps(t *testing.T) {
	r, w, session, _ := scanExecutorFixture(t, 3)
	o := scanOptions(t, r, w, session)
	pages := 0
	o.OnPage = func(c FrontierClaim) error {
		pages++
		// The real native directory has fewer than128 children. Page1 is
		// its descriptor, page2 the children, and page3 the terminal EOF.
		// CommitScanPage has already committed EOF before this callback.
		if pages == 3 {
			_, e := r.sources.RecordSourceGap(testContext, w, "fixture gap after committed directory EOF")
			return e
		}
		return nil
	}
	report, e := r.RunCapturedScan(testContext, o)
	if pages != 3 || e == nil || report.Complete {
		t.Fatal("fixture did not observe completed-EOF gap", pages, report, e)
	}
	if n := strings.Count(e.Error(), ErrStaleGeneration.Error()); n > 1 {
		t.Fatalf("one source gap cascaded through stale final sweeps: errors=%d report=%+v error=%v", n, report, e)
	}
	if report.SourceGap == nil || report.SourceGap.Current == nil || report.SourceGap.Expected != w || report.SourceGap.Current.GapGeneration != w.GapGeneration+1 || report.SourceGap.Reason != "fixture gap after committed directory EOF" {
		t.Fatal("truthful gap diagnostic missing", report.SourceGap)
	}
	set, _ := r.sources.Set(testContext, w.SetID)
	if set.GapGeneration != w.GapGeneration+1 {
		t.Fatal("gap changed or was accepted", set)
	}
}

// Actual source stat + SQLite + sealed file/transport fixture; the old mount
// number is fixture data. No mount capability, host sysctl or original DB.
func TestSourceMountGapStopsWithoutCascadingStaleSweep(t *testing.T) {
	r, w, session, _ := scanExecutorFixture(t, 2)
	session.lostAck.Store(true)
	first, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, session))
	if e == nil || first.Failed != 1 {
		t.Fatal("lost ACK fixture", first, e)
	}
	var originals []string
	rows, e := r.store.db.Query("SELECT intent_json FROM operations ORDER BY operation_id")
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			t.Fatal(e)
		}
		originals = append(originals, raw)
	}
	rows.Close()
	b, e := r.sources.Binding(testContext, w.SetID, "source")
	if e != nil {
		t.Fatal(e)
	}
	b.Object.MountID = "900000001"
	raw, _ := json.Marshal(b)
	if _, e = r.store.db.Exec("UPDATE source_bindings SET descriptor_json=? WHERE set_id=? AND source_id='source'", string(raw), w.SetID); e != nil {
		t.Fatal(e)
	}
	owner, e := NewOperationID()
	if e != nil {
		t.Fatal(e)
	}
	w, e = r.sources.BeginSourceOwner(testContext, w.SetID, w.Revision, owner)
	if e != nil {
		t.Fatal(e)
	}
	beforeBytes := session.hashBytes.Load()
	result, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, session))
	if e == nil || result.Complete || result.Failed != 1 || strings.Contains(e.Error(), ErrStaleGeneration.Error()) {
		t.Fatalf("gap must stop once without stale sweep: %+v error=%v", result, e)
	}
	if !errors.Is(e, ErrArtifactRetained) && !strings.Contains(e.Error(), ErrSourceIncomplete.Error()) {
		t.Fatal(e)
	}
	if session.hashBytes.Load() != beforeBytes || result.Recovered != 0 || result.Verified != 0 {
		t.Fatal("effects after gap", result)
	}
	rows, e = r.store.db.Query("SELECT intent_json FROM operations ORDER BY operation_id")
	if e != nil {
		t.Fatal(e)
	}
	i := 0
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			t.Fatal(e)
		}
		if i >= len(originals) || raw != originals[i] {
			t.Fatal("immutable intent changed")
		}
		i++
	}
	rows.Close()
	if i != len(originals) {
		t.Fatal("operation replaced")
	}
}
