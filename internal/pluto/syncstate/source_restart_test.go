package syncstate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceReopenCannotReusePersistedOwnerAndReadBeforeCommitCrash(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file"), []byte("one"), 0600)
	s, w, _ := sourceFixture(t, dir)
	s.BeginScan(testContext, w, "source", "interrupted")
	claim, err := s.ClaimScanFrontier(testContext, w, "interrupted")
	if err != nil {
		t.Fatal(err)
	}
	baselineScan, err := s.Scan(testContext, "interrupted")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Dir(s.store.filename)
	if err := s.store.Close(); err != nil {
		t.Fatal(err)
	}
	backup := qualifyClosedFixtureBackup(t, stateDir, []string{dir}, func(restored *Store) {
		module, err := restored.EnableSources(testContext, DefaultSourceLimits())
		if err != nil {
			t.Fatal(err)
		}
		scan, err := module.Scan(testContext, "interrupted")
		if err != nil || scan != baselineScan {
			t.Fatal("restored pre-fault scan differs", scan, baselineScan, err)
		}
	})
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^TestSourceReadBeforeCommitCrashHelper$")
	cmd.Env = append(os.Environ(), "PLUTO_SOURCE_READ_CRASH="+dir)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatal(string(out), err)
	}
	backup.recordActualExit(t, "TestSourceReadBeforeCommitCrashHelper", cmd.Process.Pid, exit.ExitCode())
	reopened, err := Open(testContext, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	module, err := reopened.EnableSources(testContext, DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = module.CommitScanPage(testContext, claim, ScanPage{EOF: true}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("persisted owner reused by a new process/store", err)
	}
	next, err := module.BeginSourceOwner(testContext, w.SetID, w.Revision, "after-crash")
	if err != nil {
		t.Fatal(err)
	}
	if next.GapGeneration != w.GapGeneration+1 {
		t.Fatal(next)
	}
	scan, _ := module.Scan(testContext, "interrupted")
	if scan.Status != "INCOMPLETE" {
		t.Fatal(scan)
	}
	scanSource(t, module, next, "fresh-read", nil)
}
func TestSourceReadBeforeCommitCrashHelper(t *testing.T) {
	dir := os.Getenv("PLUTO_SOURCE_READ_CRASH")
	if dir == "" {
		return
	}
	if _, err := os.ReadFile(filepath.Join(dir, "file")); err != nil {
		t.Fatal(err)
	}
	os.Exit(86)
}
func TestSourceScanCancellationRetainsClaimAndFreshOwnerRecovery(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file"), []byte("one"), 0600)
	s, w, _ := sourceFixture(t, dir)
	s.BeginScan(testContext, w, "source", "cancelled")
	c, _ := s.ClaimScanFrontier(testContext, w, "cancelled")
	stop := errors.New("fixture cancellation after committed page")
	if err := s.ScanClaim(testContext, c, func(FrontierClaim) error { return stop }); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	if err := s.CompleteScanScope(testContext, w, "cancelled"); !errors.Is(err, ErrSourceIncomplete) {
		t.Fatal(err)
	}
	next, err := s.BeginSourceOwner(testContext, w.SetID, w.Revision, "owner2")
	if err != nil {
		t.Fatal(err)
	}
	scanSource(t, s, next, "resumed-with-reread", nil)
}
