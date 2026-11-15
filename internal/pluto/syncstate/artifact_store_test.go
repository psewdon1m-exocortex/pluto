package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func artifactFixture(t *testing.T) (*Store, *Artifacts, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err = s.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	a, err := s.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	if report, err := a.Reconcile(testContext, artifactTestReader); err != nil || !report.Admitted {
		t.Fatal(report, err)
	}
	return s, a, dir
}
func artifactTestReader(context.Context) (func(), error) { return func() {}, nil }
func sealedArtifact(t *testing.T, a *Artifacts, content []byte) (*ArtifactReservation, *VerifiedSnapshot) {
	t.Helper()
	r, err := a.Reserve(testContext, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := r.Create(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Chmod(0400); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	v := &VerifiedSnapshot{filename: f.Name(), sealed: info, evidence: SnapshotEvidence{SnapshotID: r.ID(), SizeBytes: int64(len(content)), SHA256: hashBytes(content), GuardDigest: hashBytes([]byte("fixture guard"))}, limiter: newTestCaptureLimiter(), release: func() {}}
	if err = r.SealSnapshot(testContext, v); err != nil {
		t.Fatal(err)
	}
	return r, v
}
func TestArtifactDurableSealRestartAndExplicitDisposal(t *testing.T) {
	s, a, dir := artifactFixture(t)
	r, v := sealedArtifact(t, a, []byte("captured exact bytes"))
	id := r.ID()
	if err := s.Close(); !errors.Is(err, ErrArtifactInUse) {
		t.Fatal("live reference released writer lock", err)
	}
	if err := r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	next, err := reopened.EnableArtifacts(testContext, DefaultArtifactLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := next.Reconcile(testContext, artifactTestReader)
	if err != nil || report.ReservedBytes != int64(len("captured exact bytes")) || !report.Complete || !report.Admitted {
		t.Fatal(report, err)
	}
	if _, err = r.Create(testContext); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale reservation accepted", err)
	}
	if err = next.Dispose(testContext, id); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(v.filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file retained after disposal", err)
	}
	if charge, err := next.Charge(testContext); err != nil || charge != 0 {
		t.Fatal(charge, err)
	}
	if n, err := next.CompactGone(testContext, 128); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}
func TestArtifactUnknownCorruptSubstitutedHardlinkPreserve(t *testing.T) {
	for _, mode := range []string{"unknown", "digest", "missing", "symlink", "hardlink", "directory"} {
		t.Run(mode, func(t *testing.T) {
			_, a, _ := artifactFixture(t)
			r, v := sealedArtifact(t, a, []byte("four"))
			if err := r.Relinquish(); err != nil {
				t.Fatal(err)
			}
			original := v.filename
			switch mode {
			case "unknown":
				os.WriteFile(filepath.Join(a.Directory(), "unknown"), []byte("foreign"), 0600)
			case "digest":
				os.Chmod(original, 0600)
				os.WriteFile(original, []byte("evil"), 0400)
				os.Chmod(original, 0400)
			case "missing":
				os.Remove(original)
			case "symlink":
				os.Remove(original)
				os.Symlink(filepath.Join(t.TempDir(), "outside"), original)
			case "hardlink":
				os.Link(original, filepath.Join(t.TempDir(), "alias"))
			case "directory":
				os.Remove(original)
				os.Mkdir(original, 0700)
			}
			before, _ := os.Lstat(original)
			report, err := a.Reconcile(testContext, artifactTestReader)
			if !errors.Is(err, ErrArtifactUnreconciled) || report.Admitted || len(report.Problems) == 0 {
				t.Fatal(report, err)
			}
			after, _ := os.Lstat(original)
			if before != nil && (after == nil || !os.SameFile(before, after)) {
				t.Fatal("reconcile changed object")
			}
			if _, err = a.Reserve(testContext, 1); !errors.Is(err, ErrArtifactUnreconciled) {
				t.Fatal("work admitted", err)
			}
		})
	}
}
func TestArtifactReservationPrecedesCreateAndIncompleteNotAbsence(t *testing.T) {
	_, a, _ := artifactFixture(t)
	r, err := a.Reserve(testContext, 16)
	if err != nil {
		t.Fatal(err)
	}
	record, err := a.Record(testContext, r.ID())
	if err != nil || record.Phase != ArtifactReserved || record.ExpectedBytes != 16 {
		t.Fatal(record, err)
	}
	if _, err = os.Stat(filepath.Join(a.Directory(), record.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file created before durable reserve", err)
	}
	if err = r.Relinquish(); err != nil {
		t.Fatal(err)
	}
	report, err := a.Reconcile(testContext, artifactTestReader)
	if !errors.Is(err, ErrArtifactUnreconciled) || report.Admitted || report.ReservedBytes != 16 {
		t.Fatal(report, err)
	}
	if err = a.Dispose(testContext, r.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reconcile(testContext, artifactTestReader); err != nil {
		t.Fatal(err)
	}
}
func TestArtifactPartialCrashAndUnknownCreationGapPreserved(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(map[bool]string{false: "creation-gap", true: "partial"}[registered], func(t *testing.T) {
			_, a, _ := artifactFixture(t)
			r, err := a.Reserve(testContext, 10)
			if err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(a.Directory(), r.ID()+".snapshot")
			if registered {
				f, err := r.Create(testContext)
				if err != nil {
					t.Fatal(err)
				}
				f.Write([]byte("par"))
				f.Sync()
				f.Close()
			} else {
				os.WriteFile(filename, []byte("gap"), 0600)
			}
			r.Relinquish()
			report, err := a.Reconcile(testContext, artifactTestReader)
			if !errors.Is(err, ErrArtifactUnreconciled) || report.ReservedBytes != 10 {
				t.Fatal(report, err)
			}
			err = a.Dispose(testContext, r.ID())
			if registered {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					t.Fatal("unknown creation identity guessed")
				}
				if raw, _ := os.ReadFile(filename); string(raw) != "gap" {
					t.Fatal("unknown bytes changed")
				}
			}
		})
	}
}
func TestArtifactPinnedReaderAndJoinedUsers(t *testing.T) {
	s, a, _ := artifactFixture(t)
	r, _ := sealedArtifact(t, a, []byte("reader"))
	entered, leave, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- r.WithReader(testContext, artifactTestReader, func(input io.Reader) error {
			close(entered)
			<-leave
			raw, err := io.ReadAll(input)
			if string(raw) != "reader" {
				return ErrInvalidReceipt
			}
			return err
		})
	}()
	<-entered
	if err := r.Dispose(testContext); !errors.Is(err, ErrArtifactInUse) {
		t.Fatal(err)
	}
	if err := s.Close(); !errors.Is(err, ErrArtifactInUse) {
		t.Fatal(err)
	}
	close(leave)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := r.Dispose(testContext); err != nil {
		t.Fatal(err)
	}
}
func TestArtifactScopeQuotaAndExactPathGuard(t *testing.T) {
	_, a, _ := artifactFixture(t)
	a.limits = ArtifactLimits{Records: 2, PlaintextBytes: 4}
	r, err := a.Reserve(testContext, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reserve(testContext, 1); !errors.Is(err, ErrSourceQuota) {
		t.Fatal(err)
	}
	if err = r.Dispose(testContext); err != nil {
		t.Fatal(err)
	}
	r, err = a.Reserve(testContext, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Dispose(testContext); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reserve(testContext, 0); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("zero-byte records unbounded", err)
	}
	if _, err = a.CompactGone(testContext, 2); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "foreign")
	os.WriteFile(outside, []byte("safe"), 0600)
	r, err = a.Reserve(testContext, 4)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.store.db.Exec("UPDATE local_artifacts SET filename=? WHERE artifact_id=?", outside, r.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Dispose(testContext); err == nil {
		t.Fatal("external path accepted")
	}
	r.Relinquish()
	if bytes, _ := os.ReadFile(outside); string(bytes) != "safe" {
		t.Fatal("outside changed")
	}
}
func TestArtifactNewUnknownAfterBootstrapAndOwnerCAS(t *testing.T) {
	_, a, _ := artifactFixture(t)
	os.WriteFile(filepath.Join(a.path, "new-unknown"), []byte("new"), 0600)
	if _, err := a.Reserve(testContext, 1); !errors.Is(err, ErrArtifactUnreconciled) {
		t.Fatal("changed directory did not close admission", err)
	}
	if _, err := a.store.db.Exec("UPDATE artifact_scope SET owner_id='another-owner'"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Record(testContext, "missing"); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
}
func TestArtifactDirectorySubstitutionNoExternalMutation(t *testing.T) {
	_, a, _ := artifactFixture(t)
	old := a.path + "-old"
	if err := os.Rename(a.path, old); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "foreign")
	os.WriteFile(marker, []byte("safe"), 0600)
	if err := os.Symlink(outside, a.path); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reserve(testContext, 1); err == nil {
		t.Fatal("replaced dir accepted")
	}
	if bytes, _ := os.ReadFile(marker); string(bytes) != "safe" {
		t.Fatal("foreign changed")
	}
}
func TestArtifactQueryUsesPKAndFilenameUniqueIndex(t *testing.T) {
	_, a, _ := artifactFixture(t)
	for _, query := range []string{"SELECT artifact_id FROM local_artifacts WHERE artifact_id>'x' ORDER BY artifact_id LIMIT 128", "SELECT artifact_id,phase FROM local_artifacts WHERE filename='x'"} {
		rows, err := a.store.db.Query("EXPLAIN QUERY PLAN " + query)
		if err != nil {
			t.Fatal(err)
		}
		var details []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			rows.Scan(&id, &parent, &unused, &detail)
			details = append(details, detail)
		}
		rows.Close()
		text := strings.Join(details, " ")
		if !strings.Contains(text, "SEARCH") || strings.Contains(text, "SCAN") || strings.Contains(text, "TEMP B-TREE") {
			t.Fatal(text)
		}
	}
}

var _ = sql.ErrNoRows
