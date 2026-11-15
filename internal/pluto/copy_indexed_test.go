package pluto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
)

type unqualifiedIndexedSession struct{ calls int }

func (s *unqualifiedIndexedSession) Authority(context.Context) (*syncstate.RemoteAuthority, error) {
	return nil, nil
}
func (s *unqualifiedIndexedSession) Publish(context.Context, syncstate.Operation, io.Reader) (syncstate.CapturedPublication, error) {
	s.calls++
	return syncstate.CapturedPublication{}, syncstate.ErrRemoteUnqualified
}
func (s *unqualifiedIndexedSession) Recover(context.Context, syncstate.Operation) (*syncstate.CapturedPublication, error) {
	s.calls++
	return nil, syncstate.ErrRemoteUnqualified
}

func TestCopyIndexedActualAdmissionDefaultAuthorityAndCleanup(t *testing.T) {
	store, a, _, entry := admissionFixture(t)
	sources, err := store.EnableSources(context.Background(), syncstate.DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("fixture authoritative config"))
	digest := hex.EncodeToString(h[:])
	set, err := sources.BindSourceSet(context.Background(), "fixture-set", digest, 0, []syncstate.SourceSpec{{ID: "source", SelectedPath: entry.SourceRootPath}})
	if err != nil {
		t.Fatal(err)
	}
	w, err := sources.BeginSourceOwner(context.Background(), set.ID, set.Revision, "fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindRoot(context.Background(), syncstate.RootBinding{RootID: "root", MappingID: "mapping", ServerIdentity: "fixture-server", RemoteRootID: "fixture-remote-root", DeviceID: "fixture-device", SourceIdentity: set.ID}); err != nil {
		t.Fatal(err)
	}
	if err = sources.AttachSourceSet(context.Background(), set.ID, set.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	r, err := store.EnableRemoteImport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := &unqualifiedIndexedSession{}
	spool := filepath.Join(filepath.Dir(a.registry.Directory()), "spool")
	if _, err = os.Stat(spool); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture must exercise fresh absent spool", err)
	}
	metricsBefore := syncstate.CaptureMetricSnapshot()
	report, err := CopyIndexed(context.Background(), r, a, syncstate.CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Session: s})
	if err == nil || report.Observed != 1 || report.Verified != 1 || report.Failed != 1 || s.calls != 0 {
		t.Fatal("unqualified root or streaming adapter bypass", report, err, s.calls)
	}
	metrics := syncstate.CaptureMetricSnapshot().Since(metricsBefore)
	if metrics.PrivateVerificationReads != 1 || metrics.PrivateVerificationBytes != entry.SizeBytes {
		t.Fatal("sealing and use must share one verified private descriptor", metrics)
	}
	entries, err := os.ReadDir(spool)
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary metadata leaked", entries, err)
	}
	charge, err := a.registry.Charge(context.Background())
	if err != nil || charge != 0 {
		t.Fatal(charge, err)
	}
	if len(copyResources.enumerators) != 0 || len(copyResources.workers) != 0 || len(copyResources.readers) != 0 || copyResources.retainedBytes != 0 || copyResources.metadataBytes != 0 {
		t.Fatal("shared limits leaked")
	}
	root, err := store.Root(context.Background(), "root")
	if err != nil || root.EngineReady {
		t.Fatal("shape became readiness", root, err)
	}
	// Enumeration admission is the actual legacy process-wide single slot.
	if err = copyResources.acquireEnumeration(context.Background(), spool, copyMetadataDatabaseBytes); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, err = CopyIndexed(ctx, r, a, syncstate.CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Session: s})
	cancel()
	copyResources.releaseEnumeration()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("independent enumerator admitted", err)
	}
}
