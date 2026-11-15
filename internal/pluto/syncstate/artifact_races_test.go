package syncstate

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactLateAckDisposalPreservesNewDirtyAndTrust(t *testing.T) {
	s, a, limiter, v, op := boundArtifactFixture(t)
	if err := a.BindOperation(testContext, limiter.r.ID(), op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := s.Submitted(testContext, op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := v.Retain(); err != nil {
		t.Fatal(err)
	}
	state, _ := s.Entry(testContext, op.RootID, op.EntryID)
	next := state.Local
	next.ExpectedGeneration = state.Local.Generation
	next.SHA256 = hashBytes([]byte("two"))
	next.HashGeneration = state.Local.Generation + 1
	next.MTimeNS++
	capture(t, s, next)
	root, _ := s.Root(testContext, op.RootID)
	if err := s.InvalidateTrust(testContext, op.RootID, root.TrustGeneration); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{OperationID: op.OperationID, RootID: op.RootID, EntryID: op.EntryID, LocalGeneration: op.LocalGeneration, NodeID: "node", Epoch: "epoch", Version: "version", SHA256: op.SHA256, SizeBytes: op.SizeBytes, SealedFingerprint: op.SealedFingerprint, Seq: 1, Published: true, ContentVerified: true}
	if err := s.Ack(testContext, receipt); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Entry(testContext, op.RootID, op.EntryID)
	trustBefore, _ := s.Root(testContext, op.RootID)
	if before.Dirty == nil || before.Local.Generation <= op.LocalGeneration {
		t.Fatal("fixture did not retain newer dirty")
	}
	if err := a.Dispose(testContext, op.SnapshotID); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Entry(testContext, op.RootID, op.EntryID)
	trustAfter, _ := s.Root(testContext, op.RootID)
	if after.Dirty == nil || *before.Dirty != *after.Dirty || trustBefore != trustAfter || before.Local != after.Local {
		t.Fatal("local cleanup erased new observation/trust")
	}
}
func TestArtifactConcurrentUnknownCreationCannotHideBehindOwnMutation(t *testing.T) {
	_, a, _ := artifactFixture(t)
	r, err := a.Reserve(testContext, 4)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(a.Directory(), "unknown-during-create")
	a.crashPoint = func(point string) {
		if point == "created" {
			if err := os.WriteFile(name, []byte("unknown"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	f, err := r.Create(testContext)
	if !errors.Is(err, ErrArtifactUnreconciled) {
		t.Fatal("own directory ctime hid unknown insertion", err)
	}
	if f != nil {
		f.Close()
	}
	if _, err = a.Reserve(testContext, 1); !errors.Is(err, ErrArtifactUnreconciled) {
		t.Fatal("work after unknown", err)
	}
	if raw, _ := os.ReadFile(name); string(raw) != "unknown" {
		t.Fatal("foreign bytes changed")
	}
	r.Relinquish()
}
func TestArtifactScopedReaderDetectsContentMutationAndCancellation(t *testing.T) {
	for _, mode := range []string{"mutate", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			_, a, _ := artifactFixture(t)
			r, v := sealedArtifact(t, a, []byte("original"))
			err := r.WithReader(testContext, artifactTestReader, func(reader io.Reader) error {
				if mode == "cancel" {
					return context.Canceled
				}
				if err := os.Chmod(v.filename, 0600); err != nil {
					return err
				}
				if err := os.WriteFile(v.filename, []byte("modified"), 0400); err != nil {
					return err
				}
				return nil
			})
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrInvalidReceipt) {
				t.Fatal("changed sealed bytes accepted", err)
			}
			if r.users != 0 {
				t.Fatal("reader leaked reference")
			}
			if err = r.Relinquish(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
