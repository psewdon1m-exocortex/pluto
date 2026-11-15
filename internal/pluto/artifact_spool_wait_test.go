package pluto

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
)

func retainedBudgetFixture(t *testing.T, retained int64) (*copyBudget, string) {
	t.Helper()
	profile := t.TempDir()
	if err := os.Chmod(profile, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(profile, "artifacts")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	b := newCopyBudget(2, 1, 32)
	if err := b.installArtifactOwner("scope", retained, directory); err != nil {
		t.Fatal(err)
	}
	if err := b.completeArtifactBootstrap("scope", retained); err != nil {
		t.Fatal(err)
	}
	return b, directory
}

func TestArtifactRetainedQuotaRefusesWithoutWaitingForImpossibleDisposal(t *testing.T) {
	b, directory := retainedBudgetFixture(t, 31)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := b.reserveSpool(ctx, directory, 2); !errors.Is(err, syncstate.ErrArtifactRetained) {
		t.Fatalf("retained originals cannot make progress in this admission: %v", err)
	}
	if b.retainedBytes != 31 || b.spoolBytes != 0 {
		t.Fatal("refusal lost retained charge")
	}
	if err := b.releaseRetained("scope", 31); err != nil {
		t.Fatal(err)
	}
	if err := b.reserveSpool(context.Background(), directory, 32); err != nil {
		t.Fatal("qualified disposal did not restore admission", err)
	}
	b.releaseSpool(32)
}

func TestArtifactLiveChargeWaitsForActualTerminalDisposition(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(map[bool]string{false: "disposed", true: "retained"}[retain], func(t *testing.T) {
			b, directory := retainedBudgetFixture(t, 0)
			if err := b.reserveSpool(context.Background(), directory, 32); err != nil {
				t.Fatal(err)
			}
			if err := b.retainReservation("scope", 32); err != nil {
				t.Fatal(err)
			}
			if err := b.releaseRetained("scope", 1); !errors.Is(err, syncstate.ErrIdentityConflict) {
				t.Fatal("recovery cannot dispose a live capture", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- b.reserveSpool(ctx, directory, 1) }()
			select {
			case err := <-result:
				t.Fatal("live capture should provide backpressure", err)
			case <-time.After(20 * time.Millisecond):
			}
			if err := b.finishArtifactCapture("scope", 32, retain); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if retain && !errors.Is(err, syncstate.ErrArtifactRetained) || !retain && err != nil {
					t.Fatal("terminal disposition did not wake with the actual budget outcome", err)
				}
			case <-ctx.Done():
				t.Fatal("terminal disposition stranded the waiter")
			}
			if b.liveArtifactBytes != 0 {
				t.Fatal("finished capture stayed live")
			}
			if retain {
				if b.retainedBytes != 32 || b.spoolBytes != 0 {
					t.Fatal("lost durable charge")
				}
				if err := b.releaseRetained("scope", 32); err != nil {
					t.Fatal(err)
				}
			} else {
				b.releaseSpool(1)
			}
			if b.spoolBytes != 0 || b.retainedBytes != 0 {
				t.Fatal("budget not conserved")
			}
		})
	}
}

func TestArtifactZeroByteCaptureStillFitsAFullRetainedBudget(t *testing.T) {
	b, directory := retainedBudgetFixture(t, 32)
	if err := b.reserveSpool(context.Background(), directory, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.retainReservation("scope", 0); err != nil {
		t.Fatal(err)
	}
	if err := b.finishArtifactCapture("scope", 0, false); err != nil {
		t.Fatal(err)
	}
	if b.retainedBytes != 32 || b.liveArtifactBytes != 0 {
		t.Fatal("zero-byte capture changed retained charge")
	}
}
