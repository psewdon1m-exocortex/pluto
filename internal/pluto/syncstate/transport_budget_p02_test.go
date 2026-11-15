package syncstate

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestP02NegotiatedPipelinePreservesGlobalCapAndCooldown(t *testing.T) {
	b := &transportBudget{target: 1, finishes: map[string]float64{}, paceSlot: make(chan struct{}, 1)}
	b.qualifyPipeline(1)
	if b.target != 1 {
		t.Fatal("unqualified credit")
	}
	b.qualifyPipeline(4)
	a, err := b.acquire(context.Background(), true, 1)
	if err != nil {
		t.Fatal(err)
	}
	c, err := b.acquire(context.Background(), true, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if release, err := b.acquire(ctx, true, 1); err == nil {
		release()
		t.Fatal("third process-wide data credit")
	}
	a()
	c()
	b.failed(io.ErrUnexpectedEOF)
	b.qualifyPipeline(4)
	if b.target != 1 || b.data != 0 || len(b.queue) != 0 {
		t.Fatal("new session bypassed cooldown or leaked credit")
	}
	b.cooldown = time.Now().Add(-time.Second)
	b.qualifyPipeline(2)
	if b.target != 2 {
		t.Fatal("pipeline did not recover after cooldown")
	}
}
