package syncstate

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

type workClassKey struct{}

func WithWorkClass(ctx context.Context, class string) context.Context {
	if class != "live" && class != "recovery" && class != "bootstrap" {
		class = "live"
	}
	return context.WithValue(ctx, workClassKey{}, class)
}

type transportTicket struct {
	data         bool
	class        string
	cost, finish float64
	queued       time.Time
	ready        chan struct{}
	admitted     bool
}
type TransportPressure struct {
	ActiveData, ActiveMetadata, TargetData, Queued                       int
	PublishedBytes, PublishedOperations, AdmissionWaitMS, RetryResponses int64
	PublishedBytesPerSecond, PublicationLatencyMS                        float64
	CooldownUntil                                                        string
}
type transportBudget struct {
	mu                                            sync.Mutex
	queue                                         []*transportTicket
	finishes                                      map[string]float64
	virtual                                       float64
	data, metadata, target, healthy               int
	publishedBytes, publishedOps, waitMS, retries int64
	throughput, latency, waitEMA                  float64
	cooldown                                      time.Time
	paceSlot                                      chan struct{}
}

// Process owner, never per-root multiplied. Existing copy budgets separately
// retain the stricter two workers, one source reader and 256 MiB spool limits.
var transportResources = &transportBudget{target: 1, finishes: map[string]float64{}, paceSlot: make(chan struct{}, 1)}

// A negotiated stream pipeline can start with two process-wide credits even
// before the first whole file publishes. A recent failure still takes priority;
// opening another root/session cannot reset the adaptive cooldown.
func (b *transportBudget) qualifyPipeline(credits int) {
	if credits < 2 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Now().Before(b.cooldown) {
		return
	}
	b.target = 2
	b.dispatch()
}

func TransportMetrics() TransportPressure {
	b := transportResources
	b.mu.Lock()
	defer b.mu.Unlock()
	stamp := ""
	if time.Now().Before(b.cooldown) {
		stamp = b.cooldown.UTC().Format(time.RFC3339Nano)
	}
	return TransportPressure{b.data, b.metadata, b.target, len(b.queue), b.publishedBytes, b.publishedOps, b.waitMS, b.retries, b.throughput, b.latency, stamp}
}
func (b *transportBudget) dispatch() {
	for {
		selected := -1
		for i, t := range b.queue {
			if t.data && b.data >= b.target || !t.data && b.metadata >= 2 {
				continue
			}
			if selected < 0 || time.Since(t.queued) > 5*time.Second && t.queued.Before(b.queue[selected].queued) || time.Since(b.queue[selected].queued) <= 5*time.Second && t.finish < b.queue[selected].finish {
				selected = i
			}
		}
		if selected < 0 {
			return
		}
		t := b.queue[selected]
		b.queue = append(b.queue[:selected], b.queue[selected+1:]...)
		t.admitted = true
		b.virtual = max(b.virtual, t.finish)
		if t.data {
			b.data++
		} else {
			b.metadata++
		}
		wait := float64(time.Since(t.queued).Milliseconds())
		b.waitMS += int64(wait)
		b.waitEMA = .8*b.waitEMA + .2*wait
		close(t.ready)
	}
}
func (b *transportBudget) acquire(ctx context.Context, data bool, bytes int64) (func(), error) {
	class, _ := ctx.Value(workClassKey{}).(string)
	if class == "" {
		class = "live"
	}
	weight := 1.
	if class == "live" {
		weight = 4
	} else if class == "recovery" {
		weight = 2
	}
	b.mu.Lock()
	if len(b.queue) >= 64 {
		b.mu.Unlock()
		return nil, ErrSourceQuota
	}
	cost := float64(max(bytes, 4096)) / weight
	finish := max(b.virtual, b.finishes[class]) + cost
	b.finishes[class] = finish
	ticket := &transportTicket{data: data, class: class, cost: cost, finish: finish, queued: time.Now(), ready: make(chan struct{})}
	b.queue = append(b.queue, ticket)
	b.dispatch()
	b.mu.Unlock()
	select {
	case <-ticket.ready:
	case <-ctx.Done():
		b.mu.Lock()
		if ticket.admitted {
			if data {
				b.data--
			} else {
				b.metadata--
			}
		} else {
			for i, t := range b.queue {
				if t == ticket {
					b.queue = append(b.queue[:i], b.queue[i+1:]...)
					break
				}
			}
		}
		b.dispatch()
		b.mu.Unlock()
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			if data {
				b.data--
			} else {
				b.metadata--
			}
			b.dispatch()
			b.mu.Unlock()
		})
	}, nil
}
func (b *transportBudget) pace(ctx context.Context, bytes, limit int64) error {
	if limit == 0 || bytes == 0 {
		return nil
	}
	if limit < 1 || limit > 1<<40 || bytes < 0 || bytes > MaxFileBytes {
		return ErrSourceQuota
	}
	select {
	case b.paceSlot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-b.paceSlot }()
	timer := time.NewTimer(time.Duration(math.Ceil(float64(bytes) * float64(time.Second) / float64(limit))))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func maxTime(a, c time.Time) time.Time {
	if a.After(c) {
		return a
	}
	return c
}
func (b *transportBudget) failed(err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	if _, retry := RetryClass(err); !retry {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.target = 1
	b.healthy = 0
	b.retries++
	b.cooldown = time.Now().Add(30 * time.Second)
}
func RecordPublication(bytes int64, elapsed time.Duration) {
	recordPublications(bytes, 1, elapsed)
}
func recordPublications(bytes, count int64, elapsed time.Duration) {
	if bytes < 0 || elapsed <= 0 {
		return
	}
	b := transportResources
	b.mu.Lock()
	defer b.mu.Unlock()
	b.publishedBytes += bytes
	b.publishedOps += count
	rate := float64(bytes) / elapsed.Seconds()
	latency := float64(elapsed.Milliseconds())
	prior := b.throughput
	if prior == 0 {
		b.throughput = rate
		b.latency = latency
	} else {
		b.throughput = .8*b.throughput + .2*rate
		b.latency = .8*b.latency + .2*latency
	}
	if time.Now().Before(b.cooldown) {
		return
	}
	if prior > 0 && rate < prior*.5 && latency > b.latency*1.5 {
		b.target = 1
		b.healthy = 0
		b.cooldown = time.Now().Add(30 * time.Second)
		return
	}
	b.healthy++
	if b.healthy >= 8 && b.waitEMA < 1000 && rate >= prior*.8 {
		b.target = min(2, b.target+1)
		b.healthy = 0
		b.cooldown = time.Now().Add(30 * time.Second)
		b.dispatch()
	}
}
