package syncstate

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type smallBatchQueueLimits struct {
	items          int
	data, metadata int64
}
type smallBatchQueueItem struct {
	original           Operation
	rules              string
	complete           func(error)
	metadata, retained int64
	key                smallBatchQueueKey
	destination        [2]string
}
type smallBatchQueueKey struct {
	root, rules string
	transport   CapturedHTTPIdentity
}
type smallBatchQueueMessage struct {
	item  *smallBatchQueueItem
	final bool
	reply chan error
}
type smallBatchQueueWork struct {
	items []smallBatchQueueItem
	plan  *smallBatchPlan
}

// The producer must release source/capture scopes before enqueue. At most two
// workers, two queued groups and one current group retain bounded metadata.
// Backpressure waits at admission without accumulating file descriptors.
type smallBatchQueue struct {
	ctx            context.Context
	limits         smallBatchQueueLimits
	age            time.Duration
	commands       chan smallBatchQueueMessage
	jobs           chan smallBatchQueueWork
	done           chan struct{}
	workers, tasks sync.WaitGroup
	run            func(context.Context, *smallBatchPlan) error
	mu             sync.Mutex
	firstError     error
	sameParent     bool
}

func newSmallBatchQueue(ctx context.Context, limits smallBatchQueueLimits, age time.Duration, run func(context.Context, *smallBatchPlan) error, capabilities ...*smallBatchCapability) (*smallBatchQueue, error) {
	if ctx == nil || run == nil || limits.items < 1 || limits.items > smallBatchMaximumItems || limits.data < 1 || limits.data > smallBatchMaximumDataBytes || limits.metadata < 1024 || limits.metadata > smallBatchMaximumMetadataBytes || age != 250*time.Millisecond && age != time.Second {
		return nil, ErrSourceQuota
	}
	q := &smallBatchQueue{ctx: ctx, limits: limits, age: age, commands: make(chan smallBatchQueueMessage), jobs: make(chan smallBatchQueueWork, 2), done: make(chan struct{}), run: run}
	workers := 2
	if len(capabilities) > 1 {
		return nil, ErrIdentityConflict
	}
	if len(capabilities) == 1 && capabilities[0] != nil && capabilities[0].executionJob {
		workers = capabilities[0].jobs
		if workers < 1 || workers > 2 {
			return nil, ErrSourceQuota
		}
		q.sameParent = true
	}
	for range workers {
		q.workers.Add(1)
		go func() {
			defer q.workers.Done()
			for work := range q.jobs {
				err := q.ctx.Err()
				if err == nil {
					err = q.run(q.ctx, work.plan)
				}
				q.finish(work.items, err)
				q.tasks.Done()
			}
		}()
	}
	go q.collect()
	return q, nil
}

func (q *smallBatchQueue) finish(items []smallBatchQueueItem, err error) {
	if err != nil {
		q.mu.Lock()
		if q.firstError == nil {
			q.firstError = err
		}
		q.mu.Unlock()
	}
	for _, item := range items {
		item.complete(err)
	}
}
func (q *smallBatchQueue) result() error { q.mu.Lock(); defer q.mu.Unlock(); return q.firstError }

func (q *smallBatchQueue) enqueue(ctx context.Context, original Operation, rules string, complete func(error)) error {
	if complete == nil || original.Stage != "SUBMITTED" {
		return ErrIdentityConflict
	}
	// Single-item construction validates and deeply freezes caller-owned proof.
	p, err := newSmallBatchPlan("queue-candidate", rules, []Operation{original})
	if err != nil {
		return err
	}
	raw, err := p.prepareBytes()
	if err != nil {
		return err
	}
	op := p.entries[0].original
	retained, err := json.Marshal(op)
	if err != nil {
		return err
	}
	encodedBytes := int64(len(raw) + 128) // Reserve the eventual generated batch ID/envelope.
	if op.SizeBytes > q.limits.data || encodedBytes > q.limits.metadata || int64(len(retained)) > q.limits.metadata {
		return ErrSourceQuota
	}
	identity := *op.Captured.Transport
	identity.RequestPath = ""
	item := &smallBatchQueueItem{original: op, rules: rules, complete: complete, metadata: encodedBytes, retained: int64(len(retained)), key: smallBatchQueueKey{op.RootID, rules, identity}, destination: [2]string{p.entries[0].input.body["intent"].(map[string]any)["parentId"].(string), op.Name}}
	return q.command(ctx, smallBatchQueueMessage{item: item, reply: make(chan error, 1)})
}
func (q *smallBatchQueue) command(ctx context.Context, message smallBatchQueueMessage) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.done:
		return errors.Join(ErrArtifactRetained, q.result())
	case q.commands <- message:
	}
	// Once accepted, the collector owns exactly one reply even on cancellation.
	// Returning early here would let both caller and queue report the same item.
	return <-message.reply
}
func (q *smallBatchQueue) flush(ctx context.Context) error {
	return q.command(ctx, smallBatchQueueMessage{reply: make(chan error, 1)})
}
func (q *smallBatchQueue) close() error {
	err := q.command(context.Background(), smallBatchQueueMessage{final: true, reply: make(chan error, 1)})
	<-q.done
	if q.ctx.Err() != nil {
		return errors.Join(q.ctx.Err(), q.result())
	}
	if errors.Is(err, ErrArtifactRetained) {
		return q.result()
	}
	return err
}

func (q *smallBatchQueue) collect() {
	defer close(q.done)
	defer q.workers.Wait()
	defer close(q.jobs)
	var current []smallBatchQueueItem
	var data, metadata, retained int64
	operations := map[string]bool{}
	destinations := map[[2]string]bool{}
	var timer *time.Timer
	var tick <-chan time.Time
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = nil
		tick = nil
	}
	defer stopTimer()
	flush := func() {
		if len(current) == 0 {
			return
		}
		items := current
		current = nil
		data = 0
		metadata = 0
		retained = 0
		operations = map[string]bool{}
		destinations = map[[2]string]bool{}
		stopTimer()
		if err := q.ctx.Err(); err != nil {
			q.finish(items, err)
			return
		}
		id, err := NewOperationID()
		var plan *smallBatchPlan
		if err == nil {
			originals := make([]Operation, len(items))
			for n := range items {
				originals[n] = items[n].original
			}
			plan, err = newSmallBatchPlan(id, items[0].rules, originals)
			if err == nil {
				var raw []byte
				raw, err = plan.prepareBytes()
				if err == nil && int64(len(raw)) > q.limits.metadata {
					err = ErrSourceQuota
				}
			}
		}
		if err != nil {
			q.finish(items, err)
			return
		}
		q.tasks.Add(1)
		select {
		case q.jobs <- smallBatchQueueWork{items, plan}:
		case <-q.ctx.Done():
			q.finish(items, q.ctx.Err())
			q.tasks.Done()
		}
	}
	for {
		select {
		case <-q.ctx.Done():
			flush()
			return
		case <-tick:
			flush()
		case message := <-q.commands:
			if message.item == nil {
				flush()
				q.tasks.Wait()
				message.reply <- q.result()
				if message.final {
					return
				}
				continue
			}
			item := *message.item
			if err := q.ctx.Err(); err != nil {
				message.reply <- err
				continue
			}
			if len(current) > 0 && (item.key != current[0].key || q.sameParent && item.destination[0] != current[0].destination[0]) {
				flush()
			}
			if operations[item.original.OperationID] || destinations[item.destination] {
				message.reply <- ErrIdentityConflict
				continue
			}
			if len(current) >= q.limits.items || data > q.limits.data-item.original.SizeBytes || metadata > q.limits.metadata-item.metadata || retained > q.limits.metadata-item.retained {
				flush()
			}
			if err := q.ctx.Err(); err != nil {
				message.reply <- err
				continue
			}
			if len(current) == 0 {
				timer = time.NewTimer(q.age)
				tick = timer.C
			}
			current = append(current, item)
			operations[item.original.OperationID] = true
			destinations[item.destination] = true
			data += item.original.SizeBytes
			metadata += item.metadata
			retained += item.retained
			if len(current) == q.limits.items || data == q.limits.data || metadata == q.limits.metadata || retained == q.limits.metadata {
				flush()
			}
			message.reply <- nil
		}
	}
}
