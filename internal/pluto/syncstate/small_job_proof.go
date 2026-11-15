package syncstate

import (
	"bytes"
	"encoding/json"
	"sync"
)

// Only encoding proofs are retained. Every lookup follows fresh, bounded SQL
// reads and hashes the complete current originals and exact persisted manifest.
// Authority, phases, custody, active membership and receipts are never cached.
// Two jobs and four MiB bound retained wire/metadata independently of the catalog.
type smallJobProofCache struct {
	mu      sync.Mutex
	entries []smallJobProof
	bytes   int
}
type smallJobProof struct {
	id, key, rules     string
	binding            RemoteBinding
	dataBytes          int64
	manifest, wire     []byte
	inputs             [][]byte
	hashes, identities []string
	bytes              int
}

func (c *smallJobProofCache) get(id, key string, originals []Operation) (*smallBatchPlan, bool, error) {
	if c == nil {
		return nil, false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, saved := range c.entries {
		if saved.id != id || saved.key != key {
			continue
		}
		if len(originals) != len(saved.inputs) {
			return nil, false, ErrIdentityConflict
		}
		plan := &smallBatchPlan{id: id, rules: saved.rules, binding: saved.binding, dataBytes: saved.dataBytes,
			manifest: bytes.Clone(saved.manifest), executionJob: true, jobWire: bytes.Clone(saved.wire), entries: make([]smallBatchEntry, len(originals))}
		for i, op := range originals {
			// Decode a private copy so callers cannot mutate a later cache hit.
			var body map[string]any
			if err := json.Unmarshal(saved.inputs[i], &body); err != nil {
				return nil, false, err
			}
			plan.entries[i] = smallBatchEntry{original: op, input: catalogHTTPInput{body: body, hash: saved.hashes[i]}, sourceIdentity: saved.identities[i]}
		}
		return plan, true, nil
	}
	return nil, false, nil
}

func (c *smallJobProofCache) put(key string, plan *smallBatchPlan) {
	if c == nil || plan == nil || !plan.executionJob || len(plan.entries) > 16 {
		return
	}
	saved := smallJobProof{id: plan.id, key: key, rules: plan.rules, binding: plan.binding, dataBytes: plan.dataBytes,
		manifest: bytes.Clone(plan.manifest), wire: bytes.Clone(plan.jobWire)}
	saved.bytes = len(saved.manifest) + len(saved.wire) + len(key) + len(plan.id) + len(plan.rules) + 512
	for _, entry := range plan.entries {
		raw, err := json.Marshal(entry.input.body)
		if err != nil {
			return
		}
		saved.inputs = append(saved.inputs, raw)
		saved.hashes = append(saved.hashes, entry.input.hash)
		saved.identities = append(saved.identities, entry.sourceIdentity)
		saved.bytes += len(raw) + 128
	}
	if saved.bytes > 4<<20 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < len(c.entries); i++ {
		if c.entries[i].id == saved.id {
			c.bytes -= c.entries[i].bytes
			c.entries = append(c.entries[:i], c.entries[i+1:]...)
			break
		}
	}
	for len(c.entries) > 0 && (len(c.entries) >= 2 || c.bytes+saved.bytes > 4<<20) {
		c.bytes -= c.entries[0].bytes
		c.entries = c.entries[1:]
	}
	c.entries = append(c.entries, saved)
	c.bytes += saved.bytes
}
