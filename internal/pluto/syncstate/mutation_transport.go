package syncstate

import (
	"context"
	"errors"
	"time"

	"pluto/internal/syncproto"
)

type mutationFlight struct {
	op               Operation
	input, namespace map[string]any
	key              string
	done             chan struct{}
	raw              []byte
	err              error
}

// Only independent metadata originals coalesce. The whole batch is never a
// publication receipt; each caller validates and ACKs its exact durable intent.
func (s *IsolatedHTTPSession) mutationTransport(ctx context.Context, op Operation, command string, input, namespace map[string]any) ([]byte, error) {
	if op.Captured == nil || op.Captured.Transport == nil {
		return nil, ErrIdentityConflict
	}
	binding := op.Captured.Transport.InputBinding
	if command != "execute" || !s.features["namespace-mutations-v1"] {
		return s.post(ctx, "mutations/"+command, map[string]any{"binding": bindingHTTP(binding), "namespace": namespace, "input": input})
	}
	key := fingerprint(struct {
		Binding   RemoteBinding
		Namespace map[string]any
	}{binding, namespace})
	s.mutationMu.Lock()
	if s.mutationFlights == nil {
		s.mutationFlights = map[string]*mutationFlight{}
	}
	f := s.mutationFlights[op.OperationID]
	if f != nil && (f.op.IntentFingerprint != op.IntentFingerprint || f.key != key) {
		s.mutationMu.Unlock()
		return nil, ErrIdentityConflict
	}
	if f == nil {
		if len(s.mutationFlights) >= 500 {
			s.mutationMu.Unlock()
			return nil, ErrSourceQuota
		}
		f = &mutationFlight{op: op, input: input, namespace: namespace, key: key, done: make(chan struct{})}
		s.mutationFlights[op.OperationID] = f
		s.mutationQueue = append(s.mutationQueue, f)
		if !s.mutationSending {
			s.mutationSending = true
			go s.flushMutations(ctx)
		}
	}
	s.mutationMu.Unlock()
	<-f.done
	return f.raw, f.err
}

func (s *IsolatedHTTPSession) flushMutations(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Millisecond):
	}
	s.mutationMu.Lock()
	page := s.mutationQueue
	s.mutationQueue = nil
	s.mutationSending = false
	s.mutationMu.Unlock()
	groups := map[string][]*mutationFlight{}
	for _, f := range page {
		groups[f.key] = append(groups[f.key], f)
	}
	for _, group := range groups {
		items := make([]map[string]any, 0, len(group))
		for _, f := range group {
			items = append(items, map[string]any{"ref": f.op.OperationID, "input": f.input})
		}
		first := group[0]
		raw, err := s.post(ctx, "mutations/batch", map[string]any{"binding": bindingHTTP(first.op.Captured.Transport.InputBinding), "namespace": first.namespace, "items": items})
		if HTTPStatus(err) == 404 || HTTPStatus(err) == 413 || HTTPStatus(err) == 501 || errors.Is(err, ErrSourceQuota) {
			for _, f := range group {
				f.raw, f.err = s.post(ctx, "mutations/execute", map[string]any{"binding": bindingHTTP(f.op.Captured.Transport.InputBinding), "namespace": f.namespace, "input": f.input})
			}
			continue
		}
		if err == nil {
			value, e := syncproto.Parse(raw)
			if e != nil {
				err = e
			} else {
				object, e := strictHTTPObject(value, "outcomes")
				if e != nil {
					err = e
				} else {
					rows, ok := object["outcomes"].([]any)
					if !ok || len(rows) != len(group) {
						err = ErrInvalidReceipt
					} else {
						known := map[string]*mutationFlight{}
						for _, f := range group {
							known[f.op.OperationID] = f
						}
						seen := map[string]bool{}
						for _, row := range rows {
							item, ok := row.(map[string]any)
							if !ok || len(item) != 2 {
								err = ErrInvalidReceipt
								break
							}
							ref, ok := item["ref"].(string)
							f := known[ref]
							if !ok || f == nil || seen[ref] {
								err = ErrInvalidReceipt
								break
							}
							seen[ref] = true
							if outcome, ok := item["outcome"]; ok {
								f.raw = mustJSON(outcome)
							} else if code, ok := item["code"].(string); ok {
								f.err = s.mutationItemFailure(code)
							} else {
								err = ErrInvalidReceipt
								break
							}
						}
					}
				}
			}
		}
		if err != nil {
			for _, f := range group {
				f.err = err
			}
		}
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	for _, f := range page {
		delete(s.mutationFlights, f.op.OperationID)
		close(f.done)
	}
}

func (s *IsolatedHTTPSession) mutationItemFailure(code string) error {
	status := 409
	switch code {
	case "unauthorized", "authority_invalid":
		status = 401
	case "forbidden", "authorization_changed":
		status = 403
	case "precondition_failed":
		status = 412
	case "admission_full", "capacity":
		status = 429
	case "backend_busy", "backend_draining":
		status = 503
	case "sync_internal_error":
		status = 500
	case "unsupported":
		status = 404
	case "invalid_input", "invalid_name", "invalid_json", "invalid_contract":
		status = 400
	}
	if status == 401 || status == 403 {
		s.denied.Store(true)
		if s.sessionCancel != nil {
			s.sessionCancel()
		}
	}
	return s.httpFailure(status, "mutations/batch", "application/json", mustJSON(map[string]any{"code": code}))
}
