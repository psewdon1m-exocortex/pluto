package pluto

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"pluto/internal/network"
	"pluto/internal/pluto/syncstate"
	"time"
)

type heartbeatUpdate struct {
	config      Config
	observation Observation
}
type heartbeatWorker struct {
	updates chan heartbeatUpdate
	done    chan struct{}
}

func newHeartbeatWorker(ctx context.Context, timeout time.Duration, send func(context.Context, heartbeatUpdate)) *heartbeatWorker {
	worker := &heartbeatWorker{updates: make(chan heartbeatUpdate, 1), done: make(chan struct{})}
	go func() {
		defer close(worker.done)
		for {
			select {
			case <-ctx.Done():
				return
			case update := <-worker.updates:
				if ctx.Err() != nil {
					return
				}
				deadline, cancel := context.WithTimeout(ctx, timeout)
				send(deadline, update)
				cancel()
			}
		}
	}()
	return worker
}
func (worker *heartbeatWorker) offer(update heartbeatUpdate) {
	select {
	case worker.updates <- update:
		return
	default:
	}
	select {
	case <-worker.updates:
	default:
	}
	select {
	case worker.updates <- update:
	default:
	}
}

func networkWaitState(err error) string {
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return "TLS_ACTION_REQUIRED"
	}
	var proxy *network.ProxyError
	if errors.As(err, &proxy) {
		if proxy.Status == http.StatusProxyAuthRequired {
			return "PROXY_AUTH_REQUIRED"
		}
		return "WAIT_CONNECTIVITY"
	}
	status := syncstate.HTTPStatus(err)
	var remote *HTTPError
	if errors.As(err, &remote) {
		status = remote.Status
	}
	switch status {
	case 407:
		return "PROXY_AUTH_REQUIRED"
	case 401, 403:
		return "SERVER_AUTH_REQUIRED"
	case 408, 429, 500, 502, 503, 504:
		return "WAIT_CONNECTIVITY"
	}
	var unreachable *RemoteNetworkError
	if errors.As(err, &unreachable) {
		return "WAIT_CONNECTIVITY"
	}
	if state, ok := syncstate.RetryClass(err); ok && state == "WAIT_CONNECTIVITY" {
		return state
	}
	return ""
}

func networkRetryAfter(err error) time.Duration {
	var remote *HTTPError
	if errors.As(err, &remote) {
		return remote.RetryAfter
	}
	return syncstate.HTTPRetryAfter(err)
}

func (s *Service) heartbeat(ctx context.Context, update heartbeatUpdate) {
	c := update.config
	status := update.observation
	// NetworkState is local scheduling/UI state, outside Saturn's strict check-in
	// contract. Sending it after a failure prevents the successful probe that
	// would otherwise release the retained queue. Keep the local copy unchanged.
	status.NetworkState = ""
	err := (Remote{s.HTTP, c.SaturnURL, c.AccessToken}).json(ctx, "POST", "/api/v1/pluto/check-in", map[string]any{"version": s.Version, "status": status}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	// A stale reply must not affect newly enrolled credentials or another origin.
	if c.SaturnURL != s.Config.SaturnURL || c.AccessToken != s.Config.AccessToken {
		return
	}
	if err != nil {
		if state := networkWaitState(err); state != "" {
			if until := time.Now().Add(networkRetryAfter(err)); until.After(s.networkNotBefore) {
				s.networkNotBefore = until
			}
			s.networkWaiting = true
			s.Observation.NetworkState = state
			s.Observation.Error = state + "; credentials and queued operations retained"
		}
		return
	}
	if s.networkWaiting {
		s.networkWaiting = false
		s.Observation.NetworkState = "RECOVERING_OPERATIONS"
		s.Observation.Error = ""
		s.Observation.NextRunAt = time.Now().UTC().Format(time.RFC3339Nano)
		s.HTTP.CloseIdleConnections()
	}
}
