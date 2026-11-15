package syncstate

import (
	"context"
	"errors"
	"io"
	"net"
	"pluto/internal/network"
	"syscall"
	"time"
)

// Changes is a read, despite its POST verb. A transient connection failure must
// not discard a long source scan. Replay only this exact binding/cursor, at most
// three times inside one existing control budget. Refresh still invalidates its
// cached authority before reading and imports only a complete validated page.
// Mutating POSTs, HTTP refusals and contract/identity failures use their existing
// recovery paths; this is deliberately not a generic request retry.
func (s *IsolatedHTTPSession) readChanges(parent context.Context, cursor string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, network.ControlTimeout)
	defer cancel()
	if s.sessionContext != nil {
		stop := context.AfterFunc(s.sessionContext, cancel)
		defer stop()
	}
	input := map[string]any{"binding": bindingHTTP(s.binding), "cursor": cursor}
	for attempt := 0; ; attempt++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		raw, e := s.post(ctx, "changes", input)
		if e == nil {
			return raw, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt == 2 || !transientChangesRead(e) {
			return nil, e
		}
		timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}
}

func transientChangesRead(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var failure *guardedHTTPFailure
	if errors.As(err, &failure) {
		return false
	}
	var transport net.Error
	return errors.As(err, &transport) && transport.Timeout() ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED)
}
