package syncstate

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// Headers remain authoritative even if a proxy's error body is HTML, cut short,
// oversized or stalled. No body error may turn 407 into lost registration.
func (s *IsolatedHTTPSession) readHTTPFailure(ctx context.Context, response *http.Response, path string) error {
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if readErr != nil {
		raw = nil
	} // Never interpret a partial protocol reply.
	failure := s.httpFailure(response.StatusCode, path, response.Header.Get("Content-Type"), raw)
	var typed *guardedHTTPFailure
	if errors.As(failure, &typed) {
		typed.retryAfter = max(typed.retryAfter, retryAfter(response.Header.Get("Retry-After")))
	}
	return errors.Join(failure, readErr)
}
