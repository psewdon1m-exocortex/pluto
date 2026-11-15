package syncstate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

type RetryWait struct {
	State string
	Until time.Time
	Cause error
}

func (e *RetryWait) Error() string {
	return e.State + " until " + e.Until.UTC().Format(time.RFC3339Nano)
}
func (e *RetryWait) Unwrap() error { return e.Cause }
func RetryClass(err error) (string, bool) {
	if errors.Is(err, context.Canceled) {
		return "", false
	}
	if errors.Is(err, ErrCaptureChanged) {
		return "SOURCE_BUSY", true
	}
	if errors.Is(err, ErrArtifactRetained) {
		return "RETRY_WAIT", true
	}
	var h *guardedHTTPFailure
	if errors.As(err, &h) {
		switch h.status {
		case 408, 429, 500, 502, 503, 504:
			return "RETRY_WAIT", true
		case 409:
			if h.code == "operation_unknown" || h.code == "transfer_unresolved" || h.code == "reconciliation_required" {
				return "RETRY_WAIT", true
			}
		}
		return "", false
	}
	var n net.Error
	if errors.As(err, &n) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return "WAIT_CONNECTIVITY", true
	}
	return "", false
}
func HTTPStatus(err error) int {
	var h *guardedHTTPFailure
	if errors.As(err, &h) {
		return h.status
	}
	return 0
}
func HTTPRetryAfter(err error) time.Duration {
	var h *guardedHTTPFailure
	if errors.As(err, &h) {
		return h.retryAfter
	}
	return 0
}
func retryAfter(value string) time.Duration {
	if n, err := strconv.ParseInt(value, 10, 32); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		return max(0, time.Until(t))
	}
	return 0
}
func (s *Store) RetryReady(ctx context.Context, id string) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != daemonSchemaVersion {
		return nil
	}
	var state string
	var next int64
	err := s.db.QueryRowContext(ctx, "SELECT state,next_ms FROM operation_retry WHERE operation_id=?", id).Scan(&state, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if next > time.Now().UnixMilli() {
		return &RetryWait{State: state, Until: time.UnixMilli(next)}
	}
	return nil
}
func (s *Store) RecordRetry(ctx context.Context, id string, cause error) error {
	state, ok := RetryClass(cause)
	if !ok {
		return cause
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return errors.Join(cause, err)
	}
	if version != daemonSchemaVersion {
		return cause
	}
	var wait *RetryWait
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var attempt int
		err := tx.QueryRowContext(ctx, "SELECT attempt FROM operation_retry WHERE operation_id=?", id).Scan(&attempt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		attempt++
		ceiling := min(60*time.Second, time.Second*time.Duration(1<<min(attempt-1, 6)))
		var random [8]byte
		if _, err = rand.Read(random[:]); err != nil {
			return err
		}
		delay := time.Duration(binary.LittleEndian.Uint64(random[:]) % uint64(ceiling+1))
		var h *guardedHTTPFailure
		if errors.As(cause, &h) {
			delay = max(delay, h.retryAfter)
		}
		if attempt >= 8 {
			state = "DEGRADED"
			delay = max(delay, 15*time.Minute)
		}
		next := time.Now().Add(delay)
		_, err = tx.ExecContext(ctx, `INSERT INTO operation_retry(operation_id,attempt,state,next_ms,reason) VALUES(?,?,?,?,?) ON CONFLICT(operation_id) DO UPDATE SET attempt=excluded.attempt,state=excluded.state,next_ms=excluded.next_ms,reason=excluded.reason`, id, attempt, state, next.UnixMilli(), state)
		wait = &RetryWait{State: state, Until: next, Cause: cause}
		return err
	})
	if err != nil {
		return errors.Join(cause, err)
	}
	return wait
}
func (s *Store) ClearRetry(ctx context.Context, id string) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != daemonSchemaVersion {
		return nil
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM operation_retry WHERE operation_id=?", id)
	return err
}
