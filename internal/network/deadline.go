package network

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

const ControlTimeout = 45 * time.Second
const TransferIdleTimeout = 30 * time.Second
const ConnectTimeout = 10 * time.Second
const LegacyCopyHeaderTimeout = 2 * time.Minute

// Deadlines separate a complete control exchange from a progressing transfer.
// Header is the quiet period allowed after upload EOF (legacy server-side copy).
type Deadlines struct{ Control, Idle, Header time.Duration }

func GuardedDeadlines(data bool) Deadlines {
	d := Deadlines{Idle: TransferIdleTimeout, Header: ControlTimeout}
	if !data {
		d.Control = ControlTimeout
	} else {
		d.Header = TransferIdleTimeout
	}
	return d
}

type requestLifetime struct {
	mu           sync.Mutex
	cancel       context.CancelCauseFunc
	timer        *time.Timer
	total        *time.Timer
	due          time.Time
	closed       bool
	idle, header time.Duration
}

func (l *requestLifetime) reset(delay time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.due = time.Now().Add(delay)
	l.timer.Reset(delay)
}
func (l *requestLifetime) expire() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if remaining := time.Until(l.due); remaining > 0 {
		l.timer.Reset(remaining)
		return
	}
	l.closed = true
	l.cancel(context.DeadlineExceeded)
}
func (l *requestLifetime) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.timer.Stop()
	if l.total != nil {
		l.total.Stop()
	}
	l.cancel(context.Canceled)
}

type progressBody struct {
	io.ReadCloser
	life      *requestLifetime
	ctx       context.Context
	upload    bool
	closeOnce sync.Once
	closeErr  error
}

func (b *progressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.life.reset(b.life.idle)
	}
	if b.upload && err == io.EOF {
		b.life.reset(b.life.header)
	}
	if err != nil && context.Cause(b.ctx) != nil {
		err = context.Cause(b.ctx)
	}
	return n, err
}
func (b *progressBody) Close() error {
	b.closeOnce.Do(func() {
		if b.upload {
			b.life.reset(b.life.header)
		} else {
			b.life.close()
		}
		b.closeErr = b.ReadCloser.Close()
	})
	return b.closeErr
}

// Do performs exactly one attempt. The lifetime belongs to the returned body;
// callers must close it. Readers never prebuffer a complete upload/download.
func Do(client *http.Client, request *http.Request, d Deadlines) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(request.Context())
	l := &requestLifetime{cancel: cancel, idle: d.Idle, header: d.Header}
	if l.idle <= 0 {
		l.idle = TransferIdleTimeout
	}
	if l.header <= 0 {
		l.header = ControlTimeout
	}
	initial := l.header
	if request.Body != nil && request.Body != http.NoBody {
		initial = l.idle
	}
	l.due = time.Now().Add(initial)
	l.mu.Lock()
	l.timer = time.AfterFunc(initial, l.expire)
	l.mu.Unlock()
	if d.Control > 0 {
		l.total = time.AfterFunc(d.Control, func() { cancel(context.DeadlineExceeded) })
	}
	req := request.Clone(ctx)
	// Redirects are forbidden by the owning client. Also prevent transparent
	// transport retries of a mutation whose outcome is not yet known.
	req.GetBody = nil
	if req.Body != nil && req.Body != http.NoBody {
		body := &progressBody{ReadCloser: req.Body, life: l, ctx: ctx, upload: true}
		req.Body = body
		// HTTP/1 waits for its writer when unwinding a cancelled request.
		// Close the producer as well, so a blocked Body.Read cannot retain
		// that writer and its connection after the idle/caller deadline.
		context.AfterFunc(ctx, func() { _ = body.Close() })
	}
	own := *client
	own.Timeout = 0
	response, err := own.Do(req)
	if err != nil {
		cause := context.Cause(ctx)
		l.close()
		if cause != nil {
			return nil, cause
		}
		return nil, err
	}
	l.reset(l.idle)
	response.Body = &progressBody{ReadCloser: response.Body, life: l, ctx: ctx}
	return response, nil
}
