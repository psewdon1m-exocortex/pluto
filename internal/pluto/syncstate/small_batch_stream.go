package syncstate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"strconv"
	"sync"
)

const smallBatchStreamChunk = 64 * 1024

// The caller retains its sealed, seekable local aggregate through the response.
// This reader owns neither its file handle nor its recovery lifetime. Reading
// and Close are joined; there is no producer goroutine or unbounded body buffer.
type smallBatchStream struct {
	mu                    sync.Mutex
	ctx                   context.Context
	plan                  *smallBatchPlan
	source                io.ReadSeeker
	boundary, contentType string
	length                int64
	phase, item           int
	pending               []byte
	remaining             int64
	digest                hash.Hash
	terminal              error
	closed                bool
	count                 func(int, bool)
	metadata              []byte
}

func newSmallBatchStream(ctx context.Context, plan *smallBatchPlan, source io.ReadSeeker, count func(int, bool)) (*smallBatchStream, error) {
	if plan == nil || source == nil || ctx == nil {
		return nil, ErrIdentityConflict
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	position, err := source.Seek(0, io.SeekCurrent)
	if err != nil || position != 0 {
		return nil, ErrIdentityConflict
	}
	length, err := source.Seek(0, io.SeekEnd)
	reset, resetErr := source.Seek(0, io.SeekStart)
	if err != nil || resetErr != nil || reset != 0 || length != plan.dataBytes {
		return nil, ErrIdentityConflict
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	b := &smallBatchStream{ctx: ctx, plan: plan, source: source, boundary: "pluto_" + hex.EncodeToString(nonce[:]), count: count}
	b.metadata = plan.manifestBytes()
	if plan.executionJob {
		b.metadata, err = plan.prepareBytes()
		if err != nil {
			return nil, err
		}
	}
	b.contentType = "multipart/related; boundary=" + b.boundary
	b.length = int64(len(b.opening())+len(b.metadata)+len(b.closing())) + plan.dataBytes
	for n := range plan.entries {
		b.length += int64(len(b.header(n)))
	}
	return b, nil
}
func (b *smallBatchStream) opening() []byte {
	return []byte("--" + b.boundary + "\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(b.metadata)) + "\r\n\r\n")
}
func (b *smallBatchStream) header(n int) []byte {
	op := b.plan.entries[n].original
	return []byte("\r\n--" + b.boundary + "\r\nContent-Type: application/octet-stream\r\nContent-ID: <pluto-sync-" + op.OperationID + ">\r\nContent-Length: " + remoteDecimal(op.SizeBytes) + "\r\n\r\n")
}
func (b *smallBatchStream) closing() []byte { return []byte("\r\n--" + b.boundary + "--\r\n") }
func (b *smallBatchStream) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}
func (b *smallBatchStream) finished() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil && b.terminal != io.EOF {
		return b.terminal
	}
	if b.phase != 4 || len(b.pending) != 0 {
		return ErrArtifactRetained
	}
	return nil
}
func (b *smallBatchStream) Read(out []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if len(out) == 0 {
		return 0, nil
	}
	if len(out) > smallBatchStreamChunk {
		out = out[:smallBatchStreamChunk]
	}
	for {
		if err := b.ctx.Err(); err != nil {
			b.terminal = err
		}
		if b.terminal != nil {
			return 0, b.terminal
		}
		if len(b.pending) > 0 {
			n := copy(out, b.pending)
			b.pending = b.pending[n:]
			if b.count != nil {
				b.count(n, false)
			}
			return n, nil
		}
		switch b.phase {
		case 0:
			b.pending = b.opening()
			b.phase = 1
		case 1:
			b.pending = b.metadata
			b.phase = 2
		case 2:
			if b.item == len(b.plan.entries) {
				position, e1 := b.source.Seek(0, io.SeekCurrent)
				length, e2 := b.source.Seek(0, io.SeekEnd)
				if e1 != nil || e2 != nil || position != b.plan.dataBytes || length != b.plan.dataBytes {
					b.terminal = ErrIdentityConflict
					continue
				}
				b.pending = b.closing()
				b.phase = 4
				continue
			}
			b.pending = b.header(b.item)
			b.remaining = b.plan.entries[b.item].original.SizeBytes
			b.digest = sha256.New()
			b.phase = 3
		case 3:
			if b.remaining == 0 {
				// A following delimiter permits the server to finish this item.
				// Do not release it until the original span hash is verified.
				if hex.EncodeToString(b.digest.Sum(nil)) != b.plan.entries[b.item].original.SHA256 {
					b.terminal = ErrIdentityConflict
					continue
				}
				b.item++
				b.phase = 2
				continue
			}
			if int64(len(out)) > b.remaining {
				out = out[:b.remaining]
			}
			n, err := b.source.Read(out)
			if n < 0 || n > len(out) {
				b.terminal = ErrIdentityConflict
				continue
			}
			if n > 0 {
				b.digest.Write(out[:n])
				b.remaining -= int64(n)
				if b.count != nil {
					b.count(n, true)
				}
			}
			if err == io.EOF {
				if b.remaining != 0 {
					err = io.ErrUnexpectedEOF
				} else {
					err = nil
				}
			}
			if err != nil {
				b.terminal = err
			} else if n == 0 {
				b.terminal = io.ErrNoProgress
			}
			return n, b.terminal
		case 4:
			b.terminal = io.EOF
		}
	}
}
