package syncstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// streamCaptured joins the transport user before a handle can release its
// process-wide data/plaintext admission. Source hash readers remain separately
// limited; the two admitted transport workers may read sealed bytes concurrently.
func streamCaptured(ctx context.Context, v *VerifiedSnapshot, use func(io.Reader) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if use == nil {
		return ErrIdentityConflict
	}
	if err := v.integrity(ctx); err != nil {
		return err
	}
	f, err := os.OpenFile(v.filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !os.SameFile(before, v.sealed) {
		return errors.Join(ErrInvalidReceipt, err)
	}
	h := sha256.New()
	counter := &capturedCountingReader{reader: io.TeeReader(captureContextReader{ctx, io.LimitReader(f, v.evidence.SizeBytes+1)}, h)}
	captureTransportReads.Add(1)
	defer func() { captureTransportBytes.Add(counter.count) }()
	if err = use(counter); err != nil {
		return err
	}
	// The receiver must consume the entire bounded payload, including EOF. A
	// partial reader cannot turn a claimed receipt into acknowledged bytes.
	var tail [1]byte
	n, e := counter.Read(tail[:])
	if n != 0 || e != io.EOF {
		return ErrInvalidReceipt
	}
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if counter.count != v.evidence.SizeBytes || hex.EncodeToString(h.Sum(nil)) != v.evidence.SHA256 || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || statCTime(before) != statCTime(after) {
		return ErrInvalidReceipt
	}
	return nil
}

type capturedCountingReader struct {
	reader io.Reader
	count  int64
}

func (r *capturedCountingReader) Read(p []byte) (int, error) {
	n, e := r.reader.Read(p)
	r.count += int64(n)
	return n, e
}
