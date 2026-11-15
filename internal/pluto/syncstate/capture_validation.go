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

// A lexical scope owns one readonly no-follow descriptor. It is never a source
// stat shortcut, persistent checksum cache or permission to reuse another cut.
type captureValidation struct {
	file  *os.File
	info  os.FileInfo
	sha   string
	bytes int64
}

func (s *captureValidation) check(v *VerifiedSnapshot, ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if v.closed || v.release == nil || !validHash(v.evidence.GuardDigest) || v.scopeDisposition != "" || s.file == nil || !os.SameFile(s.info, v.sealed) || s.sha != v.evidence.SHA256 || s.bytes != v.evidence.SizeBytes {
		return ErrInvalidReceipt
	}
	fd, e := s.file.Stat()
	if e != nil {
		return e
	}
	p, e := os.Lstat(v.filename)
	if e != nil {
		return e
	}
	for _, actual := range []os.FileInfo{fd, p} {
		if !actual.Mode().IsRegular() || actual.Mode().Perm() != 0400 || !os.SameFile(s.info, actual) || actual.Size() != s.bytes || actual.ModTime() != s.info.ModTime() || statCTime(actual) != statCTime(s.info) {
			return ErrInvalidReceipt
		}
	}
	return nil
}

// WithValidatedCapture joins every user before descriptor closure. It hashes
// private sealed bytes once, then identity-checks each existing integrity/CAS
// boundary. It does not bypass source or local/R/trust generation checks.
func WithValidatedCapture(ctx context.Context, v *VerifiedSnapshot, use func() error) (err error) {
	if v == nil || use == nil {
		return ErrIdentityConflict
	}
	v.mu.Lock()
	if v.validation != nil || v.closed {
		v.mu.Unlock()
		return ErrIdentityConflict
	}
	f, e := os.OpenFile(v.filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		v.mu.Unlock()
		return e
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || !os.SameFile(info, v.sealed) || info.Size() != v.evidence.SizeBytes {
		v.mu.Unlock()
		f.Close()
		return errors.Join(ErrInvalidReceipt, e)
	}
	done, e := v.limiter.AcquireCaptureReader(ctx)
	if e != nil {
		v.mu.Unlock()
		f.Close()
		return e
	}
	h := sha256.New()
	n, e := io.CopyBuffer(h, captureContextReader{ctx, io.LimitReader(f, v.evidence.SizeBytes+1)}, make([]byte, 65536))
	capturePrivateReads.Add(1)
	capturePrivateBytes.Add(n)
	done()
	s := &captureValidation{file: f, info: info, sha: hex.EncodeToString(h.Sum(nil)), bytes: n}
	if e == nil && (s.sha != v.evidence.SHA256 || n != v.evidence.SizeBytes) {
		e = ErrInvalidReceipt
	}
	if e == nil {
		e = s.check(v, ctx)
	}
	if e != nil {
		v.mu.Unlock()
		f.Close()
		return e
	}
	v.validation = s
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		v.validation = nil
		disposition := v.scopeDisposition
		v.scopeDisposition = ""
		closeErr := f.Close()
		v.mu.Unlock()
		var cleanup error
		if disposition == "retain" {
			cleanup = v.Retain()
		} else if disposition == "close" {
			cleanup = v.Close()
			if errors.Is(cleanup, ErrArtifactRetained) {
				cleanup = v.Retain()
			}
		}
		err = errors.Join(err, closeErr, cleanup)
	}()
	return use()
}
