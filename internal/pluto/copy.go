package pluto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const MaxFileBytes int64 = 256 * 1024 * 1024

func RelativePath(source string) string { return strings.TrimLeft(filepath.ToSlash(source), "/") }
func Copy(ctx context.Context, r Remote, sources []string, spoolDir string) (int, error) {
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		return 0, err
	}
	return copyPipeline(ctx, r, sources, spoolDir, copyResources)
}

func copyFile(ctx context.Context, r Remote, filename string, entry fs.DirEntry, spoolDir string, parents *parentEnsurer, budget *copyBudget, stopOnFailure func(error)) (uploaded bool, err error) {
	if err = budget.acquireWorker(ctx); err != nil {
		return false, err
	}
	defer budget.releaseWorker()
	// Publish a fatal network/access failure before releasing the admission
	// slot; otherwise a queued worker can start another upload in this gap.
	defer func() { stopOnFailure(err) }()
	relative := RelativePath(filename)
	if entry.Type()&os.ModeSymlink != 0 {
		info, err := os.Stat(filename)
		if err != nil {
			return false, errors.New("symbolic link target is missing or inaccessible to the Pluto service account")
		}
		if !info.Mode().IsRegular() {
			return false, errors.New("symbolic links must point to regular files; directory links and special files are not followed")
		}
	} else if entry.Type() != 0 {
		return false, errors.New("sources must contain only regular files and directories")
	}
	// A link can change between validation and open. Nonblocking open plus
	// fstat rejects a replacement FIFO/device without waiting for a writer.
	src, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, errors.New("source file cannot be opened by the Pluto service account; check target and parent-directory permissions")
	}
	defer src.Close()
	before, err := src.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > MaxFileBytes {
		return false, errors.New("source must be a regular file no larger than 256 MiB")
	}
	if err = budget.reserveSpool(ctx, spoolDir, before.Size()); err != nil {
		return false, err
	}
	defer budget.releaseSpool(before.Size())
	tmp, err := os.CreateTemp(spoolDir, "copy-*")
	if err != nil {
		return false, err
	}
	defer func() {
		closeErr := tmp.Close()
		removeErr := os.Remove(tmp.Name())
		if closeErr != nil || (removeErr != nil && !errors.Is(removeErr, os.ErrNotExist)) {
			cleanupErr := errors.Join(errSnapshotCleanup, closeErr, removeErr)
			budget.blockSpool(cleanupErr)
			err = errors.Join(err, cleanupErr)
		}
	}()
	if err = budget.acquireReader(ctx); err != nil {
		return false, err
	}
	digest := sha256.New()
	// Read one extra byte to detect growth, but never write past the reserved
	// snapshot size. Cancellation is checked between bounded buffer reads.
	size, err := io.CopyBuffer(&snapshotWriter{writer: io.MultiWriter(tmp, digest), remaining: before.Size()},
		&copyContextReader{ctx: ctx, reader: io.LimitReader(src, before.Size()+1)}, make([]byte, copyBufferBytes))
	budget.releaseReader()
	if err != nil || size != before.Size() || size > MaxFileBytes {
		if ctx.Err() != nil {
			return false, context.Cause(ctx)
		}
		return false, errors.New("source changed or could not be copied")
	}
	after, err := src.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return false, errors.New("source changed during copying")
	}
	current, err := os.Stat(filename)
	if err != nil || !os.SameFile(before, current) {
		return false, errors.New("source or symbolic link target changed during copying")
	}
	sha := hex.EncodeToString(digest.Sum(nil))
	if err = parents.ensure(ctx, filepath.ToSlash(filepath.Dir(relative))); err != nil {
		return false, err
	}
	var meta Metadata
	err = r.request(ctx, "GET", "/api/v1/pluto/files?path="+url.QueryEscape(relative), nil, -1, nil, &meta)
	headers := map[string]string{"Content-Type": "application/octet-stream", "X-Content-Sha256": sha}
	if err == nil {
		if meta.Type != "file" {
			return false, errors.New("destination conflicts with a folder")
		}
		if meta.SHA256 == sha {
			return false, nil
		}
		headers["If-Match"] = meta.ETag
	} else {
		var remote *HTTPError
		if !errors.As(err, &remote) || remote.Status != 404 {
			return false, err
		}
		headers["If-None-Match"] = "*"
	}
	if _, err = tmp.Seek(0, 0); err != nil {
		return false, err
	}
	var receipt Metadata
	if err = r.request(ctx, "PUT", "/api/v1/pluto/files?path="+url.QueryEscape(relative), struct{ io.Reader }{tmp}, size, headers, &receipt); err != nil {
		if destinationChanged(err) {
			parents.invalidate()
		}
		return false, err
	}
	if receipt.SHA256 != sha || receipt.SizeBytes != size {
		return false, errors.New("Saturn did not confirm the copied file checksum")
	}
	return true, nil
}
