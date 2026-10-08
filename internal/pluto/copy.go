package pluto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const MaxFileBytes int64 = 256 * 1024 * 1024

func RelativePath(source string) string { return strings.TrimLeft(filepath.ToSlash(source), "/") }
func Copy(ctx context.Context, r Remote, sources []string, spoolDir string) (int, error) {
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		return 0, err
	}
	files := map[string]bool{}
	dirs := map[string]bool{}
	uploaded := 0
	var failures []error
	failedCount := 0
	ensure := func(relative string) error { return nil }
	ensure = func(relative string) error {
		if relative == "." || relative == "" || dirs[relative] {
			return nil
		}
		if err := ensure(path.Dir(relative)); err != nil {
			return err
		}
		var meta Metadata
		err := r.request(ctx, "GET", "/api/v1/pluto/files?path="+url.QueryEscape(relative), nil, -1, nil, &meta)
		if err == nil {
			if meta.Type != "folder" {
				return errors.New("destination directory conflicts with a file")
			}
			dirs[relative] = true
			return nil
		}
		var remote *HTTPError
		if !errors.As(err, &remote) || remote.Status != 404 {
			return err
		}
		err = r.json(ctx, "POST", "/api/v1/pluto/folders", map[string]string{"path": relative}, nil)
		if err != nil {
			return err
		}
		dirs[relative] = true
		return nil
	}
	for _, source := range sources {
		process := func(filename string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("a source cannot be read")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			relative := RelativePath(filename)
			if files[relative] {
				return nil
			}
			if entry.IsDir() {
				return ensure(relative)
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("a symbolic link was found; symbolic links are not followed")
			}
			if entry.Type() != 0 {
				return errors.New("sources must contain only regular files and directories")
			}
			src, err := os.Open(filename)
			if err != nil {
				return errors.New("source file cannot be opened")
			}
			defer src.Close()
			before, err := src.Stat()
			if err != nil || !before.Mode().IsRegular() || before.Size() > MaxFileBytes {
				return errors.New("source must be a regular file no larger than 256 MiB")
			}
			if err = checkSpoolSpace(spoolDir, before.Size()); err != nil {
				return err
			}
			tmp, err := os.CreateTemp(spoolDir, "copy-*")
			if err != nil {
				return err
			}
			defer os.Remove(tmp.Name())
			defer tmp.Close()
			digest := sha256.New()
			size, err := io.Copy(io.MultiWriter(tmp, digest), io.LimitReader(src, MaxFileBytes+1))
			if err != nil || size != before.Size() || size > MaxFileBytes {
				return errors.New("source changed or could not be copied")
			}
			after, err := src.Stat()
			if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
				return errors.New("source changed during copying")
			}
			sha := hex.EncodeToString(digest.Sum(nil))
			if err = ensure(path.Dir(relative)); err != nil {
				return err
			}
			var meta Metadata
			err = r.request(ctx, "GET", "/api/v1/pluto/files?path="+url.QueryEscape(relative), nil, -1, nil, &meta)
			headers := map[string]string{"Content-Type": "application/octet-stream", "X-Content-Sha256": sha}
			if err == nil {
				if meta.Type != "file" {
					return errors.New("destination conflicts with a folder")
				}
				if meta.SHA256 == sha {
					files[relative] = true
					return nil
				}
				headers["If-Match"] = meta.ETag
			} else {
				var remote *HTTPError
				if !errors.As(err, &remote) || remote.Status != 404 {
					return err
				}
				headers["If-None-Match"] = "*"
			}
			if _, err = tmp.Seek(0, 0); err != nil {
				return err
			}
			var receipt Metadata
			if err = r.request(ctx, "PUT", "/api/v1/pluto/files?path="+url.QueryEscape(relative), tmp, size, headers, &receipt); err != nil {
				return err
			}
			if receipt.SHA256 != sha || receipt.SizeBytes != size {
				return errors.New("Saturn did not confirm the copied file checksum")
			}
			files[relative] = true
			uploaded++
			return nil
		}
		err := filepath.WalkDir(source, func(filename string, entry fs.DirEntry, walkErr error) error {
			err := process(filename, entry, walkErr)
			if err == nil {
				return nil
			}
			var denied *HTTPError
			if ctx.Err() != nil || (errors.As(err, &denied) && (denied.Status == 401 || denied.Status == 403)) {
				return err
			}
			failedCount++
			if len(failures) < 20 {
				failures = append(failures, fmt.Errorf("%s: %w", filename, err))
			}
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		})
		if err != nil {
			return uploaded, err
		}
	}
	if failedCount > 0 {
		return uploaded, fmt.Errorf("%d source entries failed: %w", failedCount, errors.Join(failures...))
	}
	return uploaded, nil
}
