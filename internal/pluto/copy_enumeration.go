package pluto

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type copyDirectoryReader interface {
	ReadDir(int) ([]fs.DirEntry, error)
	Close() error
}

type copyEnumerationFS interface {
	Lstat(string) (fs.FileInfo, error)
	OpenDirectory(string) (copyDirectoryReader, error)
}

type osCopyEnumerationFS struct{}

func (osCopyEnumerationFS) Lstat(filename string) (fs.FileInfo, error) { return os.Lstat(filename) }
func (osCopyEnumerationFS) OpenDirectory(filename string) (copyDirectoryReader, error) {
	// A previously observed directory replaced by a symlink/FIFO must not
	// turn into traversal outside the observed tree or a blocked source read.
	return os.OpenFile(filename, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// Each source drains its disk FIFO before the next source begins. Directory
// entries follow filesystem order, not WalkDir's whole-directory lexical sort.
// Diagnostic selection/order is handled separately from transport scheduling.
func streamCopySource(ctx context.Context, source string, filesystem copyEnumerationFS, state *copyEnumerationState,
	visit func(string, fs.DirEntry, error) error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if err := validCopyStatePath(source); err != nil {
		return visit(source, nil, err)
	}
	info, err := filesystem.Lstat(source)
	if err != nil {
		return visit(source, nil, err)
	}
	entry := fs.FileInfoToDirEntry(info)
	if err := visit(source, entry, nil); err != nil {
		if errors.Is(err, fs.SkipDir) {
			return nil
		}
		return err
	}
	if !entry.IsDir() {
		return nil
	}
	if err := state.pushDirectory(ctx, source); err != nil {
		return errors.Join(errCopyEnumerationState, err)
	}
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		filename, ok, err := state.popDirectory(ctx)
		if err != nil {
			return errors.Join(errCopyEnumerationState, err)
		}
		if !ok {
			return nil
		}
		// Directory discovery is cheap disk frontier work. Preparing its remote
		// namespace waits until dequeue, so a wide parent cannot become a barrier
		// of remote mkdir calls before ready descendants start publication.
		info, err := filesystem.Lstat(filename)
		if err != nil || !info.IsDir() {
			if err == nil {
				err = errors.New("source directory changed during enumeration")
			}
			if err := visit(filename, nil, err); err != nil {
				return err
			}
			continue
		}
		if err := visit(filename, fs.FileInfoToDirEntry(info), nil); err != nil {
			if errors.Is(err, fs.SkipDir) {
				continue
			}
			return err
		}
		if err := streamCopyDirectory(ctx, filename, filesystem, state, visit); err != nil {
			return err
		}
	}
}

func streamCopyDirectory(ctx context.Context, filename string, filesystem copyEnumerationFS, state *copyEnumerationState,
	visit func(string, fs.DirEntry, error) error) (finalErr error) {
	directory, err := filesystem.OpenDirectory(filename)
	if err != nil {
		return visit(filename, nil, err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			finalErr = errors.Join(finalErr, visit(filename, nil, err))
		}
	}()
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		entries, readErr := directory.ReadDir(copyDirectoryBatch)
		// A test adapter must uphold the same bounded ReadDir contract as os.File.
		if len(entries) > copyDirectoryBatch {
			return errors.New("source directory reader exceeded bounded descriptor batch")
		}
		// Files first within this one bounded batch. It does not sort or retain
		// later batches, and keeps folder preparation from blocking ready files.
		var discovered []string
		for _, directories := range []bool{false, true} {
			for _, entry := range entries {
				if entry.IsDir() != directories {
					continue
				}
				if ctx.Err() != nil {
					return context.Cause(ctx)
				}
				name := entry.Name()
				if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
					return errors.New("source returned an invalid directory entry name")
				}
				child := filepath.Join(filename, name)
				var entryErr error
				if err := validCopyStatePath(child); err != nil {
					entryErr = err
				}
				if entry.IsDir() && entryErr == nil {
					discovered = append(discovered, child)
					continue
				}
				err := visit(child, entry, entryErr)
				if errors.Is(err, fs.SkipDir) {
					continue
				}
				if err != nil {
					return err
				}
			}
		}
		if err := state.pushDirectories(ctx, discovered); err != nil {
			return errors.Join(errCopyEnumerationState, err)
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return visit(filename, nil, readErr)
		}
		if len(entries) == 0 {
			return visit(filename, nil, io.ErrNoProgress)
		}
	}
}
