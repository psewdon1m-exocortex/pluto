package pluto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"pluto/internal/pluto/syncstate"
)

// Unknown artifacts retain their disk charge after a crash by blocking new
// admission. Only a future qualified intent reconciler may dispose of them.
var ErrSourceCaptureArtifactsUnreconciled = errors.New("source capture artifacts require reconciliation before new admission")

var sourceCaptureCreation = make(chan struct{}, 1)
var sourceCaptureLive = struct {
	sync.Mutex
	files map[string]os.FileInfo
}{files: make(map[string]os.FileInfo)}

type sourceCaptureBudget struct {
	directory string
	filename  string
	gate      bool
}

func (b *sourceCaptureBudget) releaseCreation() {
	if b.gate {
		b.gate = false
		<-sourceCaptureCreation
	}
}

func knownCaptureArtifacts(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			filename := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(filename)
			if err != nil {
				return err
			}
			sourceCaptureLive.Lock()
			known := sourceCaptureLive.files[filename]
			sourceCaptureLive.Unlock()
			if known == nil || !info.Mode().IsRegular() || !os.SameFile(info, known) {
				return fmt.Errorf("%w: %s", ErrSourceCaptureArtifactsUnreconciled, filename)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (b *sourceCaptureBudget) ReserveCapture(ctx context.Context, dir string, size int64) (func(), error) {
	if err := copyResources.acquireWorker(ctx); err != nil {
		return nil, err
	}
	if err := acquireCopySlot(ctx, sourceCaptureCreation); err != nil {
		copyResources.releaseWorker()
		return nil, err
	}
	b.gate, b.directory = true, filepath.Clean(dir)
	if err := knownCaptureArtifacts(b.directory); err != nil {
		if errors.Is(err, ErrSourceCaptureArtifactsUnreconciled) {
			// Until a qualified artifact reconciler exists, unknown retained bytes
			// must prevent legacy Copy from spending a second plaintext budget too.
			copyResources.blockSpool(err)
		}
		b.releaseCreation()
		copyResources.releaseWorker()
		return nil, err
	}
	if err := copyResources.reserveSpool(ctx, dir, size); err != nil {
		b.releaseCreation()
		copyResources.releaseWorker()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			b.releaseCreation()
			sourceCaptureLive.Lock()
			delete(sourceCaptureLive.files, b.filename)
			sourceCaptureLive.Unlock()
			copyResources.releaseSpool(size)
			copyResources.releaseWorker()
		})
	}, nil
}
func (b *sourceCaptureBudget) RegisterCaptureArtifact(filename string, size int64) error {
	if !b.gate || b.filename != "" || filepath.Dir(filename) != b.directory || !strings.HasPrefix(filepath.Base(filename), "source-sealed-") || size < 0 || size > MaxFileBytes {
		return syncstate.ErrIdentityConflict
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return errors.Join(syncstate.ErrIdentityConflict, err)
	}
	sourceCaptureLive.Lock()
	if len(sourceCaptureLive.files) >= copyWorkers {
		sourceCaptureLive.Unlock()
		return syncstate.ErrSourceQuota
	}
	sourceCaptureLive.files[filename] = info
	sourceCaptureLive.Unlock()
	b.filename = filename
	b.releaseCreation()
	return nil
}
func (*sourceCaptureBudget) AcquireCaptureReader(ctx context.Context) (func(), error) {
	if err := copyResources.acquireReader(ctx); err != nil {
		return nil, err
	}
	return copyResources.releaseReader, nil
}

// CaptureSourceSnapshot is not connected to Copy/Serve. Its future executor must
// join every snapshot user before Close releases the existing process-wide spool.
func CaptureSourceSnapshot(ctx context.Context, w syncstate.SourceWitness, entry syncstate.SourceEntry, privateDirectory string) (*syncstate.VerifiedSnapshot, error) {
	return syncstate.CaptureGuarded(ctx, w, entry, privateDirectory, &sourceCaptureBudget{})
}
