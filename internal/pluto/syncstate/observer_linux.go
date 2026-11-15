//go:build linux

package syncstate

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const maximumObserverWatches = 65536

type observedWatch struct {
	source, physical, destination string
	directory                     bool
}
type LinuxObserver struct {
	sources *Sources
	witness SourceWitness
	fd      int
	mu      sync.Mutex
	watches map[int][]observedWatch
	paths   map[string]bool
	cancel  context.CancelFunc
	done    chan struct{}
	wake    chan struct{}
	failed  atomic.Bool
	gap     atomic.Bool
}

func NewLinuxObserver(ctx context.Context, s *Sources, w SourceWitness) (*LinuxObserver, error) {
	if err := s.StartObserver(ctx, w); err != nil {
		return nil, err
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	child, cancel := context.WithCancel(ctx)
	o := &LinuxObserver{sources: s, witness: w, fd: fd, watches: map[int][]observedWatch{}, paths: map[string]bool{}, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	if err != nil {
		o.fd = -1
		o.failed.Store(true)
		o.markGap(ctx, "inotify unavailable; periodic guarded reconciliation")
		close(o.done)
		return o, nil
	}
	go o.read(child)
	return o, nil
}
func (o *LinuxObserver) Wake() <-chan struct{} { return o.wake }
func (o *LinuxObserver) signal() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}
func (o *LinuxObserver) Close() error {
	o.cancel()
	<-o.done
	if o.fd < 0 {
		return nil
	}
	return unix.Close(o.fd)
}
func (o *LinuxObserver) Healthy() bool { return !o.failed.Load() }
func (o *LinuxObserver) markGap(ctx context.Context, reason string) {
	o.gap.Store(true)
	if err := o.sources.ObserverGap(ctx, o.witness, reason); err != nil {
		o.failed.Store(true)
	}
	o.signal()
}

// Called before enumerating a directory and before dispatching its children.
// Inode watches include regular files so hardlink writes via another directory
// also invalidate a capture. Unsupported links/watch exhaustion retain a gap.
func (o *LinuxObserver) Watch(ctx context.Context, source, physical, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.fd < 0 || o.failed.Load() {
		return nil
	} // The durable gap keeps periodic capture mandatory.
	info, err := os.Lstat(physical)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		o.failed.Store(true)
		o.markGap(ctx, "symlink target requires periodic guarded observation")
		return nil
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return ErrIdentityConflict
	}
	key := source + "\x00" + physical
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.paths[key] {
		return nil
	}
	if len(o.paths) >= maximumObserverWatches {
		o.failed.Store(true)
		return ErrSourceQuota
	}
	flags := uint32(unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_CREATE | unix.IN_DELETE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_DONT_FOLLOW | unix.IN_MASK_ADD)
	if info.IsDir() {
		flags |= unix.IN_ONLYDIR
	}
	wd, err := unix.InotifyAddWatch(o.fd, physical, flags)
	if err != nil {
		o.failed.Store(true)
		return err
	}
	o.paths[key] = true
	o.watches[wd] = append(o.watches[wd], observedWatch{source, physical, destination, info.IsDir()})
	return nil
}
func (o *LinuxObserver) BeforeClaim(ctx context.Context, c FrontierClaim) error {
	scan, err := o.sources.Scan(ctx, c.ScanID)
	if err != nil {
		return err
	}
	if err = o.Watch(ctx, scan.SourceID, c.PhysicalPath, c.Destination); err != nil {
		o.markGap(ctx, "watch registration unavailable")
		return nil
	}
	return nil
}
func (o *LinuxObserver) ObserveEntry(ctx context.Context, source string, d SourceDescriptor) error {
	if err := o.Watch(ctx, source, d.PhysicalPath, d.Destination); err != nil {
		o.markGap(ctx, "child watch unavailable")
	}
	return nil
}
func (o *LinuxObserver) read(ctx context.Context) {
	defer close(o.done)
	buffer := make([]byte, 64<<10)
	for ctx.Err() == nil {
		poll := []unix.PollFd{{Fd: int32(o.fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 200); err != nil && !errors.Is(err, unix.EINTR) {
			o.failed.Store(true)
			o.markGap(ctx, "inotify poll failed")
			return
		}
		n, err := unix.Read(o.fd, buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			o.failed.Store(true)
			o.markGap(ctx, "inotify read failed")
			return
		}
		hints := make([]DirtyHint, 0, MaxSourcePage)
		flush := func() bool {
			if len(hints) == 0 {
				return true
			}
			err := o.sources.RecordDirty(ctx, o.witness, hints)
			hints = hints[:0]
			if err != nil {
				o.failed.Store(true)
				o.markGap(ctx, "durable event ingress failed")
				return false
			}
			o.signal()
			return true
		}
		for offset := 0; offset+16 <= n; {
			wd := int(int32(binary.NativeEndian.Uint32(buffer[offset:])))
			mask := binary.NativeEndian.Uint32(buffer[offset+4:])
			cookie := binary.NativeEndian.Uint32(buffer[offset+8:])
			length := int(binary.NativeEndian.Uint32(buffer[offset+12:]))
			offset += 16
			if length > n-offset {
				o.failed.Store(true)
				o.markGap(ctx, "truncated inotify record")
				return
			}
			name := strings.TrimRight(string(buffer[offset:offset+length]), "\x00")
			offset += length
			if mask&unix.IN_Q_OVERFLOW != 0 {
				o.markGap(ctx, "inotify queue overflow")
				continue
			}
			o.mu.Lock()
			watched := append([]observedWatch(nil), o.watches[wd]...)
			if mask&unix.IN_IGNORED != 0 {
				delete(o.watches, wd)
				for _, w := range watched {
					delete(o.paths, w.source+"\x00"+w.physical)
				}
			}
			o.mu.Unlock()
			if mask&(unix.IN_UNMOUNT|unix.IN_IGNORED) != 0 {
				o.markGap(ctx, "watch detached or filesystem unmounted")
			}
			for _, w := range watched {
				p, d := w.physical, w.destination
				if name != "" {
					if name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
						o.markGap(ctx, "invalid event path")
						continue
					}
					p = filepath.Join(p, name)
					d += "/" + name
				}
				hints = append(hints, DirtyHint{SourceID: w.source, Destination: d, PhysicalPath: p, Mask: mask, Cookie: cookie})
				if len(hints) == MaxSourcePage && !flush() {
					return
				}
			}
		}
		if !flush() {
			return
		}
	}
}

// Health checks root mount/boot/object identity; a cold owner can never claim
// continuity from an empty inotify queue. Periodic catch-up is still required
// for filesystems/workloads whose writes are not fully observable by inotify.
func (o *LinuxObserver) Health(ctx context.Context, ids []string) error {
	for _, id := range ids {
		b, err := o.sources.Binding(ctx, o.witness.SetID, id)
		if err != nil {
			return err
		}
		observed, err := ObserveSourceIncarnation(b.PhysicalPath)
		if err != nil || observed.object != b.Object {
			o.markGap(ctx, "source or mount identity changed")
			return errors.Join(err, ErrSourceIncomplete)
		}
	}
	if o.failed.Load() {
		return ErrSourceIncomplete
	}
	return nil
}

func (s *Sources) RetryDelay() time.Duration { return 750 * time.Millisecond }
