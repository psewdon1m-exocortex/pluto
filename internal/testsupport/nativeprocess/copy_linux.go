//go:build linux

package nativefixture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

type copyEntry struct {
	Relative  string
	Directory bool
	Bytes     int64
	SHA       string
	Mode      uint32
}

func copyInventory(root string, maximum int64) ([]copyEntry, error) {
	var out []copyEntry
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, prior error) error {
		if prior != nil {
			return prior
		}
		if len(out) >= 20000 {
			return errors.New("collector entry bound")
		}
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return errors.New("collector refuses symlink")
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		entry := copyEntry{Relative: rel, Directory: i.IsDir(), Mode: uint32(i.Mode().Perm())}
		if !i.IsDir() {
			if !i.Mode().IsRegular() || i.Size() < 0 || i.Size() > maximum-total {
				return errors.New("collector special/byte bound")
			}
			total += i.Size()
			entry.Bytes = i.Size()
			fd, e := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				return e
			}
			f := os.NewFile(uintptr(fd), p)
			before, e := f.Stat()
			if e != nil {
				f.Close()
				return e
			}
			if !os.SameFile(i, before) {
				f.Close()
				return errors.New("collector file incarnation changed")
			}
			h := sha256.New()
			n, re := io.Copy(h, io.LimitReader(f, maximum+1))
			after, se := f.Stat()
			ce := f.Close()
			if e = errors.Join(re, se, ce); e != nil {
				return e
			}
			if n != i.Size() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				return errors.New("collector input changed during hash")
			}
			entry.SHA = hex.EncodeToString(h.Sum(nil))
		}
		out = append(out, entry)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Relative < out[j].Relative })
	return out, err
}
