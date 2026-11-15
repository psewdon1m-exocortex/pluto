//go:build linux

package nativefixture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	c "pluto/internal/testsupport/nativeprocess/custody"
)

type fileView struct {
	Device, Inode uint64
	Bytes         int64
	SHA256        string
}
type observed struct {
	Core           c.Tuple
	Group, Session int
	Namespaces     [3]string
}

func publicReadonly(p string, mode os.FileMode) error {
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() || i.Mode().Perm() != mode || s.Uid != 0 || s.Gid != 0 {
		return errors.New("Root0 immutable public input required")
	}
	return nil
}

func boundedRead(p string, n int64, nofollow bool) ([]byte, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC
	if nofollow {
		flags |= unix.O_NOFOLLOW
	}
	fd, e := unix.Open(p, flags, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() {
		return nil, errors.New("bounded regular input")
	}
	b, e := io.ReadAll(io.LimitReader(f, n+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > n {
		return nil, errors.New("input exceeds bound")
	}
	return b, nil
}
func fingerprint(a Artifact, p string, procExe bool) (fileView, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC
	if !procExe {
		flags |= unix.O_NOFOLLOW
	}
	fd, e := unix.Open(p, flags, 0)
	if e != nil {
		return fileView{}, e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return fileView{}, e
	}
	s, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != 0555 || before.Mode()&^(os.ModePerm) != 0 || s.Uid != 0 || s.Gid != 0 || before.Size() != a.Bytes || a.Bytes <= 0 || a.Bytes > MaxArtifact {
		return fileView{}, errors.New("Root0 regular0555/no-setid exact-size staged artifact")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, MaxArtifact+1))
	if e != nil || n != a.Bytes {
		return fileView{}, errors.New("complete bounded artifact read")
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return fileView{}, errors.New("artifact changed during read")
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if digest != a.SHA256 {
		return fileView{}, errors.New("Root manifest artifact SHA mismatch")
	}
	if !procExe {
		now, e := os.Lstat(p)
		if e != nil || now.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, now) {
			return fileView{}, errors.New("artifact pathname changed")
		}
	}
	return fileView{uint64(s.Dev), s.Ino, n, digest}, nil
}
func privateDirectory(p string, create bool) error {
	if !cleanAbsolute(p) {
		return errors.New("clean absolute own directory")
	}
	if create {
		if e := os.Mkdir(p, 0700); e != nil {
			return e
		}
	}
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0700 || s.Uid != 10001 || s.Gid != 10001 {
		return errors.New("UID10001 private0700 exact directory")
	}
	return nil
}
func withinPrivate(root, p string, allowMissingLeaf bool) error {
	if !beneath(root, p) {
		return errors.New("outside exact retained fixture")
	}
	if e := privateDirectory(root, false); e != nil {
		return e
	}
	rel, _ := filepath.Rel(root, p)
	parts := strings.Split(rel, string(os.PathSeparator))
	current := root
	for n, part := range parts {
		current = filepath.Join(current, part)
		i, e := os.Lstat(current)
		if os.IsNotExist(e) && n == len(parts)-1 && allowMissingLeaf {
			return nil
		}
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return errors.New("reparse/symlink input refused")
		}
		if n < len(parts)-1 && !i.IsDir() {
			return errors.New("non-directory ancestor")
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 10001 || s.Gid != 10001 || i.Mode().Perm()&0077 != 0 {
			return errors.New("foreign/unprotected fixture member")
		}
	}
	return nil
}
func birth(pid int) (c.Birth, error) {
	raw, e := boundedRead(fmt.Sprintf("/proc/%d/stat", pid), c.MaxStat, true)
	if e != nil {
		return c.Birth{}, e
	}
	return c.ParseStat(raw)
}
func parseGroupSession(raw []byte) (int, int, error) {
	if _, e := c.ParseStat(raw); e != nil {
		return 0, 0, e
	}
	i := strings.LastIndex(string(raw), ") ")
	f := strings.Fields(string(raw)[i+2:])
	parse := func(v string) (int, error) {
		if v == "" || strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return 0, errors.New("unsigned pgrp/session")
		}
		n, e := strconv.ParseUint(v, 10, 31)
		if e != nil || n == 0 {
			return 0, errors.New("positive bounded pgrp/session")
		}
		return int(n), nil
	}
	g, e := parse(f[2])
	if e != nil {
		return 0, 0, e
	}
	s, e := parse(f[3])
	return g, s, e
}
func namespaces(pid int) ([3]string, error) {
	var out [3]string
	for i, n := range []string{"mnt", "pid", "user"} {
		v, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, n))
		if e != nil {
			return out, e
		}
		out[i] = v
	}
	return out, nil
}
func profile(pid int) (c.Profile, error) {
	b, e := boundedRead(fmt.Sprintf("/proc/%d/status", pid), c.MaxStatus, true)
	if e != nil {
		return c.Profile{}, e
	}
	return c.ParseStatus(b)
}
func selfProfile() error {
	p, e := profile(os.Getpid())
	if e != nil {
		return e
	}
	return c.RequireRuntimeProfile(p)
}
func fdTarget(fd int) (int, error) {
	b, e := boundedRead(fmt.Sprintf("/proc/self/fdinfo/%d", fd), 4096, true)
	if e != nil {
		return 0, e
	}
	return c.ParsePIDFDTarget(b)
}

func observe(pid, fd int, a Artifact, argv []string, expectedParent c.Birth, expectedNS [3]string, candidate fileView) (observed, error) {
	var out observed
	target, e := fdTarget(fd)
	if e != nil || target != pid {
		return out, errors.New("same Start pidfd live target unavailable")
	}
	raw, e := boundedRead(fmt.Sprintf("/proc/%d/stat", pid), c.MaxStat, true)
	if e != nil {
		return out, e
	}
	b, e := c.ParseStat(raw)
	if e != nil {
		return out, e
	}
	g, s, e := parseGroupSession(raw)
	if e != nil {
		return out, e
	}
	parent, e := birth(expectedParent.PID)
	if e != nil {
		return out, e
	}
	exe, e := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if e != nil {
		return out, e
	}
	actual, e := fingerprint(a, fmt.Sprintf("/proc/%d/exe", pid), true)
	if e != nil {
		return out, e
	}
	if actual != candidate {
		return out, errors.New("actual exe is not Root-admitted inode/bytes")
	}
	argsRaw, e := boundedRead(fmt.Sprintf("/proc/%d/cmdline", pid), c.MaxCmdline, true)
	if e != nil {
		return out, e
	}
	args, e := c.ParseCmdline(argsRaw)
	if e != nil {
		return out, e
	}
	p, e := profile(pid)
	if e != nil {
		return out, e
	}
	ns, e := namespaces(pid)
	if e != nil {
		return out, e
	}
	after, e := birth(pid)
	if e != nil {
		return out, e
	}
	again, e := fdTarget(fd)
	if e != nil || again != pid || b.PID != after.PID || b.PPID != after.PPID || b.Ticks != after.Ticks {
		return out, errors.New("live pidfd/birth identity changed")
	}
	expected := c.Tuple{Birth: b, Parent: expectedParent, PIDFDTarget: pid, Exe: a.Path, ExeSHA256: a.SHA256, Argv: argv, Profile: c.Profile{UID: [4]uint32{10001, 10001, 10001, 10001}, GID: [4]uint32{10001, 10001, 10001, 10001}, Groups: []uint32{}, NNP: 1, Seccomp: 2}}
	expected.Birth.PPID = expectedParent.PID
	out = observed{Core: c.Tuple{Birth: after, Parent: parent, PIDFDTarget: pid, Exe: exe, ExeSHA256: actual.SHA256, Argv: args, Profile: p}, Group: g, Session: s, Namespaces: ns}
	if e = c.CheckTuple(expected, out.Core, out.Core, c.Handle{OwnStartPID: pid, AtomicPIDFD: true, FD: fd}); e != nil {
		return out, e
	}
	parentStat, e := boundedRead(fmt.Sprintf("/proc/%d/stat", parent.PID), c.MaxStat, true)
	if e != nil {
		return out, e
	}
	_, parentSession, e := parseGroupSession(parentStat)
	if e != nil || g != pid || s != parentSession || ns != expectedNS {
		return out, errors.New("pgrp/session/namespace mismatch")
	}
	return out, nil
}

func durableNew(dir, name string, value any) error {
	if filepath.Base(name) != name {
		return errors.New("fixed receipt name")
	}
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	if len(raw) > MaxPacket {
		return errors.New("receipt bound")
	}
	fd, e := unix.Open(filepath.Join(dir, name), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), name)
	n, we := f.Write(append(raw, '\n'))
	if we == nil && n != len(raw)+1 {
		we = io.ErrShortWrite
	}
	se := f.Sync()
	ce := f.Close()
	if e = errors.Join(we, se, ce); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
