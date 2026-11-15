package syncstate

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtureBackupEntry struct {
	Name      string
	Directory bool
	Mode      fs.FileMode
	Bytes     int64
	SHA256    string
}
type fixtureBackup struct{ directory, archiveSHA string }

// Closed local fixtures have no live writer or external backend. The caller
// supplies every physical source root and verifies a real restored product store.
func qualifyClosedFixtureBackup(t *testing.T, state string, sources []string, verify func(*Store)) *fixtureBackup {
	t.Helper()
	base, input := os.Getenv("PLUTO_FAULT_BACKUP_DIR"), os.Getenv("PLUTO_FAULT_INPUT_DIR")
	if base == "" || input == "" || !filepath.IsAbs(base) || !filepath.IsAbs(input) || filepath.Clean(base) != base || filepath.Clean(input) != input {
		t.Fatal("explicit fresh fixture backup/input roots required")
	}
	within := func(root, p string) bool {
		rel, e := filepath.Rel(root, p)
		return e == nil && rel != "." && filepath.IsLocal(rel)
	}
	if within(input, base) || within(base, input) || base == input {
		t.Fatal("independent fixture backup root required")
	}
	info, e := os.Lstat(base)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private admitted fixture backup root", e)
	}
	roots := append([]string{state}, sources...)
	for _, root := range roots {
		resolved, e := filepath.EvalSymlinks(root)
		if e != nil || resolved != root || !within(input, root) {
			t.Fatal("source outside exact fixture root", root, e)
		}
	}
	for _, suffix := range []string{"-wal", "-journal"} {
		info, e := os.Stat(filepath.Join(state, "sync-state.sqlite") + suffix)
		if e == nil && info.Size() != 0 {
			t.Fatal("closed checkpoint required before fixture fault", suffix)
		}
		if e != nil && !os.IsNotExist(e) {
			t.Fatal(e)
		}
	}
	inventory := func() []fixtureBackupEntry {
		var result []fixtureBackupEntry
		var total int64
		for n, root := range roots {
			label := "state"
			if n > 0 {
				label = fmt.Sprintf("source-%03d", n)
			}
			e := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				info, e := d.Info()
				if e != nil {
					return e
				}
				rel, e := filepath.Rel(root, p)
				if e != nil {
					return e
				}
				name := label
				if rel != "." {
					name += "/" + filepath.ToSlash(rel)
				}
				entry := fixtureBackupEntry{Name: name, Directory: info.IsDir(), Mode: info.Mode().Perm()}
				if !info.IsDir() {
					if !info.Mode().IsRegular() {
						return fmt.Errorf("unsupported fixture object %s", name)
					}
					entry.Bytes = info.Size()
					total += info.Size()
					if total > 64<<20 {
						return fmt.Errorf("fixture graph exceeds admitted 64 MiB")
					}
					entry.SHA256, e = fileDigest(p)
					if e != nil {
						return e
					}
				}
				result = append(result, entry)
				if len(result) > 4096 {
					return fmt.Errorf("fixture graph exceeds admitted 4096 entries")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		return result
	}
	before := inventory()
	directory, e := os.MkdirTemp(base, "snapshot-")
	if e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(directory, "coherent-fixture.tar")
	output, e := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	tw := tar.NewWriter(output)
	for _, entry := range before {
		parts := strings.SplitN(entry.Name, "/", 2)
		index := 0
		if parts[0] != "state" {
			if _, e = fmt.Sscanf(parts[0], "source-%03d", &index); e != nil {
				t.Fatal(e)
			}
		}
		source := roots[index]
		if len(parts) == 2 {
			source = filepath.Join(source, filepath.FromSlash(parts[1]))
		}
		kind := byte(tar.TypeReg)
		if entry.Directory {
			kind = tar.TypeDir
		}
		if e = tw.WriteHeader(&tar.Header{Name: entry.Name, Mode: int64(entry.Mode.Perm()), Size: entry.Bytes, Typeflag: kind}); e != nil {
			t.Fatal(e)
		}
		if !entry.Directory {
			in, e := os.Open(source)
			if e != nil {
				t.Fatal(e)
			}
			n, copyErr := io.Copy(tw, in)
			closeErr := in.Close()
			if copyErr != nil || closeErr != nil || n != entry.Bytes {
				t.Fatal("fixture archive write", copyErr, closeErr)
			}
		}
	}
	if e = tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e = output.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = output.Close(); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, inventory()) {
		t.Fatal("fixture graph changed during checkpoint")
	}
	archiveSHA, e := fileDigest(archive)
	if e != nil {
		t.Fatal(e)
	}
	restored := filepath.Join(directory, "restored")
	if e = os.Mkdir(restored, 0700); e != nil {
		t.Fatal(e)
	}
	in, e := os.Open(archive)
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	tr := tar.NewReader(in)
	var directories []string
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		relative := filepath.FromSlash(h.Name)
		target := filepath.Join(restored, relative)
		if !filepath.IsLocal(relative) || !within(restored, target) {
			t.Fatal("nonlocal archive member")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.Mkdir(target, 0700); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(target, fs.FileMode(h.Mode)); e != nil {
				t.Fatal(e)
			}
			directories = append(directories, target)
		case tar.TypeReg:
			f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				t.Fatal(e)
			}
			n, copyErr := io.Copy(f, tr)
			modeErr := f.Chmod(fs.FileMode(h.Mode))
			syncErr := f.Sync()
			closeErr := f.Close()
			if copyErr != nil || modeErr != nil || syncErr != nil || closeErr != nil || n != h.Size {
				t.Fatal("fixture restore write", copyErr, syncErr, closeErr)
			}
		default:
			t.Fatal("unsupported archive member")
		}
	}
	for _, entry := range before {
		p := filepath.Join(restored, filepath.FromSlash(entry.Name))
		info, e := os.Lstat(p)
		if e != nil || info.IsDir() != entry.Directory || info.Mode().Perm() != entry.Mode {
			t.Fatal("restored fixture shape", e)
		}
		if !entry.Directory {
			digest, e := fileDigest(p)
			if e != nil || digest != entry.SHA256 || info.Size() != entry.Bytes {
				t.Fatal("restored fixture bytes", e)
			}
		}
	}
	for n := len(directories) - 1; n >= 0; n-- {
		syncFixtureDirectory(t, directories[n])
	}
	syncFixtureDirectory(t, restored)
	product, e := Open(testContext, filepath.Join(restored, "state"))
	if e != nil {
		t.Fatal("actual restored fixture store", e)
	}
	func() {
		defer func() {
			if closeErr := product.Close(); closeErr != nil {
				t.Error("restored fixture close", closeErr)
			}
		}()
		verify(product)
	}()
	if t.Failed() {
		t.Fatal("restored fixture precondition failed")
	}
	if !reflect.DeepEqual(before, inventory()) {
		t.Fatal("restored product probe changed original fixture")
	}
	raw, e := json.MarshalIndent(map[string]any{"schema": "pluto.closed-fixture-backup.v1", "case": t.Name(), "at": time.Now().UTC(), "state": state, "sources": sources, "archiveSHA256": archiveSHA, "entries": before, "productStoreOpened": true, "baselineEmpty": len(before) == len(roots)}, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(filepath.Join(directory, "verified-backup.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(append(raw, '\n')); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	syncFixtureDirectory(t, directory)
	syncFixtureDirectory(t, base)
	t.Logf("CLOSED_FIXTURE_BACKUP_QUALIFIED archiveSHA256=%s directory=%s", archiveSHA, directory)
	return &fixtureBackup{directory: directory, archiveSHA: archiveSHA}
}

func syncFixtureDirectory(t *testing.T, p string) {
	t.Helper()
	d, e := os.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil || closeErr != nil {
		t.Fatal("fixture directory sync", syncErr, closeErr)
	}
}

func (b *fixtureBackup) recordActualExit(t *testing.T, helper string, pid, code int) {
	t.Helper()
	if pid <= 0 || code < 1 || code > 255 {
		t.Fatal("actual expected fixture fault exit required")
	}
	raw, e := json.Marshal(map[string]any{"schema": "pluto.fixture-fault-actual-wait.v1", "case": t.Name(), "helper": helper, "pid": pid, "actualExitCode": code, "archiveSHA256": b.archiveSHA, "expectedFault": true, "graceful": false})
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(filepath.Join(b.directory, "actual-child-exit.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(append(raw, '\n')); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	syncFixtureDirectory(t, b.directory)
	t.Logf("FIXTURE_FAULT_ACTUAL_WAIT helper=%s pid=%d exit=%d", helper, pid, code)
}
