package pluto

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const runtimeNoticeAsset = "pluto-runtime-notices.tar"
const runtimeNoticeFormat = "pluto-runtime-notices.tar.v1"
const runtimeNoticeMaximum = 2 << 20

var runtimeNoticeHashes = map[string]string{
	"LICENSE":              "c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822",
	"LICENSE-3RD-PARTY.md": "b4366b9c27a9364633e015011a231913ed19bf1228f335bf617e50a6f7b168a6",
	"LICENSE-SQLITE":       "8438c9c89b849131ead81d5435cb97fcf052df5b0b286dda8a2d4c29e6cb3fd0",
	"LICENSE-SQLITE_VEC":   "6ce72bbe12d975bd5286e5ab0a064c069693300c47bccbc57bec18485f1621ea",
}

// Verify every byte and all member names before creating installation files.
func verifiedRuntimeNotices(raw []byte, a Artifact) (map[string][]byte, error) {
	hash := sha256.Sum256(raw)
	if len(raw) > runtimeNoticeMaximum || int64(len(raw)) != a.Size || hex.EncodeToString(hash[:]) != a.SHA256 || len(raw)%512 != 0 || len(raw) < 1024 || !bytes.Equal(raw[len(raw)-1024:], make([]byte, 1024)) {
		return nil, errors.New("release notice checksum/size verification failed")
	}
	source := bytes.NewReader(raw)
	reader := tar.NewReader(source)
	files := map[string][]byte{}
	for {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		_, pinned := runtimeNoticeHashes[h.Name]
		if (!pinned && h.Name != "INVENTORY.json") || h.Typeflag != tar.TypeReg || h.Format != tar.FormatUSTAR || h.Linkname != "" || h.Size < 1 || h.Size > runtimeNoticeMaximum {
			return nil, errors.New("release notice archive member rejected")
		}
		if _, duplicate := files[h.Name]; duplicate {
			return nil, errors.New("release notice archive duplicate member")
		}
		content, err := io.ReadAll(io.LimitReader(reader, h.Size+1))
		if err != nil || int64(len(content)) != h.Size {
			return nil, errors.New("release notice archive truncated")
		}
		files[h.Name] = content
	}
	tail, _ := io.ReadAll(source)
	if len(files) != 5 || bytes.Count(tail, []byte{0}) != len(tail) {
		return nil, errors.New("release notice archive inventory rejected")
	}
	for name, want := range runtimeNoticeHashes {
		h := sha256.Sum256(files[name])
		if hex.EncodeToString(h[:]) != want {
			return nil, fmt.Errorf("pinned notice bytes differ: %s", name)
		}
	}
	var inventory struct {
		Schema int    `json:"schema"`
		Driver string `json:"driver"`
		Files  []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
			Size   int    `json:"size"`
		} `json:"files"`
		LinkedModules map[string][]struct {
			Path    string `json:"path"`
			Version string `json:"version"`
			Sum     string `json:"sum"`
		} `json:"linkedModules"`
	}
	if json.Unmarshal(files["INVENTORY.json"], &inventory) != nil || inventory.Schema != 1 || inventory.Driver != "modernc.org/sqlite@v1.60.1" || len(inventory.Files) != 4 {
		return nil, errors.New("notice inventory is invalid")
	}
	seen := map[string]bool{}
	for _, f := range inventory.Files {
		want, ok := runtimeNoticeHashes[f.Name]
		if !ok || seen[f.Name] || f.SHA256 != want || f.Size != len(files[f.Name]) {
			return nil, errors.New("notice inventory/source mismatch")
		}
		seen[f.Name] = true
	}
	for _, arch := range []string{"linux-amd64", "linux-arm64"} {
		driver, libc := false, false
		seen = map[string]bool{}
		for _, m := range inventory.LinkedModules[arch] {
			if m.Path == "" || m.Version == "" || !strings.HasPrefix(m.Sum, "h1:") || seen[m.Path] {
				return nil, errors.New("notice linked module inventory is invalid")
			}
			seen[m.Path] = true
			driver = driver || (m.Path == "modernc.org/sqlite" && m.Version == "v1.60.1")
			libc = libc || (m.Path == "modernc.org/libc" && m.Version == "v1.77.1")
		}
		if !driver || !libc {
			return nil, errors.New("notice linked SQLite runtime is missing")
		}
	}
	return files, nil
}
func stageRuntimeNotices(parent string, files map[string][]byte) (string, error) {
	dir, err := os.MkdirTemp(parent, ".pluto-notices-*")
	if err != nil {
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	if len(files) != 5 {
		return "", errors.New("notice staging inventory mismatch")
	}
	for name, content := range files {
		_, ok := runtimeNoticeHashes[name]
		if !ok && name != "INVENTORY.json" {
			return "", errors.New("unsafe notice path")
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return "", err
		}
		_, err = f.Write(content)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	if err = os.Chmod(dir, 0755); err != nil {
		return "", err
	}
	if err = syncParent(filepath.Join(dir, "INVENTORY.json")); err != nil {
		return "", err
	}
	success = true
	return dir, nil
}

type noticeUpdateIntent struct {
	Schema     string `json:"schema"`
	HadNotices bool   `json:"hadNotices"`
}

func noticeDirectory(executable string) string { return executable + ".notices" }
func safeNoticeDirectory(name string) (bool, error) {
	stat, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("notice directory requires reconciliation")
	}
	return true, nil
}
func recoverNoticeUpdate(executable string, raw []byte, systemctl func(string) error) error {
	var intent noticeUpdateIntent
	var fields map[string]json.RawMessage
	if len(raw) > 1024 || json.Unmarshal(raw, &intent) != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["hadNotices"] == nil || fields["schema"] == nil || intent.Schema != "pluto-replacement-v2" {
		return errors.New("invalid notice update journal; operator reconciliation required")
	}
	canonical, _ := json.Marshal(intent)
	if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return errors.New("noncanonical notice update journal; operator reconciliation required")
	}
	notices, backup := noticeDirectory(executable), executable+".previous"
	oldNotices := notices + ".previous"
	hasOld, err := safeNoticeDirectory(oldNotices)
	if err != nil {
		return err
	}
	if !intent.HadNotices && hasOld {
		return errors.New("unexpected previous notices; reconciliation required")
	}
	binaryBackup, err := os.Lstat(backup)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if binaryBackup != nil && (!binaryBackup.Mode().IsRegular() || binaryBackup.Mode()&os.ModeSymlink != 0) {
		return errors.New("previous binary requires reconciliation")
	}
	currentNotices, err := safeNoticeDirectory(notices)
	if err != nil {
		return err
	}
	if (hasOld && binaryBackup == nil) || (intent.HadNotices && !hasOld && !currentNotices) {
		return errors.New("notice update artifacts are incomplete; reconciliation required")
	}
	if binaryBackup != nil || hasOld || !intent.HadNotices {
		if err = systemctl("stop"); err != nil {
			return errors.New("interrupted notice update recovery requires service stop")
		}
		if binaryBackup != nil {
			if err = requireInstalledRollback(executable, backup); err != nil {
				return err
			}
		}
		if hasOld || !intent.HadNotices {
			if _, err = safeNoticeDirectory(notices); err != nil {
				return err
			}
			if err = os.RemoveAll(notices); err != nil {
				return err
			}
			if hasOld {
				if err = os.Rename(oldNotices, notices); err != nil {
					return err
				}
			}
		}
		if binaryBackup != nil {
			if err = os.Rename(backup, executable); err != nil {
				return err
			}
		}
		if err = syncParent(executable); err != nil {
			return err
		}
	}
	if _, err = os.Stat(executable); err != nil {
		return err
	}
	if err = systemctl("start"); err != nil {
		return errors.New("previous binary/notices restored but service restart failed")
	}
	if err = os.Remove(executable + ".update-pending"); err != nil {
		return err
	}
	return syncParent(executable)
}
func installCandidateWithNotices(executable, candidate, stagedNotices string, systemctl func(string) error, healthy func() bool, timeout time.Duration) error {
	notices, backup, journal := noticeDirectory(executable), executable+".previous", executable+".update-pending"
	for _, name := range []string{backup, notices + ".previous", journal} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("previous update artifacts require reconciliation")
		}
	}
	for _, name := range []string{executable, candidate} {
		stat, err := os.Lstat(name)
		if err != nil {
			return err
		}
		if !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 {
			return errors.New("update binary path is not a regular file")
		}
	}
	hadNotices, err := safeNoticeDirectory(notices)
	if err != nil {
		return err
	}
	if ok, err := safeNoticeDirectory(stagedNotices); err != nil || !ok {
		return errors.New("staged notices are missing or unsafe")
	}
	intent, err := json.Marshal(noticeUpdateIntent{"pluto-replacement-v2", hadNotices})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(journal, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(intent, '\n'))
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	if err == nil {
		err = syncParent(executable)
	}
	if err != nil {
		return err
	}
	if err = systemctl("stop"); err != nil {
		_ = systemctl("restart")
		_ = os.Remove(journal)
		_ = syncParent(executable)
		return errors.New("Pluto could not be stopped for notice update")
	}
	rollback := func(cause error) error {
		if e := recoverInterruptedUpdate(executable, systemctl); e != nil {
			return e
		}
		return cause
	}
	if err = os.Link(executable, backup); err != nil {
		return rollback(err)
	}
	if err = syncParent(executable); err != nil {
		return rollback(err)
	}
	if hadNotices {
		if err = os.Rename(notices, notices+".previous"); err != nil {
			return rollback(err)
		}
		if err = syncParent(executable); err != nil {
			return rollback(err)
		}
	}
	if err = os.Rename(stagedNotices, notices); err != nil {
		return rollback(err)
	}
	if err = syncParent(executable); err != nil {
		return rollback(err)
	}
	if err = os.Rename(candidate, executable); err != nil {
		return rollback(err)
	}
	if err = syncParent(executable); err != nil {
		return rollback(err)
	}
	if err = systemctl("start"); err != nil {
		return rollback(errors.New("new Pluto failed to start; previous binary/notices restored"))
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if healthy() {
			if err = os.Remove(journal); err != nil {
				return err
			}
			if err = syncParent(executable); err != nil {
				return err
			}
			if err = os.Remove(backup); err != nil {
				return err
			}
			if hadNotices {
				if err = os.RemoveAll(notices + ".previous"); err != nil {
					return err
				}
			}
			return syncParent(executable)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return rollback(errors.New("updated Pluto did not become healthy; previous binary/notices restored"))
}
