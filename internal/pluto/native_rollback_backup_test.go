package pluto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type nativeRollbackFile struct {
	Path     string `json:"path"`
	Relative string `json:"relative"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	Mode     uint32 `json:"mode"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
}
type nativeRollbackBackup struct {
	root  string
	files []nativeRollbackFile
}

func nativeRollbackDirectorySync(t *testing.T, directory string) {
	t.Helper()
	f, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	syncErr, closeErr := f.Sync(), f.Close()
	if syncErr != nil || closeErr != nil {
		t.Fatal(syncErr, closeErr)
	}
}
func nativeRollbackWrite(t *testing.T, filename string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	for directory := filepath.Dir(filename); ; directory = filepath.Dir(directory) {
		nativeRollbackDirectorySync(t, directory)
		if directory == filepath.Dir(directory) {
			break
		}
	}
}
func nativeRollbackRead(t *testing.T, filename string) ([]byte, nativeRollbackFile) {
	t.Helper()
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		t.Fatal("absolute canonical fixture input required")
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 65536 {
		t.Fatal("bounded regular rollback input", filename, err)
	}
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, 65537))
	syncErr, closeErr := f.Sync(), f.Close()
	if readErr != nil || syncErr != nil || closeErr != nil || int64(len(raw)) != info.Size() {
		t.Fatal(readErr, syncErr, closeErr)
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Nlink != 1 || identity.Uid != uint32(os.Getuid()) {
		t.Fatal("private original rollback identity required")
	}
	digest := sha256.Sum256(raw)
	return raw, nativeRollbackFile{Path: filename, Relative: strings.TrimPrefix(filename, "/"), Bytes: int64(len(raw)), SHA256: hex.EncodeToString(digest[:]), Mode: uint32(info.Mode().Perm()), Device: uint64(identity.Dev), Inode: identity.Ino}
}
func qualifyNativeRollbackBackup(t *testing.T) *nativeRollbackBackup {
	t.Helper()
	if t.Name() != "TestStage3C12NativeIncompatibleRollbackRetainsJournal" {
		t.Fatal("specific native rollback fixture required")
	}
	root := os.Getenv("PLUTO_ROLLBACK_BACKUP_DIR")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("absolute Root-admitted rollback backup directory required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private rollback backup root required", err)
	}
	for _, absent := range []string{"/var/lib/pluto/indexed", "/etc/pluto/config.json"} {
		if _, err := os.Lstat(absent); !os.IsNotExist(err) {
			t.Fatal("negative installer fixture must have no DB or config", absent, err)
		}
	}
	directory, err := os.MkdirTemp(root, "snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	backup := &nativeRollbackBackup{root: directory}
	for _, filename := range []string{"/usr/local/bin/pluto", "/usr/local/bin/pluto.previous", "/usr/local/bin/pluto.update-pending", "/var/lib/pluto/indexed-activation.json"} {
		raw, entry := nativeRollbackRead(t, filename)
		nativeRollbackWrite(t, filepath.Join(directory, "backup", entry.Relative), raw, os.FileMode(entry.Mode))
		restored := filepath.Join(directory, "restored", entry.Relative)
		nativeRollbackWrite(t, restored, raw, os.FileMode(entry.Mode))
		for _, copyRoot := range []string{"backup", "restored"} {
			copied, copyInfo := nativeRollbackRead(t, filepath.Join(directory, copyRoot, entry.Relative))
			if copyInfo.SHA256 != entry.SHA256 || copyInfo.Mode != entry.Mode || string(copied) != string(raw) || copyInfo.Inode == entry.Inode && copyInfo.Device == entry.Device {
				t.Fatal("actual independent file restore differs")
			}
		}
		backup.files = append(backup.files, entry)
	}
	err = requireIndexedWriter(context.Background(), filepath.Join(directory, "restored/usr/local/bin/pluto.previous"), filepath.Join(directory, "restored/var/lib/pluto"))
	if err == nil || !strings.Contains(err.Error(), "binary cannot read activated indexed state") {
		t.Fatal("restored negative writer contract did not refuse", err)
	}
	proof := map[string]any{"schema": "pluto.native-rollback-fixture-backup.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "files": backup.files, "DBPresent": false, "configPresent": false, "restoredProductProbe": "INCOMPATIBLE_DECLARED_WRITER_REFUSED", "historicalReader": false}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	nativeRollbackWrite(t, filepath.Join(directory, "verified-backup.json"), append(raw, '\n'), 0600)
	backup.verifyOriginals(t, false)
	t.Logf("NATIVE_ROLLBACK_BACKUP_QUALIFIED directory=%s files=%d", directory, len(backup.files))
	return backup
}
func (backup *nativeRollbackBackup) verifyOriginals(t *testing.T, after bool) {
	t.Helper()
	for _, original := range backup.files {
		_, current := nativeRollbackRead(t, original.Path)
		if current != original {
			t.Fatal("rollback mutated original fixture", original.Path)
		}
	}
	if after {
		raw, err := json.Marshal(map[string]any{"schema": "pluto.native-rollback-after.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "originalFilesUnchanged": true, "files": backup.files, "historicalReader": false})
		if err != nil {
			t.Fatal(err)
		}
		nativeRollbackWrite(t, filepath.Join(backup.root, "verified-after.json"), append(raw, '\n'), 0600)
		t.Logf("NATIVE_ROLLBACK_ORIGINALS_UNCHANGED directory=%s files=%d", backup.root, len(backup.files))
	}
}

// Candidate probes execute read-only synthetic scripts. Preserve their real
// bytes and the exact in-memory expected archive/contract before cancellation.
type candidateCommandBackup struct {
	root     string
	original nativeRollbackFile
	probe    int
}

func qualifyCandidateCommandBackup(t *testing.T, filename string, probe int, release Release, archive []byte) *candidateCommandBackup {
	t.Helper()
	if t.Name() != "TestCandidateLicenseAndVersionProbesBoundOutputAndCancellation" || probe < 0 || probe > 3 || len(archive) == 0 || len(archive) > runtimeNoticeMaximum {
		t.Fatal("specific bounded candidate probe fixture required")
	}
	root := os.Getenv("PLUTO_COMMAND_PROBE_BACKUP_DIR")
	if root == "" {
		root = t.TempDir()
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("canonical candidate backup root required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private candidate backup root", err)
	}
	raw, original := nativeRollbackRead(t, filename)
	config, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(root, "candidate-")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"candidate": raw, "release.json": config, "notices.tar": archive}
	entries := []map[string]any{}
	for _, name := range []string{"candidate", "release.json", "notices.tar"} {
		data := files[name]
		mode := os.FileMode(0600)
		if name == "candidate" {
			mode = os.FileMode(original.Mode)
		}
		sum := sha256.Sum256(data)
		for _, kind := range []string{"backup", "restored"} {
			copyPath := filepath.Join(directory, kind, name)
			nativeRollbackWrite(t, copyPath, data, mode)
			readBack, err := os.ReadFile(copyPath)
			metadata, statErr := os.Lstat(copyPath)
			if err != nil || statErr != nil || !metadata.Mode().IsRegular() || metadata.Mode().Perm() != mode || string(readBack) != string(data) {
				t.Fatal("candidate fixture copy/restore differs", err, statErr)
			}
		}
		entries = append(entries, map[string]any{"name": name, "bytes": len(data), "mode": uint32(mode), "sha256": hex.EncodeToString(sum[:])})
	}
	restoredArchive, err := os.ReadFile(filepath.Join(directory, "restored/notices.tar"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifiedRuntimeNotices(restoredArchive, Artifact{Size: int64(len(archive)), SHA256: func() string { d := sha256.Sum256(archive); return hex.EncodeToString(d[:]) }()}); err != nil {
		t.Fatal("restored actual notice archive invalid", err)
	}
	proof := map[string]any{"schema": "pluto.candidate-command-backup.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "probe": probe, "original": original, "entries": entries, "DBPresent": false, "configKind": "actual expected Release argument", "restoredNoticesVerified": true, "historicalReader": false}
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	nativeRollbackWrite(t, filepath.Join(directory, "verified-backup.json"), append(proofRaw, '\n'), 0600)
	t.Logf("CANDIDATE_COMMAND_BACKUP_QUALIFIED probe=%d directory=%s", probe, directory)
	return &candidateCommandBackup{root: directory, original: original, probe: probe}
}
func (backup *candidateCommandBackup) verifyAfter(t *testing.T) {
	t.Helper()
	_, current := nativeRollbackRead(t, backup.original.Path)
	if current != backup.original {
		t.Fatal("read-only candidate input changed")
	}
	raw, err := json.Marshal(map[string]any{"schema": "pluto.candidate-command-after.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "probe": backup.probe, "original": current, "originalUnchanged": true, "historicalReader": false})
	if err != nil {
		t.Fatal(err)
	}
	nativeRollbackWrite(t, filepath.Join(backup.root, "verified-after.json"), append(raw, '\n'), 0600)
	t.Logf("CANDIDATE_COMMAND_ORIGINAL_UNCHANGED probe=%d directory=%s", backup.probe, backup.root)
}
