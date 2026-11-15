//go:build linux

package pluto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
)

type sourceOrphanContext struct {
	Witness  syncstate.SourceWitness
	Entry    syncstate.SourceEntry
	Evidence syncstate.SnapshotEvidence
}
type sourceOrphanFile struct {
	Label, Relative string
	Original        nativeRollbackFile
}
type sourceOrphanBackup struct {
	Schema, Case, At, Directory, State, Source, Spool                       string
	ContextSHA256                                                           string
	Files                                                                   []sourceOrphanFile
	OriginalPhysical                                                        []admissionPhysicalEntry
	Evidence                                                                syncstate.SnapshotEvidence
	RestoreProbePID, RestoreProbeExit                                       int
	RestoreProbeOutputSHA256                                                string
	RestoreProbe                                                            sourceOrphanProbe
	DatabasePresent, ProductConfigPresent, BackendPresent, HistoricalReader bool
}
type sourceOrphanProbe struct {
	Schema, Status, RestoreRoot, SHA256                      string
	SourceBytes, RetainedBytes                               int64
	NewCaptureRefused, LegacyRefused, PhysicalGraphUnchanged bool
	Workers, Readers, LiveFiles                              int
	SpoolBytes                                               int64
	HistoricalReader                                         bool
}

func sourceOrphanPhysical(t *testing.T, source, spool string) []admissionPhysicalEntry {
	t.Helper()
	var entries []admissionPhysicalEntry
	for _, root := range []string{source, spool} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != uint32(os.Getuid()) {
				return fmt.Errorf("private original physical owner required")
			}
			row := admissionPhysicalEntry{Path: p, Kind: "directory", Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, Bytes: info.Size(), MTimeNS: info.ModTime().UnixNano(), CTimeNS: st.Ctim.Sec*1e9 + st.Ctim.Nsec}
			if !info.IsDir() {
				if !info.Mode().IsRegular() || st.Nlink != 1 {
					return fmt.Errorf("original regular nlink1 required")
				}
				row.Kind = "file"
				row.SHA256, e = admissionFileDigest(p)
				if e != nil {
					return e
				}
			}
			entries = append(entries, row)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return entries
}
func sourceOrphanInput(t *testing.T, source, spool string) string {
	t.Helper()
	input, backup := os.Getenv("PLUTO_FAULT_INPUT_DIR"), os.Getenv("PLUTO_FAULT_BACKUP_DIR")
	within := func(root, p string) bool {
		rel, err := filepath.Rel(root, p)
		return err == nil && rel != "." && filepath.IsLocal(rel)
	}
	for _, root := range []string{input, backup, source, spool} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			t.Fatal("canonical explicit fixture paths required")
		}
		actual, err := filepath.EvalSymlinks(root)
		if err != nil || actual != root {
			t.Fatal("no link fixture root", err)
		}
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("private fixture directory", err)
		}
	}
	if !within(input, source) || !within(input, spool) || within(input, backup) || within(backup, input) || input == backup || within(source, spool) || within(spool, source) || source == spool {
		t.Fatal("separate admitted input/source/spool/backup roots required")
	}
	return backup
}
func qualifySourceOrphanBackup(t *testing.T, w syncstate.SourceWitness, entry syncstate.SourceEntry, v *syncstate.VerifiedSnapshot, spool string) {
	t.Helper()
	if t.Name() != "TestSourceCaptureOrphanSurvivesProcessRestart" {
		t.Fatal("specific original source orphan fixture required")
	}
	base := sourceOrphanInput(t, entry.SourceRootPath, spool)
	evidence := v.Evidence()
	if evidence.SizeBytes != 8 || entry.SizeBytes != 8 || evidence.SnapshotID == "" || entry.PhysicalPath != filepath.Join(entry.SourceRootPath, "file") {
		t.Fatal("original eight retained bytes required")
	}
	items, err := os.ReadDir(spool)
	if err != nil || len(items) != 1 || !strings.HasPrefix(items[0].Name(), "source-sealed-") {
		t.Fatal("one actual sealed artifact", err)
	}
	original := sourceOrphanPhysical(t, entry.SourceRootPath, spool)
	if len(original) != 4 {
		t.Fatal("exact original source/spool two-file graph required", len(original))
	}
	copyResources.mu.Lock()
	charged := copyResources.spoolBytes
	failed := copyResources.spoolFailure
	copyResources.mu.Unlock()
	if charged != 8 || failed != nil || len(copyResources.workers) != 1 || len(copyResources.readers) != 0 {
		t.Fatal("original capture remains live and sealed before fault")
	}
	sourceCaptureLive.Lock()
	known := sourceCaptureLive.files[filepath.Join(spool, items[0].Name())]
	liveCount := len(sourceCaptureLive.files)
	sourceCaptureLive.Unlock()
	if known == nil || liveCount != 1 {
		t.Fatal("actual original live capture registration required")
	}
	directory, err := os.MkdirTemp(base, "snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := sourceOrphanBackup{Schema: "pluto.source-orphan-backup.v1", Case: t.Name(), At: time.Now().UTC().Format(time.RFC3339Nano), Directory: directory, Source: entry.SourceRootPath, Spool: spool, Evidence: evidence, OriginalPhysical: original}
	contextRaw, err := json.MarshalIndent(sourceOrphanContext{Witness: w, Entry: entry, Evidence: evidence}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	contextRaw = append(contextRaw, '\n')
	digest := sha256.Sum256(contextRaw)
	checkpoint.ContextSHA256 = hex.EncodeToString(digest[:])
	for _, kind := range []string{"backup", "restored"} {
		nativeRollbackWrite(t, filepath.Join(directory, kind, "capture-context.json"), contextRaw, 0600)
	}
	for _, record := range []struct{ label, relative, filename string }{{"source", "source/file", entry.PhysicalPath}, {"retained", "spool/" + items[0].Name(), filepath.Join(spool, items[0].Name())}} {
		raw, info := nativeRollbackRead(t, record.filename)
		if len(raw) != 8 || string(raw) != "retained" || info.SHA256 != evidence.SHA256 {
			t.Fatal("actual retained/source original differs")
		}
		for _, kind := range []string{"backup", "restored"} {
			target := filepath.Join(directory, kind, record.relative)
			nativeRollbackWrite(t, target, raw, os.FileMode(info.Mode))
			copied, copyInfo := nativeRollbackRead(t, target)
			if string(copied) != string(raw) || copyInfo.Mode != info.Mode || copyInfo.SHA256 != info.SHA256 || copyInfo.Device == info.Device && copyInfo.Inode == info.Inode {
				t.Fatal("actual independent restored file differs")
			}
		}
		checkpoint.Files = append(checkpoint.Files, sourceOrphanFile{Label: record.label, Relative: record.relative, Original: info})
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestSourceCaptureOrphanSurvivesProcessRestart$")
	cmd.Env = append(os.Environ(), "PLUTO_SOURCE_ORPHAN_RESTORE_PROBE="+filepath.Join(directory, "restored"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("actual fresh restore probe", string(output), err)
	}
	first, tail, ok := bytes.Cut(output, []byte("\n"))
	if !ok || strings.TrimSpace(string(tail)) != "PASS" {
		t.Fatal("complete fresh probe test output", string(output))
	}
	var probe sourceOrphanProbe
	if err = json.Unmarshal(first, &probe); err != nil || probe.Status != "PASS_ACTUAL_RESTORED_ORPHAN_REFUSES_NEW_AND_LEGACY" || probe.RestoreRoot != filepath.Join(directory, "restored") || probe.SHA256 != evidence.SHA256 || probe.SourceBytes != 8 || probe.RetainedBytes != 8 || !probe.NewCaptureRefused || !probe.LegacyRefused || !probe.PhysicalGraphUnchanged || probe.Workers != 0 || probe.Readers != 0 || probe.LiveFiles != 0 || probe.SpoolBytes != 0 || probe.HistoricalReader {
		t.Fatal("actual restored product refusal proof", err)
	}
	checkpoint.RestoreProbePID = cmd.Process.Pid
	checkpoint.RestoreProbeExit = cmd.ProcessState.ExitCode()
	checkpoint.RestoreProbe = probe
	outSHA := sha256.Sum256(output)
	checkpoint.RestoreProbeOutputSHA256 = hex.EncodeToString(outSHA[:])
	nativeRollbackWrite(t, filepath.Join(directory, "restore-probe-stdout.log"), output, 0600)
	if !reflect.DeepEqual(original, sourceOrphanPhysical(t, entry.SourceRootPath, spool)) {
		t.Fatal("backup/actual restore probe changed original inode graph")
	}
	admissionProofWrite(t, filepath.Join(directory, "verified-backup.json"), checkpoint)
	t.Logf("SOURCE_ORPHAN_GENUINE_BACKUP_RESTORED directory=%s actualRestoreProbePID=%d exit=0 retainedBytes=8", directory, cmd.Process.Pid)
}
func verifySourceOrphanRestored(t *testing.T, root string) {
	t.Helper()
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("canonical actual restored graph required")
	}
	raw, err := os.ReadFile(filepath.Join(root, "capture-context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved sourceOrphanContext
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Evidence.SizeBytes != 8 || saved.Entry.SizeBytes != 8 || saved.Evidence.Witness != saved.Witness {
		t.Fatal("genuine original capture context")
	}
	source, spool := filepath.Join(root, "source"), filepath.Join(root, "spool")
	before := sourceOrphanPhysical(t, source, spool)
	if len(before) != 4 {
		t.Fatal("complete restored source/spool graph")
	}
	sourceRaw, err := os.ReadFile(filepath.Join(source, "file"))
	if err != nil {
		t.Fatal(err)
	}
	items, err := os.ReadDir(spool)
	if err != nil || len(items) != 1 {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(filepath.Join(spool, items[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(sourceRaw)
	if string(sourceRaw) != "retained" || !bytes.Equal(sourceRaw, retained) || hex.EncodeToString(h[:]) != saved.Evidence.SHA256 {
		t.Fatal("actual restored source/retained payload")
	}
	copyResources.mu.Lock()
	charged := copyResources.spoolBytes
	failed := copyResources.spoolFailure
	copyResources.mu.Unlock()
	sourceCaptureLive.Lock()
	live := len(sourceCaptureLive.files)
	sourceCaptureLive.Unlock()
	if charged != 0 || failed != nil || len(copyResources.workers) != 0 || len(copyResources.readers) != 0 || live != 0 {
		t.Fatal("restore probe must be a genuinely fresh process")
	}
	descriptor, err := syncstate.DescribeSource(filepath.Join(source, "file"), saved.Entry.Destination, 0)
	if err != nil {
		t.Fatal(err)
	}
	incarnation, err := syncstate.ObserveSourceIncarnation(source)
	if err != nil {
		t.Fatal(err)
	}
	candidate := saved.Entry
	candidate.SourceDescriptor = descriptor
	candidate.SourceRootPath = source
	candidate.SourceObject = incarnation.Object()
	if _, err = CaptureSourceSnapshot(context.Background(), saved.Witness, candidate, spool); !errors.Is(err, ErrSourceCaptureArtifactsUnreconciled) {
		t.Fatal("actual restored unknown plaintext admitted", err)
	}
	if err = copyResources.reserveSpool(context.Background(), t.TempDir(), 1); !errors.Is(err, ErrSourceCaptureArtifactsUnreconciled) {
		t.Fatal("actual restored orphan did not block legacy", err)
	}
	after := sourceOrphanPhysical(t, source, spool)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("actual product refusal mutated restored original")
	}
	copyResources.mu.Lock()
	charged = copyResources.spoolBytes
	copyResources.mu.Unlock()
	sourceCaptureLive.Lock()
	live = len(sourceCaptureLive.files)
	sourceCaptureLive.Unlock()
	if charged != 0 || len(copyResources.workers) != 0 || len(copyResources.readers) != 0 || live != 0 {
		t.Fatal("failed admission leaked actual resource owner")
	}
	proof := sourceOrphanProbe{Schema: "pluto.source-orphan-restore-probe.v1", Status: "PASS_ACTUAL_RESTORED_ORPHAN_REFUSES_NEW_AND_LEGACY", RestoreRoot: root, SHA256: saved.Evidence.SHA256, SourceBytes: 8, RetainedBytes: 8, NewCaptureRefused: true, LegacyRefused: true, PhysicalGraphUnchanged: true, Workers: 0, Readers: 0, LiveFiles: 0, SpoolBytes: 0}
	output, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stdout.Write(append(output, '\n')); err != nil {
		t.Fatal(err)
	}
}
func recordSourceOrphanCrashWait(t *testing.T, pid, code int, spool string, before, after []byte, charged int64) {
	t.Helper()
	if pid <= 0 || code != 86 || string(before) != "retained" || !bytes.Equal(before, after) || charged != 0 || len(copyResources.workers) != 0 {
		t.Fatal("actual original crash/refusal/byte invariants required")
	}
	root := os.Getenv("PLUTO_FAULT_BACKUP_DIR")
	items, err := os.ReadDir(root)
	if err != nil || len(items) != 1 {
		t.Fatal("one qualified before-fault backup", err)
	}
	directory := filepath.Join(root, items[0].Name())
	raw, err := os.ReadFile(filepath.Join(directory, "verified-backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint sourceOrphanBackup
	if err = json.Unmarshal(raw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.Schema != "pluto.source-orphan-backup.v1" || checkpoint.Case != t.Name() || checkpoint.Spool != spool || checkpoint.RestoreProbePID <= 0 || checkpoint.RestoreProbeExit != 0 || checkpoint.HistoricalReader {
		t.Fatal("actual before-fault checkpoint and restore probe required")
	}
	physical := sourceOrphanPhysical(t, checkpoint.Source, spool)
	if !reflect.DeepEqual(physical, checkpoint.OriginalPhysical) {
		t.Fatal("original source/spool inode graph changed after actual child86")
	}
	digest := sha256.Sum256(raw)
	admissionProofWrite(t, filepath.Join(directory, "actual-crash-wait.json"), map[string]any{"schema": "pluto.source-orphan-actual-crash.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "pid": pid, "actualExitCode": code, "graceful": false, "expectedFault": true, "backupProofSHA256": hex.EncodeToString(digest[:]), "source": checkpoint.Source, "spool": spool, "evidence": checkpoint.Evidence, "originalPhysical": physical, "physicalGraphUnchanged": true, "retainedBytes": len(after), "newCaptureRefused": true, "legacyRefused": true, "postRejectedSpoolCharge": charged, "postRejectedWorkers": len(copyResources.workers), "historicalReader": false})
	t.Logf("SOURCE_ORPHAN_ACTUAL_CRASH_WAIT pid=%d exit=86 retainedBytes=8 originalsUnchanged=true", pid)
}
