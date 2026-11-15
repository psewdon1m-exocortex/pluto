//go:build linux

package pluto

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"pluto/internal/pluto/syncstate"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

type admissionBackupEntry struct {
	Name      string
	Directory bool
	Mode      fs.FileMode
	Bytes     int64
	SHA256    string
}
type admissionClosedBackup struct{ directory, archiveSHA string }

// Closed local fixtures have no live writer or external backend. The caller
// supplies every physical source root and verifies a real restored product store.
func qualifyAdmissionClosedBackup(t *testing.T, state string, sources []string, verify func(*syncstate.Store, string)) *admissionClosedBackup {
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
	inventory := func() []admissionBackupEntry {
		var result []admissionBackupEntry
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
				entry := admissionBackupEntry{Name: name, Directory: info.IsDir(), Mode: info.Mode().Perm()}
				if !info.IsDir() {
					if !info.Mode().IsRegular() {
						return fmt.Errorf("unsupported fixture object %s", name)
					}
					entry.Bytes = info.Size()
					total += info.Size()
					if total > 64<<20 {
						return fmt.Errorf("fixture graph exceeds admitted 64 MiB")
					}
					entry.SHA256, e = admissionFileDigest(p)
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
	archiveSHA, e := admissionFileDigest(archive)
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
			digest, e := admissionFileDigest(p)
			if e != nil || digest != entry.SHA256 || info.Size() != entry.Bytes {
				t.Fatal("restored fixture bytes", e)
			}
		}
	}
	for n := len(directories) - 1; n >= 0; n-- {
		admissionDirectorySync(t, directories[n])
	}
	admissionDirectorySync(t, restored)
	product, e := syncstate.Open(context.Background(), filepath.Join(restored, "state"))
	if e != nil {
		t.Fatal("actual restored fixture store", e)
	}
	func() {
		defer func() {
			if closeErr := product.Close(); closeErr != nil {
				t.Error("restored fixture close", closeErr)
			}
		}()
		verify(product, filepath.Join(restored, "state"))
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
	admissionDirectorySync(t, directory)
	admissionDirectorySync(t, base)
	t.Logf("CLOSED_FIXTURE_BACKUP_QUALIFIED archiveSHA256=%s directory=%s", archiveSHA, directory)
	return &admissionClosedBackup{directory: directory, archiveSHA: archiveSHA}
}

func admissionDirectorySync(t *testing.T, p string) {
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

func admissionImmutableDB(t *testing.T, filename string) *sql.DB {
	t.Helper()
	u := url.URL{Scheme: "file", Path: filename}
	u.RawQuery = "mode=ro&immutable=1"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}
func admissionLogicalDigest(t *testing.T, filename string) (string, int) {
	t.Helper()
	db := admissionImmutableDB(t, filename)
	defer db.Close()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	objects, err := db.Query("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")
	if err != nil {
		t.Fatal(err)
	}
	var schema [][]any
	var tables []string
	for objects.Next() {
		var kind, name, table string
		var ddl any
		if err = objects.Scan(&kind, &name, &table, &ddl); err != nil {
			t.Fatal(err)
		}
		schema = append(schema, []any{kind, name, table, ddl})
		if kind == "table" {
			tables = append(tables, name)
		}
	}
	if err = objects.Err(); err != nil {
		t.Fatal(err)
	}
	if err = objects.Close(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(tables)
	payload := map[string]any{"version": version, "schema": schema}
	rowCount := 0
	for _, table := range tables {
		quoted := "\"" + strings.ReplaceAll(table, "\"", "\"\"") + "\""
		rows, err := db.Query("SELECT * FROM " + quoted)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var values []string
		for rows.Next() {
			cells := make([]any, len(columns))
			targets := make([]any, len(columns))
			for n := range cells {
				targets[n] = &cells[n]
			}
			if err = rows.Scan(targets...); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(cells)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, string(raw))
			rowCount++
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err = rows.Close(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(values)
		payload[table] = map[string]any{"columns": columns, "rows": values}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), rowCount
}

type admissionRestartBackup struct {
	*admissionClosedBackup
	state, source, snapshot, sha string
	bytes                        int64
	physical                     []admissionPhysicalEntry
}
type admissionPhysicalEntry struct {
	Path, Kind, SHA256      string
	Device, Inode           uint64
	Mode                    uint32
	Bytes, MTimeNS, CTimeNS int64
}

func admissionFileDigest(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func admissionPhysical(t *testing.T, state, source string) []admissionPhysicalEntry {
	t.Helper()
	var entries []admissionPhysicalEntry
	for _, root := range []string{filepath.Join(state, syncstate.ArtifactDirectoryName), source} {
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
func admissionProofWrite(t *testing.T, filename string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(append(raw, '\n'))
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	admissionDirectorySync(t, filepath.Dir(filename))
}
func qualifyAdmissionRestartBackup(t *testing.T, state string, e syncstate.SourceEntry, v *syncstate.VerifiedSnapshot) *admissionRestartBackup {
	t.Helper()
	if t.Name() != "TestArtifactActualRestartAccountsBeforeLegacyWork" {
		t.Fatal("specific original orderly restart fixture required")
	}
	evidence := v.Evidence()
	if evidence.SizeBytes != 11 || e.SizeBytes != 11 || evidence.SnapshotID == "" {
		t.Fatal("original eleven retained bytes required")
	}
	logical, count := admissionLogicalDigest(t, filepath.Join(state, "sync-state.sqlite"))
	physical := admissionPhysical(t, state, e.SourceRootPath)
	backup := qualifyAdmissionClosedBackup(t, state, []string{e.SourceRootPath}, func(copy *syncstate.Store, copyState string) {
		if err := copy.Close(); err != nil {
			t.Fatal(err)
		}
		digest, rows := admissionLogicalDigest(t, filepath.Join(copyState, "sync-state.sqlite"))
		if digest != logical || rows != count {
			t.Fatal("all genuine cloned SQL rows differ")
		}
		db := admissionImmutableDB(t, filepath.Join(copyState, "sync-state.sqlite"))
		defer db.Close()
		var filename, phase, sha, snapshot string
		var bytes int64
		err := db.QueryRow("SELECT filename,phase,size_bytes,sha256,snapshot_id FROM local_artifacts WHERE artifact_id=?", evidence.SnapshotID).Scan(&filename, &phase, &bytes, &sha, &snapshot)
		if err != nil || phase != "SEALED" || bytes != 11 || sha != evidence.SHA256 || snapshot != evidence.SnapshotID || filepath.Base(filename) != filename {
			t.Fatal("exact copied sealed artifact SQL", err)
		}
		retained, err := os.ReadFile(filepath.Join(copyState, syncstate.ArtifactDirectoryName, filename))
		if err != nil {
			t.Fatal(err)
		}
		source, err := os.ReadFile(filepath.Join(filepath.Dir(copyState), "source-001", "file"))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(retained)
		if string(retained) != "exact bytes" || string(source) != string(retained) || hex.EncodeToString(h[:]) != evidence.SHA256 {
			t.Fatal("actual copied original source/retained read")
		}
	})
	if !reflect.DeepEqual(physical, admissionPhysical(t, state, e.SourceRootPath)) {
		t.Fatal("backup changed original physical graph")
	}
	admissionProofWrite(t, filepath.Join(backup.directory, "retained-restore.json"), map[string]any{"schema": "pluto.orderly-admission-backup.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano), "archiveSHA256": backup.archiveSHA, "snapshotID": evidence.SnapshotID, "retainedBytes": evidence.SizeBytes, "retainedSHA256": evidence.SHA256, "logicalSHA256": logical, "logicalRows": count, "originalPhysical": physical, "actualClonedStoreOpened": true, "actualCopiedSourceAndRetainedRead": true, "relocatedArtifactCustodyAdmitted": false, "scope": "ordinary same-profile graceful process restart; complete closed SQL/source/artifact backup with real copied-byte readback; no restored-location ownership claim", "historicalReader": false})
	return &admissionRestartBackup{admissionClosedBackup: backup, state: state, source: e.SourceRootPath, snapshot: evidence.SnapshotID, sha: evidence.SHA256, bytes: evidence.SizeBytes, physical: physical}
}
func (backup *admissionRestartBackup) recordOrderlyWait(t *testing.T, pid, code int, output []byte) {
	t.Helper()
	if pid <= 0 || code != 0 {
		t.Fatal("actual orderly child wait0 required")
	}
	var child struct {
		RetainedBytes           int64
		LegacyBlocked, Admitted bool
	}
	if err := json.Unmarshal(output, &child); err != nil || child.RetainedBytes != backup.bytes || !child.LegacyBlocked || !child.Admitted {
		t.Fatal("actual child result", err)
	}
	current := admissionPhysical(t, backup.state, backup.source)
	if !reflect.DeepEqual(current, backup.physical) {
		t.Fatal("orderly process restart changed original source/artifact inodes or bytes")
	}
	filename := filepath.Join(backup.state, "sync-state.sqlite")
	for _, suffix := range []string{"-wal", "-journal"} {
		info, err := os.Stat(filename + suffix)
		if err == nil && info.Size() != 0 {
			t.Fatal("closed child checkpoint required")
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filename)
	if err != nil || len(raw) == 0 || len(raw) > 64<<20 {
		t.Fatal("bounded actual postrestart database", err)
	}
	target := filepath.Join(backup.directory, "postrestart.sqlite")
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	h := sha256.Sum256(raw)
	admissionProofWrite(t, filepath.Join(backup.directory, "actual-orderly-restart.json"), map[string]any{"schema": "pluto.orderly-admission-restart.v1", "case": t.Name(), "helper": "TestArtifactAdmissionRestartChild", "at": time.Now().UTC().Format(time.RFC3339Nano), "pid": pid, "actualExitCode": code, "graceful": true, "storeClosedBeforeExit": true, "child": json.RawMessage(output), "archiveSHA256": backup.archiveSHA, "snapshotID": backup.snapshot, "retainedBytes": backup.bytes, "retainedSHA256": backup.sha, "originalPhysical": current, "physicalGraphUnchanged": true, "postSQLiteSHA256": hex.EncodeToString(h[:]), "postSQLiteBytes": len(raw), "historicalReader": false})
	t.Logf("ADMISSION_ORIGINAL_ORDERLY_WAIT helper=TestArtifactAdmissionRestartChild pid=%d exit=0 retainedBytes=%d legacyBlocked=true", pid, backup.bytes)
}
