package syncstate

import (
	"archive/tar"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type sourceWalFileFact struct {
	Bytes      int64
	Mode       fs.FileMode
	MtimeNs    int64
	ChangeTime string
	SHA256     string
	info       os.FileInfo
}
type sourceWalMigrationBackup struct {
	*fixtureBackup
	protected map[string]sourceWalFileFact
}

func sourceWalProtected(t *testing.T, state string) map[string]sourceWalFileFact {
	t.Helper()
	result := map[string]sourceWalFileFact{}
	for _, name := range []string{"sync-state.sqlite", "sync-state.sqlite-wal", "config.json", "pause-state"} {
		file := filepath.Join(state, name)
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 64<<20 {
			t.Fatal("private original WAL graph file", name, err)
		}
		digest, err := fileDigest(file)
		if err != nil {
			t.Fatal(err)
		}
		change := ""
		native := reflect.ValueOf(info.Sys())
		if native.IsValid() && native.Kind() == reflect.Pointer && !native.IsNil() {
			native = native.Elem()
		}
		if native.IsValid() && native.Kind() == reflect.Struct {
			if field := native.FieldByName("Ctim"); field.IsValid() && field.CanInterface() {
				change = fmt.Sprint(field.Interface())
			}
		}
		result[name] = sourceWalFileFact{info.Size(), info.Mode().Perm(), info.ModTime().UnixNano(), change, digest, info}
	}
	return result
}
func sourceWalAssertSame(t *testing.T, before, after map[string]sourceWalFileFact) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatal("original protected graph count changed")
	}
	for name, old := range before {
		now, ok := after[name]
		if !ok || !os.SameFile(old.info, now.info) || old.Bytes != now.Bytes || old.Mode != now.Mode || old.MtimeNs != now.MtimeNs || old.ChangeTime != now.ChangeTime || old.SHA256 != now.SHA256 {
			t.Fatal("original inode/bytes/mode/timestamps changed during WAL restore proof", name)
		}
	}
}

func sourceWalLogical(t *testing.T, db *sql.DB) (string, int) {
	t.Helper()
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
func qualifySourceWalMigrationBackup(t *testing.T, store *Store, state string) *sourceWalMigrationBackup {
	if t.Name() != "TestSourceModuleMigrationWalBackupAndLegacyPreservation" {
		t.Fatal("exact source WAL migration case required")
	}
	var sources []string
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
	protectedBefore := sourceWalProtected(t, state)
	if protectedBefore["sync-state.sqlite-wal"].Bytes <= 32 {
		t.Fatal("original committed nonempty WAL required")
	}
	var liveVersion int
	if e = store.db.QueryRow("PRAGMA user_version").Scan(&liveVersion); e != nil || liveVersion != 2 {
		t.Fatal("original version2 store", liveVersion, e)
	}
	liveLogical, liveRows := sourceWalLogical(t, store.db)
	mainLogical, mainRows := stage3DatabaseLogicalDigest(t, filepath.Join(state, "sync-state.sqlite"))
	if mainLogical == liveLogical {
		t.Fatal("captured durable rows must still require the original WAL")
	}
	originalRoot, e := store.Root(testContext, "root")
	if e != nil {
		t.Fatal(e)
	}
	originalEntry, e := store.Entry(testContext, "root", "file")
	if e != nil {
		t.Fatal(e)
	}
	productBackup, e := store.Backup(testContext)
	if e != nil {
		t.Fatal("actual SQLite API backup", e)
	}
	if !filepath.IsLocal(productBackup.Filename) || filepath.Base(productBackup.Filename) != productBackup.Filename {
		t.Fatal("local product backup basename required")
	}
	productBackupPath := filepath.Join(state, "sync-state-backups", productBackup.Filename)
	productLogical, productRows := stage3DatabaseLogicalDigest(t, productBackupPath)
	if productLogical != liveLogical || productRows != liveRows {
		t.Fatal("actual backup omitted committed WAL rows")
	}
	backupRelative, e := filepath.Rel(state, productBackupPath)
	if e != nil || !filepath.IsLocal(backupRelative) {
		t.Fatal("same private state backup required", e)
	}
	if digest, e := fileDigest(productBackupPath); e != nil || digest != productBackup.SHA256 {
		t.Fatal("actual product backup SHA", e)
	}
	sourceWalAssertSame(t, protectedBefore, sourceWalProtected(t, state))
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
		logical, rows := sourceWalLogical(t, product.db)
		if logical != liveLogical || rows != liveRows {
			t.Fatal("restored full live-WAL logical database differs")
		}
		root, e := product.Root(testContext, "root")
		if e != nil || !reflect.DeepEqual(root, originalRoot) {
			t.Fatal("restored root differs", e)
		}
		entry, e := product.Entry(testContext, "root", "file")
		if e != nil || !reflect.DeepEqual(entry, originalEntry) {
			t.Fatal("restored entry differs", e)
		}
		apiCopy := filepath.Join(restored, "state", backupRelative)
		if digest, e := fileDigest(apiCopy); e != nil || digest != productBackup.SHA256 {
			t.Fatal("restored actual product backup differs", e)
		}
		logical, rows = stage3DatabaseLogicalDigest(t, apiCopy)
		if logical != liveLogical || rows != liveRows {
			t.Fatal("restored actual API backup logical rows differ")
		}
	}()
	if t.Failed() {
		t.Fatal("restored fixture precondition failed")
	}
	if !reflect.DeepEqual(before, inventory()) {
		t.Fatal("restored product probe changed original fixture")
	}
	protectedAfter := sourceWalProtected(t, state)
	sourceWalAssertSame(t, protectedBefore, protectedAfter)
	raw, e := json.MarshalIndent(map[string]any{"schema": "pluto.source-live-wal-backup.v1", "liveLogicalSHA256": liveLogical, "liveRows": liveRows, "rawMainLogicalSHA256": mainLogical, "rawMainRows": mainRows, "productBackup": productBackup, "productBackupRelative": filepath.ToSlash(backupRelative), "protectedBefore": protectedBefore, "protectedAfter": protectedAfter, "originalSameFile": true, "originalDatabaseAndWALUnchanged": true, "committedWALRequired": true, "restoredAllLogicalRows": true, "physicalSourcePayloadExpected": false, "historicalReaderExecuted": false, "case": t.Name(), "at": time.Now().UTC(), "state": state, "sources": sources, "archiveSHA256": archiveSHA, "entries": before, "productStoreOpened": true, "baselineEmpty": len(before) == len(roots)}, "", "  ")
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
	t.Logf("SOURCE_LIVE_WAL_BACKUP_QUALIFIED archiveSHA256=%s directory=%s", archiveSHA, directory)
	return &sourceWalMigrationBackup{fixtureBackup: &fixtureBackup{directory: directory, archiveSHA: archiveSHA}, protected: protectedBefore}
}

func preserveSourceWalMigrationOutcome(t *testing.T, store *Store, state string, backup *sourceWalMigrationBackup) {
	t.Helper()
	var version, migrations int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 3 {
		t.Fatal("final source module version3", version, err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=3").Scan(&migrations); err != nil || migrations != 1 {
		t.Fatal("one original migration required", migrations, err)
	}
	logical, count := sourceWalLogical(t, store.db)
	actual, err := store.Backup(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsLocal(actual.Filename) || filepath.Base(actual.Filename) != actual.Filename {
		t.Fatal("local product backup basename required")
	}
	actualPath := filepath.Join(state, "sync-state-backups", actual.Filename)
	digest, rows := stage3DatabaseLogicalDigest(t, actualPath)
	if digest != logical || rows != count {
		t.Fatal("actual post-migration backup lost logical data")
	}
	data, err := os.ReadFile(actualPath)
	if err != nil || len(data) > 64<<20 || hashBytes(data) != actual.SHA256 {
		t.Fatal("actual post-migration backup bytes", err)
	}
	file := filepath.Join(backup.directory, "post-migration.sqlite")
	target, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := target.Write(data)
	syncErr := target.Sync()
	closeErr := target.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	beforeLegacy, afterLegacy := map[string]sourceWalFileFact{}, map[string]sourceWalFileFact{}
	current := sourceWalProtected(t, state)
	for _, name := range []string{"config.json", "pause-state"} {
		beforeLegacy[name] = backup.protected[name]
		afterLegacy[name] = current[name]
	}
	sourceWalAssertSame(t, beforeLegacy, afterLegacy)
	optional := "NOT_RUN_ENV_UNSET"
	if os.Getenv("PLUTO_OLD_STATE_READER") != "" {
		optional = "REQUESTED_AFTER_THIS_CURRENT_MIGRATION_PROOF"
	}
	stage3PendingProofWrite(t, filepath.Join(backup.directory, "source-wal-result.json"), map[string]any{
		"schema": "pluto.source-wal-migration-result.v1", "case": t.Name(), "at": time.Now().UTC().Format(time.RFC3339Nano),
		"state": state, "archiveSHA256": backup.archiveSHA, "version": version, "sourceMigrationCount": migrations,
		"backup": actual, "sqliteSHA256": actual.SHA256, "logicalSHA256": logical, "logicalRows": count,
		"legacyBefore": beforeLegacy, "legacyAfter": afterLegacy, "legacySameFileBytesModeTimestamps": true,
		"optionalPredecessorBranch": optional, "historicalCompatibilityConfirmed": false, "physicalSourcePayloadExpected": false,
	})
	t.Logf("SOURCE_WAL_MIGRATION_CURRENT_CORE version=%d rows=%d optional_predecessor=%s; historical compatibility UNCONFIRMED", version, count, optional)
}
