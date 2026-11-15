package pluto

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

const (
	copyDirectoryBatch                 = 128
	copyCompletionBatch                = 128
	copyPathBytes                      = 32 * 1024
	copyMetadataDatabaseBytes    int64 = 1024 * 1024 * 1024
	maxCopyMetadataDatabaseBytes int64 = 4 * copyMetadataDatabaseBytes
)

// CopyOptions separates disk metadata capacity from the unchanged 256 MiB
// plaintext snapshot budget. Zero uses a 1 GiB metadata database cap. Raising
// it requires explicit caller policy; memory batches/cache remain bounded.
type CopyOptions struct{ MetadataDiskBytes int64 }

func (o CopyOptions) metadataLimit() (int64, error) {
	if o.MetadataDiskBytes == 0 {
		return copyMetadataDatabaseBytes, nil
	}
	if o.MetadataDiskBytes < 4*4096 || o.MetadataDiskBytes > maxCopyMetadataDatabaseBytes {
		return 0, errors.New("Copy metadata disk budget must be between 16 KiB and 4 GiB")
	}
	return o.MetadataDiskBytes / 4096 * 4096, nil
}

func CopyWithOptions(ctx context.Context, remote Remote, sources []string, spool string, options CopyOptions) (int, error) {
	limit, err := options.metadataLimit()
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(spool, 0700); err != nil {
		return 0, err
	}
	return copyPipelineConfigured(ctx, remote, sources, spool, copyResources, osCopyEnumerationFS{}, limit)
}

var errCopyEnumerationState = errors.New("temporary Copy enumeration state failed")

// This is an invocation-private exact set and FIFO, never a durable baseline.
// Only verified success is remembered; a failed overlapping source can retry.
// There is no reuse after process exit, no metadata/content shortcut and no WAL.
type copyEnumerationState struct {
	mu        sync.Mutex
	db        *sql.DB
	directory string
	completed map[string]struct{}
}

func newCopyEnumerationState(ctx context.Context, spool string, maxBytes int64) (_ *copyEnumerationState, err error) {
	// Keep metadata separate from the plaintext snapshot directory. The parent
	// exists because Copy has already created spool; the private sibling is
	// reserved separately (a mount-point spool may be on another filesystem).
	parentDirectory, err := filepath.Abs(filepath.Dir(spool))
	if err != nil {
		return nil, err
	}
	parentDirectory, err = filepath.EvalSymlinks(parentDirectory)
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(parentDirectory, ".pluto-enumeration-")
	if err != nil {
		return nil, err
	}
	s := &copyEnumerationState{directory: directory, completed: make(map[string]struct{})}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.close())
		}
	}()
	filename := filepath.Join(directory, "state.sqlite")
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	// The driver treats a raw '?' as DSN parameters. Encode the literal exact
	// absolute filesystem path, and reapply resource PRAGMAs on every connection
	// (database/sql may replace a bad connection even with MaxOpenConns=1).
	parameters := url.Values{"mode": {"rw"}, "cache": {"private"}, "_pragma": {
		"page_size(4096)", "journal_mode(DELETE)", "synchronous(OFF)", "cache_size(-2048)",
		"mmap_size(0)", "temp_store(FILE)", fmt.Sprintf("max_page_count(%d)", maxBytes/4096),
	}}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(filename), RawQuery: parameters.Encode()}).String()
	s.db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	if maxBytes < 4*4096 {
		return nil, errors.New("enumeration database budget is too small")
	}
	// synchronous=OFF is deliberate: this DB contains no durable sync truth.
	// DELETE still rolls back ordinary statement/transaction failures; a crash
	// abandons the invocation and its private DB, which is never reopened.
	for _, statement := range []string{
		"PRAGMA page_size=4096", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=OFF",
		"PRAGMA cache_size=-2048", "PRAGMA mmap_size=0", "PRAGMA temp_store=FILE",
		fmt.Sprintf("PRAGMA max_page_count=%d", maxBytes/4096),
		"CREATE TABLE completed(path TEXT PRIMARY KEY) WITHOUT ROWID",
		"CREATE TABLE frontier(id INTEGER PRIMARY KEY AUTOINCREMENT,path TEXT NOT NULL)",
	} {
		if _, err = s.db.ExecContext(ctx, statement); err != nil {
			return nil, err
		}
	}
	var mode string
	if err = s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return nil, err
	}
	if mode != "delete" {
		return nil, errors.New("enumeration rollback journal mode was not applied")
	}
	for _, setting := range []struct {
		name     string
		expected int64
	}{
		{"page_size", 4096}, {"cache_size", -2048}, {"synchronous", 0}, {"mmap_size", 0}, {"temp_store", 1}, {"max_page_count", maxBytes / 4096},
	} {
		var actual int64
		if err = s.db.QueryRowContext(ctx, "PRAGMA "+setting.name).Scan(&actual); err != nil {
			return nil, err
		}
		if actual != setting.expected {
			return nil, fmt.Errorf("enumeration %s budget was not applied", setting.name)
		}
	}
	var seq int
	var dbName, actualFilename string
	if err = s.db.QueryRowContext(ctx, "PRAGMA database_list").Scan(&seq, &dbName, &actualFilename); err != nil {
		return nil, err
	}
	if dbName != "main" || actualFilename != filename {
		return nil, errors.New("enumeration database did not open the exact private file")
	}
	return s, nil
}

func validCopyStatePath(filename string) error {
	if len(filename) > copyPathBytes {
		return errors.New("source path exceeds bounded enumeration path budget")
	}
	return nil
}

func (s *copyEnumerationState) hasCompleted(ctx context.Context, relative string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.completed[relative]; ok {
		return true, nil
	}
	var exists int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM completed WHERE path=?", relative).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *copyEnumerationState) markCompleted(ctx context.Context, relative string) error {
	if err := validCopyStatePath(relative); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completed[relative] = struct{}{}
	if len(s.completed) < copyCompletionBatch {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for filename := range s.completed {
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO completed(path) VALUES (?)", filename); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	clear(s.completed)
	return nil
}

func (s *copyEnumerationState) pushDirectory(ctx context.Context, filename string) error {
	return s.pushDirectories(ctx, []string{filename})
}

func (s *copyEnumerationState) pushDirectories(ctx context.Context, filenames []string) error {
	if len(filenames) > copyDirectoryBatch {
		return errors.New("directory frontier batch exceeded budget")
	}
	for _, filename := range filenames {
		if err := validCopyStatePath(filename); err != nil {
			return err
		}
	}
	if len(filenames) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, filename := range filenames {
		if _, err := tx.ExecContext(ctx, "INSERT INTO frontier(path) VALUES (?)", filename); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *copyEnumerationState) popDirectory(ctx context.Context) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id int64
	var filename string
	// INTEGER PRIMARY KEY traversal returns one descriptor, without sorting
	// or materializing the outstanding directory frontier in Go/SQLite temp.
	err := s.db.QueryRowContext(ctx, "SELECT id,path FROM frontier WHERE id>0 ORDER BY id LIMIT 1").Scan(&id, &filename)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM frontier WHERE id=?", id)
	return filename, err == nil, err
}

func (s *copyEnumerationState) close() error {
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	// directory is exactly the invocation-private MkdirTemp result. Joining
	// workers precedes this call, so no reader/writer can retain the DB/journal.
	return errors.Join(err, os.RemoveAll(s.directory))
}
