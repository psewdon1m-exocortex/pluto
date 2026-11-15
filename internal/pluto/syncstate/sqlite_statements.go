package syncstate

import (
	"container/list"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"

	"modernc.org/sqlite"
)

const stateSQLiteDriverName = "pluto-state-sqlite"
const stateSQLiteStatements = 64
const stateSQLiteStatementBytes = 8192

// Cache compiled single-statement DML, never rows or authorization decisions. Every
// execution binds fresh arguments and reads inside the caller's current TX.
// A statement returns to this connection only after database/sql closes its
// rows. The modernc driver resets its VM and clears bindings on that boundary.
type stateSQLiteNative interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
	// Migration uses the native online backup API to include committed WAL.
	NewBackup(string) (*sqlite.Backup, error)
}

type stateSQLiteDriver struct{ driver.Driver }
type stateSQLiteStatement interface {
	driver.Stmt
	driver.StmtExecContext
	driver.StmtQueryContext
}
type stateSQLiteConn struct {
	stateSQLiteNative
	mu     sync.Mutex
	idle   map[string]*list.Element
	order  list.List
	closed bool
}
type stateSQLiteCached struct {
	query     string
	statement driver.Stmt
}
type stateSQLiteLease struct {
	driver.Stmt
	connection *stateSQLiteConn
	query      string
	once       sync.Once
	failed     bool
	closeErr   error
}

func init() {
	// Reuse the registered driver, including its connection hooks/functions.
	// sql.Open does not open a physical connection here.
	db, err := sql.Open("sqlite", "")
	if err != nil {
		panic(err)
	}
	d := db.Driver()
	if err = db.Close(); err != nil {
		panic(err)
	}
	sql.Register(stateSQLiteDriverName, stateSQLiteDriver{d})
}

func (d stateSQLiteDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	native, ok := c.(stateSQLiteNative)
	if !ok {
		c.Close()
		return nil, errors.New("SQLite context/transaction interfaces unavailable")
	}
	return &stateSQLiteConn{stateSQLiteNative: native, idle: make(map[string]*list.Element)}, nil
}

func stateSQLiteCacheable(query string) bool {
	if len(query) > stateSQLiteStatementBytes || strings.Contains(query, ";") {
		return false
	}
	q := strings.TrimSpace(query)
	for _, prefix := range []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE "} {
		if strings.HasPrefix(q, prefix) {
			return true
		}
	}
	return false
}

func (c *stateSQLiteConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if stateSQLiteCacheable(query) {
		return nil, driver.ErrSkip
	}
	return c.stateSQLiteNative.ExecContext(ctx, query, args)
}

func (c *stateSQLiteConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if stateSQLiteCacheable(query) {
		// database/sql prepares and closes the lease, including on cancellation.
		return nil, driver.ErrSkip
	}
	return c.stateSQLiteNative.QueryContext(ctx, query, args)
}

func (c *stateSQLiteConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *stateSQLiteConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if !stateSQLiteCacheable(query) {
		return c.stateSQLiteNative.PrepareContext(ctx, query)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, driver.ErrBadConn
	}
	var statement driver.Stmt
	if item := c.idle[query]; item != nil {
		statement = item.Value.(stateSQLiteCached).statement
		delete(c.idle, query)
		c.order.Remove(item)
	}
	c.mu.Unlock()
	if statement == nil {
		var err error
		statement, err = c.stateSQLiteNative.PrepareContext(ctx, query)
		if err != nil {
			return nil, err
		}
	}
	if _, ok := statement.(stateSQLiteStatement); !ok {
		statement.Close()
		return nil, errors.New("SQLite contextual statement interfaces unavailable")
	}
	return &stateSQLiteLease{Stmt: statement, connection: c, query: query}, nil
}

func (s *stateSQLiteLease) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	result, err := s.Stmt.(driver.StmtExecContext).ExecContext(ctx, args)
	if err != nil {
		s.failed = true
	}
	return result, err
}
func (s *stateSQLiteLease) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := s.Stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
	if err != nil {
		s.failed = true
	}
	return rows, err
}
func (s *stateSQLiteLease) Close() error {
	s.once.Do(func() {
		c := s.connection
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed || s.failed || c.idle[s.query] != nil {
			s.closeErr = s.Stmt.Close()
			return
		}
		if c.order.Len() == stateSQLiteStatements {
			old := c.order.Back()
			entry := old.Value.(stateSQLiteCached)
			delete(c.idle, entry.query)
			c.order.Remove(old)
			s.closeErr = entry.statement.Close()
		}
		c.idle[s.query] = c.order.PushFront(stateSQLiteCached{s.query, s.Stmt})
	})
	return s.closeErr
}

func (c *stateSQLiteConn) Close() error {
	c.mu.Lock()
	c.closed = true
	var err error
	for item := c.order.Front(); item != nil; item = item.Next() {
		err = errors.Join(err, item.Value.(stateSQLiteCached).statement.Close())
	}
	c.order.Init()
	clear(c.idle)
	c.mu.Unlock()
	return errors.Join(err, c.stateSQLiteNative.Close())
}
