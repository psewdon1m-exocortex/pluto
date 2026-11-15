package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func p02StatementDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(stateSQLiteDriverName, filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.Exec("CREATE TABLE current_binding(id INTEGER PRIMARY KEY, version TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO current_binding VALUES(1,'first'),(2,'other')"); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestP02SQLitePreparedReadsFollowTransactionsAndSchema(t *testing.T) {
	db := p02StatementDB(t)
	const query = "SELECT version FROM current_binding WHERE id=?"
	read := func(q queryer, id int, want string) {
		t.Helper()
		var got string
		if err := q.QueryRowContext(context.Background(), query, id).Scan(&got); err != nil || got != want {
			t.Fatalf("fresh read %d: %q/%v, want %q", id, got, err, want)
		}
	}
	read(db, 1, "first")
	read(db, 2, "other")
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE current_binding SET version='temporary' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	read(tx, 1, "temporary")
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	read(db, 1, "first")
	tx, err = db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE current_binding SET version='committed' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	read(db, 1, "committed")
	if _, err = db.Exec("DROP TABLE current_binding; CREATE TABLE current_binding(id INTEGER PRIMARY KEY, version TEXT NOT NULL); INSERT INTO current_binding VALUES(1,'new-schema')"); err != nil {
		t.Fatal(err)
	}
	read(db, 1, "new-schema")
	var missing string
	if err = db.QueryRow(query, 2).Scan(&missing); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	read(db, 1, "new-schema")
}

func TestP02SQLitePreparedCancellationAndPartialRowsRelease(t *testing.T) {
	db := p02StatementDB(t)
	const query = "SELECT sum(x) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<?) SELECT x FROM c)"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	var sum int64
	err := db.QueryRowContext(ctx, query, 100000000).Scan(&sum)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("long query did not cancel: %v", err)
	}
	if err = db.QueryRow(query, 10).Scan(&sum); err != nil || sum != 55 {
		t.Fatalf("canceled VM/binding leaked: %d %v", sum, err)
	}
	for n := 0; n < 4; n++ {
		rows, err := db.Query("SELECT version FROM current_binding ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		if !rows.Next() {
			t.Fatal("missing first row")
		}
		if err = rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query("SELECT version FROM current_binding ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		count++
	}
	if err = rows.Err(); err != nil || count != 2 {
		t.Fatalf("partial cursor leaked: count%d %v", count, err)
	}
}

func TestP02SQLitePreparedStatementsBoundedAndParametersNotRetained(t *testing.T) {
	db := p02StatementDB(t)
	for n := 0; n < 256; n++ {
		var got int
		if err := db.QueryRow(fmt.Sprintf("SELECT ? + %d", n), n).Scan(&got); err != nil || got != 2*n {
			t.Fatalf("fresh parameters: %d %v", got, err)
		}
	}
	c, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Raw(func(raw any) error {
		owned := raw.(*stateSQLiteConn)
		owned.mu.Lock()
		defer owned.mu.Unlock()
		if len(owned.idle) > stateSQLiteStatements || owned.order.Len() != len(owned.idle) {
			return fmt.Errorf("unbounded prepared cache: %d", len(owned.idle))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestP02SQLitePreparedWritesRollbackConstraintAndCancellation(t *testing.T) {
	db := p02StatementDB(t)
	const update = "UPDATE current_binding SET version=? WHERE id=? AND version=?"
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(update, "rolled-back", 1, "first"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	result, err := db.Exec(update, "committed", 1, "first")
	if err != nil {
		t.Fatal(err)
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		t.Fatal("rollback or bindings leaked", n, e)
	}
	result, err = db.Exec(update, "stale", 1, "first")
	if err != nil {
		t.Fatal(err)
	}
	if n, e := result.RowsAffected(); e != nil || n != 0 {
		t.Fatal("stale precondition reused", n, e)
	}
	if _, err = db.Exec(update, nil, 1, "committed"); err == nil {
		t.Fatal("NOT NULL constraint bypassed")
	}
	if _, err = db.Exec(update, "after-error", 1, "committed"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = db.ExecContext(ctx, update, "canceled", 1, "after-error"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var value string
	if err = db.QueryRow("SELECT version FROM current_binding WHERE id=1").Scan(&value); err != nil || value != "after-error" {
		t.Fatal(value, err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.Raw(func(raw any) error {
		c := raw.(*stateSQLiteConn)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.idle[update] == nil {
			return errors.New("hot conditional write was not prepared and returned to the bounded connection cache")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
