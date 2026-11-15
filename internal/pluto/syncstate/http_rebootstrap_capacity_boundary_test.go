package syncstate

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// SQLite identity/capacity boundary only. These fixture intents are never sent
// to HTTP and are not publication or native recovery evidence.
func TestRetainedHTTPIdentityExactPendingCapacity(t *testing.T) {
	for _, n := range []int{4095, 4096, 4097} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r, _, _, s, _, _ := actualHTTPFixture(t, 0)
			err := r.store.transaction(testContext, func(tx *sql.Tx) error {
				if _, e := tx.ExecContext(testContext, `INSERT INTO local_entries(root_id,entry_id,parent_id,name_key,generation,descriptor_json) VALUES('root','capacity-entry',NULL,'capacity-entry',1,'{}')`); e != nil {
					return e
				}
				identity := s.identity
				identity.InputBinding = s.binding
				for i := 0; i < n; i++ {
					id := fmt.Sprintf("capacity-%05d", i)
					intent := Intent{OperationID: id, RootID: "root", EntryID: "capacity-entry", LocalGeneration: int64(i + 1), Kind: "PUT", Captured: &CapturedOperationBinding{Transport: &identity}}
					raw, e := json.Marshal(intent)
					if e != nil {
						return e
					}
					if _, e = tx.ExecContext(testContext, `INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES(?,'root','capacity-entry',?,'PUT',?,'fixture-identity-only','SUBMITTED')`, id, i+1, string(raw)); e != nil {
						return e
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			err = r.store.transaction(testContext, func(tx *sql.Tx) error { return s.validateRetainedHTTPIdentity(testContext, tx) })
			if n <= 4096 && err != nil {
				t.Fatal("Supported capacity refused", n, err)
			}
			if n > 4096 && !errors.Is(err, ErrSourceQuota) {
				t.Fatal("Excess pending debt accepted", n, err)
			}
			var count int
			if e := r.store.db.QueryRowContext(testContext, `SELECT count(*) FROM operations WHERE stage='SUBMITTED'`).Scan(&count); e != nil || count != n {
				t.Fatal("Originals changed", count, e)
			}
			if n == 4096 {
				var original string
				if e := r.store.db.QueryRowContext(testContext, `SELECT intent_json FROM operations WHERE operation_id='capacity-04095'`).Scan(&original); e != nil {
					t.Fatal(e)
				}
				var intent Intent
				if e := json.Unmarshal([]byte(original), &intent); e != nil {
					t.Fatal(e)
				}
				intent.Captured.Transport.BackendIdentity = "foreign-backend"
				raw, _ := json.Marshal(intent)
				if _, e := r.store.db.ExecContext(testContext, `UPDATE operations SET intent_json=? WHERE operation_id='capacity-04095'`, string(raw)); e != nil {
					t.Fatal(e)
				}
				e := r.store.transaction(testContext, func(tx *sql.Tx) error { return s.validateRetainedHTTPIdentity(testContext, tx) })
				if !errors.Is(e, ErrIdentityConflict) {
					t.Fatal("Last-page foreign identity accepted", e)
				}
			}
		})
	}
}
