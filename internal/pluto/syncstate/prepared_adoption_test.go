package syncstate

import (
	"testing"
)

func TestPreparedPolicyInitializationRequiresVirginDefaultRoot(t *testing.T) {
	for _, test := range []struct {
		name, mutation, codec string
		want                  bool
	}{
		{"virgin", "", "portable_v1", true},
		{"wrong-codec", "", "legacy", false},
		{"unknown-codec", "", "unknown", false},
		{"wrong-binding", "UPDATE roots SET mapping_id='other'", "portable_v1", false},
		{"installed-policy", "CREATE TABLE profile_policy(root_id TEXT); INSERT INTO profile_policy VALUES('root')", "portable_v1", false},
		{"engine-ready", "PRAGMA ignore_check_constraints=ON; UPDATE roots SET engine_ready=1", "portable_v1", false},
		{"delete-enabled", "PRAGMA ignore_check_constraints=ON; UPDATE roots SET allows_delete=1", "portable_v1", false},
		{"file-limit-drift", "PRAGMA ignore_check_constraints=ON; UPDATE roots SET max_file_bytes=1", "portable_v1", false},
		{"version-limit-drift", "PRAGMA ignore_check_constraints=ON; UPDATE roots SET max_active_versions=1", "portable_v1", false},
		{"already-portable", "UPDATE roots SET name_codec='portable_v1'", "portable_v1", false},
		{"active-trust", "UPDATE roots SET trust='CURRENT'", "portable_v1", false},
		{"later-trust-generation", "UPDATE roots SET trust_generation=2", "portable_v1", false},
		{"later-remote-generation", "UPDATE roots SET active_remote_generation=2", "portable_v1", false},
		{"retained-entry", "INSERT INTO local_entries VALUES('root','entry',NULL,'name',1,'{}')", "portable_v1", false},
		{"remote-cut", "INSERT INTO remote_entries VALUES('root',1,'remote',0,'{}')", "portable_v1", false},
		{"future-durable-row", "CREATE TABLE future_originals(id TEXT); INSERT INTO future_originals VALUES('retained')", "portable_v1", false},
		{"pending-original", "INSERT INTO local_entries VALUES('root','entry',NULL,'name',1,'{}'); INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES('original','root','entry',1,'PUT','original-bytes','fingerprint','SUBMITTED')", "portable_v1", false},
		{"acknowledged-original", "INSERT INTO local_entries VALUES('root','entry',NULL,'name',1,'{}'); INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES('original','root','entry',1,'PUT','original-bytes','fingerprint','CLIENT_ACKED')", "portable_v1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, _ := stateFixture(t)
			if test.mutation != "" {
				if _, err := s.db.ExecContext(testContext, test.mutation); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.Root(testContext, testBinding.RootID)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.CanInitializePreparedPolicy(testContext, testBinding, test.codec)
			if err != nil || got != test.want {
				t.Fatalf("eligible=%v want=%v err=%v", got, test.want, err)
			}
			after, err := s.Root(testContext, testBinding.RootID)
			if err != nil || before != after {
				t.Fatal("read-only initialization fence changed root", err)
			}
			if test.name == "pending-original" || test.name == "acknowledged-original" {
				var raw string
				if err = s.db.QueryRowContext(testContext, "SELECT intent_json FROM operations WHERE operation_id='original'").Scan(&raw); err != nil || raw != "original-bytes" {
					t.Fatal("original input bytes changed", err)
				}
			}
		})
	}
}
