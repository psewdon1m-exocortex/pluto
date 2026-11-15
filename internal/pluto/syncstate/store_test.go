package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var testContext = context.Background()
var testBinding = RootBinding{RootID: "root", MappingID: "mapping", ServerIdentity: "saturn-fixture", RemoteRootID: "remote-root", DeviceID: "device", SourceIdentity: "source-inode"}

func stateFixture(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.BindRoot(testContext, testBinding); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func capture(t *testing.T, s *Store, entry Observation) {
	t.Helper()
	before, err := s.Cursor(testContext, "root", "local")
	if err != nil {
		t.Fatal(err)
	}
	next := before
	next.Epoch = "local-journal"
	next.Position++
	next.Valid = true
	root, err := s.Root(testContext, "root")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CaptureLocal(testContext, root.TrustGeneration, before, next, []Observation{entry}); err != nil {
		t.Fatal(err)
	}
}

func fileObservation(id, name string) Observation {
	return Observation{RootID: "root", EntryID: id, Name: name, NameKey: name, Kind: "file", FileIdentity: "shared-inode", Presence: "PRESENT", SizeBytes: 3}
}

func fixtureIntent(t *testing.T, s *Store, id, entryID string) Intent {
	t.Helper()
	state, err := s.Entry(testContext, "root", entryID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.Root(testContext, "root")
	if err != nil {
		t.Fatal(err)
	}
	kind := "PUT"
	if state.Local.Kind == "folder" {
		kind = "ENSURE_DIRECTORY"
	}
	intent := Intent{OperationID: id, RootID: "root", EntryID: entryID, LocalGeneration: state.Local.Generation, TrustGeneration: root.TrustGeneration, SizeBytes: state.Local.SizeBytes, Kind: kind, ExpectedAbsent: state.Base == nil, ParentID: state.Local.ParentID, Name: state.Local.Name, NameKey: state.Local.NameKey, FileIdentity: state.Local.FileIdentity}
	if state.Base != nil {
		intent.ExpectedEpoch = state.Base.Epoch
		intent.ExpectedVersion = state.Base.Version
		intent.ExpectedNodeID = state.Base.NodeID
	}
	return intent
}

func planned(t *testing.T, s *Store, id, entryID string) Operation {
	t.Helper()
	intent := fixtureIntent(t, s, id, entryID)
	err := s.Plan(testContext, intent)
	if err != nil {
		t.Fatal(err)
	}
	sha := hashBytes([]byte("one"))
	if intent.Kind == "ENSURE_DIRECTORY" {
		sha = ""
	}
	if err = s.Seal(testContext, id, sha, "snapshot-"+id); err != nil {
		t.Fatal(err)
	}
	if err = s.Submitted(testContext, id); err != nil {
		t.Fatal(err)
	}
	op, err := s.Operation(testContext, id)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func receipt(op Operation, seq int64, version string) Receipt {
	return Receipt{OperationID: op.OperationID, RootID: op.RootID, EntryID: op.EntryID, NodeID: "node-" + op.EntryID, Epoch: "remote-epoch", Version: version, SHA256: op.SHA256, SealedFingerprint: op.SealedFingerprint, LocalGeneration: op.LocalGeneration, SizeBytes: op.SizeBytes, Seq: seq, Published: true, ContentVerified: true}
}

func seedBaselineRemote(t *testing.T, s *Store, entryID string) {
	t.Helper()
	state, err := s.Entry(testContext, "root", entryID)
	if err != nil || state.Base == nil {
		t.Fatal("baseline fixture missing", err)
	}
	b := state.Base
	root, _ := s.Root(testContext, "root")
	before, _ := s.Cursor(testContext, "root", "remote")
	next := before
	next.Epoch = b.Epoch
	next.Position++
	next.Valid = true
	r := RemoteEntry{RootID: b.RootID, NodeID: b.NodeID, Name: b.Name, Kind: b.Kind, Epoch: b.Epoch, Version: b.Version, SHA256: b.SHA256, Presence: b.Presence, OperationID: b.OperationID, Generation: root.ActiveRemoteGeneration, SizeBytes: b.SizeBytes, LastSeq: next.Position}
	if err = s.ApplyRemote(testContext, root.TrustGeneration, before, next, []RemoteEntry{r}); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyMigrationPreservesProfileAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	config := []byte(`{"enabled":false,"accessToken":"secret-fixture-only","sources":["/fixture"],"intervalSeconds":86400}`)
	status := []byte(`{"enabled":false,"lastSuccessAt":"legacy-success"}`)
	for name, raw := range map[string][]byte{"config.json": config, "status.json": status} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BindRoot(testContext, testBinding); err != nil {
		t.Fatal(err)
	}
	capture(t, s, fileObservation("file", "file"))
	state, err := s.Entry(testContext, "root", "file")
	if err != nil || state.Base != nil {
		t.Fatal("legacy baseline was fabricated", err)
	}
	root, err := s.Root(testContext, "root")
	if err != nil || root.EngineReady || root.AllowsDelete || root.Trust != TrustRequired || root.MaxFileBytes != MaxFileBytes || root.MaxActiveVersions != 10 {
		t.Fatal("migration changed backup policy/readiness", root, err)
	}
	s.Close()
	s, err = Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.BindRoot(testContext, testBinding); err != nil {
		t.Fatal(err)
	}
	var migrations int
	if err = s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migrations); err != nil || migrations != 1 {
		t.Fatal("migration reapplied", migrations, err)
	}
	for name, raw := range map[string][]byte{"config.json": config, "status.json": status} {
		current, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(current) != string(raw) {
			t.Fatal("legacy profile rewritten", name, err)
		}
	}
	backup, err := os.ReadFile(filepath.Join(dir, "sync-state-backups", "legacy-checkpoint-"+hashBytes(status)+".json"))
	if err != nil || string(backup) != string(status) {
		t.Fatal("legacy checkpoint backup missing", err)
	}
	var mode string
	var synchronous, foreignKeys int
	if err = s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" || synchronous != 2 || foreignKeys != 1 {
		t.Fatal("durability pragmas", mode, synchronous, foreignKeys)
	}
	info, err := os.Stat(filepath.Join(dir, "sync-state.sqlite"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("database permissions", info, err)
	}
}

func TestRestartRetainsCursorDirtyIntentAndReceipt(t *testing.T) {
	s, dir := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "operation", "file")
	cursor, _ := s.Cursor(testContext, "root", "local")
	s.Close()
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.PendingPage(testContext, "root", "", 10)
	if err != nil || len(pending) != 1 || pending[0].OperationID != op.OperationID || pending[0].Stage != "SUBMITTED" {
		t.Fatal("operation lost", pending, err)
	}
	current, err := reopened.Cursor(testContext, "root", "local")
	if err != nil || current != cursor {
		t.Fatal("cursor trust lost without a gap", current, err)
	}
	if err = reopened.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	reopened, err = Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state, err := reopened.Entry(testContext, "root", "file")
	if err != nil || state.Base == nil || state.Base.Version != "v1" || state.Dirty != nil {
		t.Fatal("durable ACK lost", state, err)
	}
	if err = reopened.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal("duplicate receipt not idempotent", err)
	}
}

func TestCursorAndDirtyBatchRollbackTogether(t *testing.T) {
	s, _ := stateFixture(t)
	before, _ := s.Cursor(testContext, "root", "local")
	next := before
	next.Epoch = "journal"
	next.Position = 2
	next.Valid = true
	first := fileObservation("first", "first")
	second := fileObservation("second", "same")
	second.ParentID = "missing-parent"
	if err := s.CaptureLocal(testContext, 1, before, next, []Observation{first, second}); err == nil {
		t.Fatal("bad batch committed")
	}
	if _, err := s.Entry(testContext, "root", "first"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("part of failed batch persisted", err)
	}
	current, _ := s.Cursor(testContext, "root", "local")
	if current != before {
		t.Fatal("cursor outran durable work", current)
	}
}

func TestACKOlderGenerationPreservesNewerLAndR(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "old-name"))
	op1 := planned(t, s, "op-1", "file")
	if err := s.Ack(testContext, receipt(op1, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	seedBaselineRemote(t, s, "file")
	local := fileObservation("file", "old-name")
	local.ExpectedGeneration = 1
	capture(t, s, local)
	op2 := planned(t, s, "op-2", "file")
	local.Name = "new-name"
	local.NameKey = local.Name
	local.ExpectedGeneration = 2
	capture(t, s, local)
	before, _ := s.Cursor(testContext, "root", "remote")
	next := before
	next.Epoch = "remote-epoch"
	next.Position = 2
	next.Valid = true
	remote := RemoteEntry{RootID: "root", NodeID: "node-file", Name: "other", Kind: "file", Epoch: next.Epoch, Version: "v-newer-remote", SHA256: hashBytes([]byte("two")), Presence: "PRESENT", Generation: 1, SizeBytes: 3, LastSeq: 2}
	if err := s.ApplyRemote(testContext, 1, before, next, []RemoteEntry{remote}); err != nil {
		t.Fatal(err)
	}
	// ACK the operation but preserve a later local generation and its name.
	if err := s.Ack(testContext, receipt(op2, 2, "v2")); err != nil {
		t.Fatal(err)
	}
	state, err := s.Entry(testContext, "root", "file")
	if err != nil {
		t.Fatal(err)
	}
	if state.Local.Generation != 3 || state.Base.LocalGeneration != 2 || state.Base.Name != "old-name" || state.Local.Name != "new-name" || state.Remote.Version != "v-newer-remote" || state.Dirty == nil || state.Dirty.ObservedGeneration != 3 {
		t.Fatal("ACK rolled back newer state", state)
	}
	// A subsequent R must leave B unchanged and retain remote work after ACK.
	before = next
	next.Position = 3
	remote.LastSeq = 3
	remote.Version = "v3"
	if err = s.ApplyRemote(testContext, 1, before, next, []RemoteEntry{remote}); err != nil {
		t.Fatal(err)
	}
	state, err = s.Entry(testContext, "root", "file")
	if err != nil || state.Base.Version != "v2" || state.Dirty.RemoteSeq != 3 {
		t.Fatal("R changed B", state, err)
	}
	intent := op2.Intent
	intent.OperationID = "wrong-remote-base"
	intent.LocalGeneration = 3
	intent.Name = "new-name"
	intent.NameKey = "new-name"
	intent.ExpectedVersion = "v3"
	if err = s.Plan(testContext, intent); err == nil {
		t.Fatal("used current R as baseline")
	}
}

func TestRemoteWorkNewerThanACKIsNotCleared(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "op", "file")
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	seedBaselineRemote(t, s, "file")
	local := fileObservation("file", "file")
	local.ExpectedGeneration = 1
	capture(t, s, local)
	op2 := planned(t, s, "op2", "file")
	before, _ := s.Cursor(testContext, "root", "remote")
	next := before
	next.Epoch = "remote-epoch"
	next.Position = 3
	next.Valid = true
	entries := make([]RemoteEntry, 2)
	for i := range entries {
		entries[i] = RemoteEntry{RootID: "root", NodeID: "node-file", Kind: "file", Name: "file", Epoch: next.Epoch, Version: "v-remote", SHA256: hashBytes([]byte("two")), Presence: "PRESENT", Generation: 1, SizeBytes: 3, LastSeq: int64(i) + 2}
	}
	if err := s.ApplyRemote(testContext, 1, before, next, entries); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(testContext, receipt(op2, 2, "v2")); err != nil {
		t.Fatal(err)
	}
	state, _ := s.Entry(testContext, "root", "file")
	if state.Dirty == nil || state.Dirty.RemoteSeq != 3 || state.Remote.LastSeq != 3 {
		t.Fatal("ACK deleted newer remote work", state)
	}
}

func TestOperationIdentitySealingReceiptAndBackupGuards(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "op", "file")
	if err := s.Plan(testContext, op.Intent); err != nil {
		t.Fatal("same intent is not idempotent", err)
	}
	wrong := op.Intent
	wrong.SizeBytes++
	if err := s.Plan(testContext, wrong); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("operation identity reused", err)
	}
	if err := s.Seal(testContext, op.OperationID, hashBytes([]byte("two")), op.SnapshotID); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("seal was mutable", err)
	}
	for _, mutate := range []func(*Receipt){func(r *Receipt) { r.Published = false }, func(r *Receipt) { r.ContentVerified = false }, func(r *Receipt) { r.RootID = "peer" }, func(r *Receipt) { r.LocalGeneration++ }, func(r *Receipt) { r.SHA256 = hashBytes([]byte("bad")) }, func(r *Receipt) { r.SealedFingerprint = "wrong" }} {
		r := receipt(op, 1, "v1")
		mutate(&r)
		if err := s.Ack(testContext, r); !errors.Is(err, ErrInvalidReceipt) {
			t.Fatal("bad receipt accepted", r, err)
		}
	}
	state, _ := s.Entry(testContext, "root", "file")
	if state.Base != nil || state.Dirty == nil {
		t.Fatal("invalid ACK changed baseline/work")
	}
	for _, kind := range []string{"DELETE", "MOVE"} {
		wrong = op.Intent
		wrong.OperationID = "forbidden-" + kind
		wrong.Kind = kind
		if err := s.Plan(testContext, wrong); err == nil {
			t.Fatal("backup destructive operation accepted", kind)
		}
	}
	wrong = op.Intent
	wrong.OperationID = "oversized"
	wrong.SizeBytes = MaxFileBytes + 1
	if err := s.Plan(testContext, wrong); err == nil {
		t.Fatal("256 MiB bound removed")
	}
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	r := receipt(op, 1, "v2")
	if err := s.Ack(testContext, r); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatal("acknowledged receipt changed", err)
	}
}

func TestConcurrentGenerationCASRootBindingsAndWriterOwnership(t *testing.T) {
	s, dir := stateFixture(t)
	if other, err := Open(testContext, dir); !errors.Is(err, ErrStateInUse) {
		if other != nil {
			other.Close()
		}
		t.Fatal("second profile writer admitted", err)
	}
	duplicate := testBinding
	duplicate.RootID = "duplicate"
	duplicate.MappingID = "other-mapping"
	if err := s.BindRoot(testContext, duplicate); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("duplicate remote root admitted", err)
	}
	duplicate = testBinding
	duplicate.SourceIdentity = "other-source"
	if err := s.BindRoot(testContext, duplicate); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("mapping rebound", err)
	}
	var workers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		workers.Go(func() { results <- s.InvalidateTrust(testContext, "root", 1) })
	}
	workers.Wait()
	close(results)
	pass, stale := 0, 0
	for err := range results {
		if err == nil {
			pass++
		} else if errors.Is(err, ErrStaleGeneration) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if pass != 1 || stale != 1 {
		t.Fatal("CAS allowed two winners", pass, stale)
	}
}

func TestLegacyRollbackCheckpointInvalidatesTrustWithoutLosingB(t *testing.T) {
	s, dir := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "op", "file")
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"lastSuccessAt":"old-binary-ran"}`), 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	root, _ := reopened.Root(testContext, "root")
	cursor, _ := reopened.Cursor(testContext, "root", "local")
	state, _ := reopened.Entry(testContext, "root", "file")
	if root.TrustGeneration != 2 || root.EngineReady || cursor.Valid || state.Base.Version != "v1" {
		t.Fatal("rollback trusted stale observations or lost baseline", root, cursor, state)
	}
	if err = reopened.Submitted(testContext, op.OperationID); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale writer intent reauthorized", err)
	}
}

func TestCorruptUnsupportedSchemaPreservesDatabaseBytes(t *testing.T) {
	for _, kind := range []string{"corrupt", "future", "missing-table", "foreign-key"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, "sync-state.sqlite")
			if kind == "corrupt" {
				if err := os.WriteFile(name, []byte("not a database, preserve exactly"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				s, err := Open(testContext, dir)
				if err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "future":
					_, err = s.db.Exec("PRAGMA user_version=999")
				case "missing-table":
					_, err = s.db.Exec("DROP TABLE journal_cursors")
				case "foreign-key":
					_, err = s.db.Exec("PRAGMA foreign_keys=OFF; INSERT INTO journal_cursors(root_id,stream,epoch,position,valid) VALUES('missing-root','local','journal',1,1)")
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
					t.Fatal(err)
				}
				s.Close()
			}
			before, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if s, err := Open(testContext, dir); err == nil {
				s.Close()
				t.Fatal("invalid schema opened")
			}
			after, err := os.ReadFile(name)
			if err != nil || string(before) != string(after) {
				t.Fatal("unsupported/corrupt database rewritten", err)
			}
		})
	}
}

func TestBatchPageBoundsParentCyclesAndInodeAliases(t *testing.T) {
	s, _ := stateFixture(t)
	before, _ := s.Cursor(testContext, "root", "local")
	next := before
	next.Epoch = "journal"
	next.Valid = true
	if err := s.CaptureLocal(testContext, 1, before, next, make([]Observation, MaxBatch+1)); err == nil {
		t.Fatal("unbounded batch accepted")
	}
	for _, limit := range []int{0, MaxBatch + 1} {
		if _, err := s.DirtyPage(testContext, "root", "", limit); err == nil {
			t.Fatal("unbounded dirty page")
		}
		if _, err := s.PendingPage(testContext, "root", "", limit); err == nil {
			t.Fatal("unbounded operation page")
		}
	}
	parent := fileObservation("parent", "parent")
	parent.Kind = "folder"
	parent.SizeBytes = 0
	capture(t, s, parent)
	child := fileObservation("child", "child")
	child.Kind = "folder"
	child.SizeBytes = 0
	child.ParentID = "parent"
	capture(t, s, child)
	parent.ExpectedGeneration = 1
	parent.ParentID = "child"
	before, _ = s.Cursor(testContext, "root", "local")
	next = before
	next.Position++
	if err := s.CaptureLocal(testContext, 1, before, next, []Observation{parent}); err == nil {
		t.Fatal("parent cycle accepted")
	}
	for _, id := range []string{"alias-a", "alias-b"} {
		capture(t, s, fileObservation(id, id))
	}
	values, err := s.DirtyPage(testContext, "root", "", 2)
	if err != nil || len(values) != 2 || values[0].EntryID >= values[1].EntryID {
		t.Fatal("keyset/inode alias failure", values, err)
	}
}

func TestInterruptedProcessRollsBackWithoutCursorAdvance(t *testing.T) {
	s, dir := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	before, _ := s.Cursor(testContext, "root", "local")
	s.Close()
	backup := qualifyClosedFixtureBackup(t, dir, nil, func(restored *Store) {
		state, err := restored.Entry(testContext, "root", "file")
		if err != nil || state.Local.Generation != 1 || state.Dirty.ObservedGeneration != 1 {
			t.Fatal("restored original observation", state, err)
		}
		cursor, err := restored.Cursor(testContext, "root", "local")
		if err != nil || cursor != before {
			t.Fatal("restored original cursor", cursor, err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestStateCrashHelper$")
	command.Env = append(os.Environ(), "PLUTO_STATE_CRASH_DIR="+dir)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 33 {
		t.Fatal("crash fixture failed", err, string(output))
	}
	backup.recordActualExit(t, "TestStateCrashHelper", command.Process.Pid, exit.ExitCode())
	reopened, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state, err := reopened.Entry(testContext, "root", "file")
	if err != nil || state.Local.Generation != 1 || state.Dirty.ObservedGeneration != 1 {
		t.Fatal("uncommitted dirty state survived", state, err)
	}
	after, _ := reopened.Cursor(testContext, "root", "local")
	if before != after {
		t.Fatal("uncommitted cursor advanced", after)
	}
}

func TestStateCrashHelper(t *testing.T) {
	dir := os.Getenv("PLUTO_STATE_CRASH_DIR")
	if dir == "" {
		return
	}
	s, err := Open(testContext, dir)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(testContext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE dirty_entries SET observed_generation=100 WHERE root_id='root'"); err != nil {
		t.Fatal(err)
	}
	os.Exit(33) // Simulates death after work was written but before cursor/COMMIT.
}

func TestOperationIDAndNoSecretsInMigrationManifest(t *testing.T) {
	id, err := NewOperationID()
	if err != nil || len(id) != 36 || !validID(id) {
		t.Fatal("operation id", id, err)
	}
	s, _ := stateFixture(t)
	var raw string
	if err = s.db.QueryRow("SELECT manifest_json FROM schema_migrations").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatal(err)
	}
	if value["baseline"] != "UNKNOWN" || value["engineActivated"] != false || strings.Contains(raw, "accessToken") {
		t.Fatal("migration manifest overclaims or stores secrets", raw)
	}
}

func TestOverwriteRequiresAuthoritativeCurrentRemoteAndTrust(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "op", "file")
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	local := fileObservation("file", "file")
	local.ExpectedGeneration = 1
	capture(t, s, local)
	intent := fixtureIntent(t, s, "overwrite", "file")
	if err := s.Plan(testContext, intent); err == nil {
		t.Fatal("unknown remote allowed overwrite")
	}
	seedBaselineRemote(t, s, "file")
	if err := s.Plan(testContext, intent); err != nil {
		t.Fatal("authoritative identical R rejected", err)
	}
	if err := s.InvalidateTrust(testContext, "root", 1); err != nil {
		t.Fatal(err)
	}
	intent.OperationID = "new-trust"
	intent.TrustGeneration = 2
	if err := s.Plan(testContext, intent); err == nil {
		t.Fatal("old baseline trust authorized overwrite")
	}
}

func TestFirstTransportRechecksLocalRemoteAndObservedChecksum(t *testing.T) {
	for _, change := range []string{"local", "remote", "checksum", "trust"} {
		t.Run(change, func(t *testing.T) {
			s, _ := stateFixture(t)
			observation := fileObservation("file", "file")
			if change == "checksum" {
				observation.SHA256 = hashBytes([]byte("one"))
				observation.HashGeneration = 1
			}
			capture(t, s, observation)
			if change == "remote" {
				op := planned(t, s, "initial", "file")
				if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
					t.Fatal(err)
				}
				seedBaselineRemote(t, s, "file")
				observation.ExpectedGeneration = 1
				capture(t, s, observation)
			}
			intent := fixtureIntent(t, s, "new-op", "file")
			if err := s.Plan(testContext, intent); err != nil {
				t.Fatal(err)
			}
			if change == "checksum" {
				if err := s.Seal(testContext, intent.OperationID, hashBytes([]byte("bad")), "snapshot"); !errors.Is(err, ErrIdentityConflict) {
					t.Fatal("known checksum mismatch sealed", err)
				}
				return
			}
			if err := s.Seal(testContext, intent.OperationID, hashBytes([]byte("one")), "snapshot"); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "local":
				observation.ExpectedGeneration = 1
				capture(t, s, observation)
			case "trust":
				if err := s.InvalidateTrust(testContext, "root", 1); err != nil {
					t.Fatal(err)
				}
			case "remote":
				before, _ := s.Cursor(testContext, "root", "remote")
				next := before
				next.Position++
				r := RemoteEntry{RootID: "root", NodeID: "node-file", Name: "file", Kind: "file", Epoch: next.Epoch, Version: "conflicting-v2", SHA256: hashBytes([]byte("two")), Presence: "PRESENT", Generation: 1, SizeBytes: 3, LastSeq: next.Position}
				if err := s.ApplyRemote(testContext, 1, before, next, []RemoteEntry{r}); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Submitted(testContext, intent.OperationID); err == nil {
				t.Fatal("changed state authorized transport", change)
			}
			op, _ := s.Operation(testContext, intent.OperationID)
			if op.Stage != "SEALED" {
				t.Fatal("failed transport check persisted submission", op.Stage)
			}
		})
	}
}

func TestACKAfterTrustInvalidationRetainsEvidenceAndDirty(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "op", "file")
	if err := s.InvalidateTrust(testContext, "root", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal("late verified publication lost", err)
	}
	state, _ := s.Entry(testContext, "root", "file")
	root, _ := s.Root(testContext, "root")
	cursor, _ := s.Cursor(testContext, "root", "local")
	if state.Base == nil || state.Base.TrustGeneration != 1 || state.Dirty == nil || root.TrustGeneration != 2 || root.Trust != TrustRequired || cursor.Valid {
		t.Fatal("old ACK cleared trust/dirty", state, root, cursor)
	}
	if err := s.Submitted(testContext, op.OperationID); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("old operation may start another transport", err)
	}
}

func TestInitialACKRetainsRemoteChangeObservedBeforeBinding(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	op := planned(t, s, "op", "file")
	before, _ := s.Cursor(testContext, "root", "remote")
	next := before
	next.Epoch = "remote-epoch"
	next.Position = 2
	next.Valid = true
	r := RemoteEntry{RootID: "root", NodeID: "node-file", Name: "file", Kind: "file", Epoch: next.Epoch, Version: "v1", SHA256: op.SHA256, Presence: "PRESENT", Generation: 1, SizeBytes: 3, LastSeq: 1}
	r2 := r
	r2.LastSeq = 2
	r2.Version = "newer"
	r2.SHA256 = hashBytes([]byte("two"))
	if err := s.ApplyRemote(testContext, 1, before, next, []RemoteEntry{r, r2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(testContext, receipt(op, 1, "v1")); err != nil {
		t.Fatal(err)
	}
	state, _ := s.Entry(testContext, "root", "file")
	if state.Local.Generation != 1 || state.Base.Version != "v1" || state.Remote.Version != "newer" || state.Dirty == nil || state.Dirty.RemoteSeq != 2 {
		t.Fatal("new remote work lost before baseline binding", state)
	}
}

func TestDependencyPublicationPrecedesChildTransport(t *testing.T) {
	s, _ := stateFixture(t)
	parent := fileObservation("parent", "parent")
	parent.Kind = "folder"
	parent.SizeBytes = 0
	capture(t, s, parent)
	opParent := planned(t, s, "parent-op", "parent")
	child := fileObservation("child", "child")
	child.ParentID = "parent"
	capture(t, s, child)
	intent := fixtureIntent(t, s, "child-op", "child")
	intent.Dependencies = []string{opParent.OperationID}
	if err := s.Plan(testContext, intent); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(testContext, intent.OperationID, hashBytes([]byte("one")), "child-snapshot"); err != nil {
		t.Fatal(err)
	}
	if err := s.Submitted(testContext, intent.OperationID); err == nil {
		t.Fatal("child transported before parent publication")
	}
	if err := s.Ack(testContext, receipt(opParent, 1, "parent-v1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Submitted(testContext, intent.OperationID); err != nil {
		t.Fatal("published dependency did not unblock child", err)
	}
	wrong := intent
	wrong.OperationID = "cycle"
	wrong.Dependencies = []string{"cycle"}
	if err := s.Plan(testContext, wrong); err == nil {
		t.Fatal("self-dependency allowed")
	}
}

func TestConcurrentLocalGenerationCASAndCancelledTransaction(t *testing.T) {
	s, _ := stateFixture(t)
	capture(t, s, fileObservation("file", "file"))
	before, _ := s.Cursor(testContext, "root", "local")
	next := before
	next.Position++
	entry := fileObservation("file", "file")
	entry.ExpectedGeneration = 1
	var workers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		workers.Go(func() { results <- s.CaptureLocal(testContext, 1, before, next, []Observation{entry}) })
	}
	workers.Wait()
	close(results)
	winners, stale := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrStaleGeneration) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || stale != 1 {
		t.Fatal("local generation CAS has two winners", winners, stale)
	}
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	before, _ = s.Cursor(testContext, "root", "local")
	next = before
	next.Position++
	entry.ExpectedGeneration = 2
	if err := s.CaptureLocal(cancelled, 1, before, next, []Observation{entry}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled transaction accepted", err)
	}
	current, _ := s.Cursor(testContext, "root", "local")
	state, _ := s.Entry(testContext, "root", "file")
	if current != before || state.Local.Generation != 2 || state.Dirty.ObservedGeneration != 2 {
		t.Fatal("cancelled transaction changed observations/work/cursor", state, current)
	}
}

func TestMaximumBoundedBatchAndKeysetDoNotLoseWork(t *testing.T) {
	s, _ := stateFixture(t)
	before, _ := s.Cursor(testContext, "root", "local")
	next := before
	next.Epoch = "journal"
	next.Position = MaxBatch
	next.Valid = true
	entries := make([]Observation, MaxBatch)
	for i := range entries {
		id := fmt.Sprintf("file-%04d", i)
		entries[i] = fileObservation(id, id)
	}
	if err := s.CaptureLocal(testContext, 1, before, next, entries); err != nil {
		t.Fatal(err)
	}
	after := ""
	seen := map[string]bool{}
	for {
		page, err := s.DirtyPage(testContext, "root", after, 127)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, d := range page {
			if seen[d.EntryID] || d.ObservedGeneration != 1 {
				t.Fatal("keyset lost/duplicated pending work", d)
			}
			seen[d.EntryID] = true
		}
		after = page[len(page)-1].EntryID
	}
	if len(seen) != MaxBatch {
		t.Fatal("maximum bounded batch lost work", len(seen))
	}
	current, _ := s.Cursor(testContext, "root", "local")
	if current != next {
		t.Fatal("cursor did not commit with complete batch", current)
	}
}
