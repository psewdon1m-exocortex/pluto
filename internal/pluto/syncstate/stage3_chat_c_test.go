//go:build linux

package syncstate

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"pluto/internal/syncproto"
)

type stage3WireFixture struct {
	t                       *testing.T
	base                    *guardedHTTPFixture
	session                 *IsolatedHTTPSession
	mu                      sync.Mutex
	streams                 map[string]StreamStatus
	data                    map[string][]byte
	mutations               map[string]map[string]any
	chunkCalls              map[int]int
	loseChunk, loseMutation bool
	mutateFirst             func()
	firstHashBytes          int64
	lookup                  any
	rejectName              string
	streamFault             string
	folderBatches           []int
}

func TestStage3C03MigrationProcessCrash(t *testing.T) {
	if directory := os.Getenv("STAGE3_C03_CRASH_PROFILE"); directory != "" {
		store, err := Open(testContext, directory)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.EnableSources(testContext, DefaultSourceLimits()); err != nil {
			t.Fatal(err)
		}
		if _, err = store.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
			t.Fatal(err)
		}
		r, err := store.EnableRemoteImport(testContext)
		if err != nil {
			t.Fatal(err)
		}
		r.testPoint = func(point string) error {
			if point == "daemon.migration.before_commit" {
				os.Exit(86)
			}
			return nil
		}
		if err = r.EnableDaemonState(testContext); err != nil {
			t.Fatal(err)
		}
		t.Fatal("migration crash barrier not reached")
	}
	d, _, plan, witness := dispatchFixture(t, 2)
	r := d.session.r
	physical, err := r.sources.Binding(testContext, witness.SetID, "source")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(r.store.filename)
	d.session.Close()
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	backup := qualifyStage3PendingMigrationBackup(t, directory, physical.PhysicalPath, plan)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestStage3C03MigrationProcessCrash$")
	cmd.Env = append(os.Environ(), "STAGE3_C03_CRASH_PROFILE="+directory)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatal("child crash gate", string(out), err)
	}
	backup.recordActualExit(t, "TestStage3C03MigrationProcessCrash", cmd.Process.Pid, exit.ExitCode())
	store, err := Open(testContext, directory)
	if err != nil {
		t.Fatal("partial migration accepted as complete", err)
	}
	defer store.Close()
	var version int
	store.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 7 {
		t.Fatal("partial schema survived", version)
	}
	preserveStage3PendingDatabase(t, store, backup, "rolledback-v7", 7, plan)
	if _, err = store.EnableSources(testContext, DefaultSourceLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	r, err = store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	for _, entry := range plan.entries {
		op, e := store.Operation(testContext, entry.original.OperationID)
		if e != nil || op.IntentFingerprint != entry.original.IntentFingerprint || op.Stage != entry.original.Stage {
			t.Fatal("original changed by crash", e)
		}
	}
	preserveStage3PendingDatabase(t, store, backup, "forward-v8", 8, plan)
	stage3VerifyPendingPhysicalAfter(t, backup, directory, physical.PhysicalPath)
}

func TestStage3C03DisposedReservationSurvivesPruning(t *testing.T) {
	_, a, _ := artifactFixture(t)
	r, _ := sealedArtifact(t, a, []byte("captured but no publication needed"))
	if err := r.Dispose(testContext); err != nil {
		t.Fatal(err)
	}
	if removed, err := a.PruneDisposed(testContext, MaxSourcePage); err != nil || removed != 1 {
		t.Fatal("prune interleaving", removed, err)
	}
	// registryCaptureBudget.DisposeCaptureArtifact disposes, then finish(false)
	// repeats disposal; another capture can prune between those calls.
	if err := r.Dispose(testContext); err != nil {
		t.Fatal("completed disposal lost after prune", err)
	}
	if charge, err := a.Charge(testContext); err != nil || charge != 0 {
		t.Fatal("disposed charge restored", charge, err)
	}
	unknown, err := NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Dispose(testContext, unknown); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unknown disposal must still refuse", err)
	}
	retained, _ := sealedArtifact(t, a, []byte("still retained"))
	if err = retained.Relinquish(); err != nil {
		t.Fatal(err)
	}
	if removed, err := a.PruneDisposed(testContext, MaxSourcePage); err != nil || removed != 0 {
		t.Fatal("pruned retained capture", removed, err)
	}
	if row, err := a.Record(testContext, retained.ID()); err != nil || row.Phase != ArtifactSealed {
		t.Fatal("retained capture changed", row, err)
	}
}

func TestStage3C02NativeQueueOverflow(t *testing.T) {
	r, w, _, dir := stage3Daemon(t, 0)
	b, _ := r.sources.Binding(testContext, w.SetID, "source")
	o, err := NewLinuxObserver(testContext, r.sources, w)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.Watch(testContext, "source", dir, b.Destination); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("/proc/sys/fs/inotify/max_queued_events")
	if err != nil {
		t.Fatal(err)
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || limit < 1 || limit > 131072 {
		t.Fatal("native overflow capacity unsupported", limit, err)
	}
	// Block the consumer at the watch-map barrier while the real kernel queue
	// fills. Distinct filenames prevent inotify event coalescing.
	o.mu.Lock()
	for i := 0; i < limit+128; i++ {
		p := filepath.Join(dir, fmt.Sprintf("overflow-%06d", i))
		file, e := os.Create(p)
		if e != nil {
			o.mu.Unlock()
			t.Fatal(e)
		}
		file.Close()
	}
	o.mu.Unlock()
	stage3WaitWithin(t, 45*time.Second, func() bool {
		status, _ := r.sources.ObserverStatus(testContext, w)
		return status.Gap && strings.Contains(status.Reason, "overflow")
	})
}

func TestStage3C02NativePermissionFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		directory, err := os.MkdirTemp("/tmp", "stage3-c02-unprivileged-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(directory)
		os.Chmod(directory, 0755)
		data, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(directory, "test-helper")
		if err = os.WriteFile(child, data, 0755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(child, "-test.run=^TestStage3C02NativePermissionFailure$", "-test.v")
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal(string(out), err)
		}
		t.Log(string(out))
		return
	}
	r, w, _, dir := stage3Daemon(t, 0)
	b, _ := r.sources.Binding(testContext, w.SetID, "source")
	o, err := NewLinuxObserver(testContext, r.sources, w)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	locked := filepath.Join(dir, "locked")
	if err = os.Mkdir(locked, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0700)
	if err = o.ObserveEntry(testContext, "source", SourceDescriptor{PhysicalPath: locked, Destination: b.Destination + "/locked"}); err != nil {
		t.Fatal(err)
	}
	status, err := r.sources.ObserverStatus(testContext, w)
	if err != nil || !status.Gap || o.Healthy() {
		t.Fatal("permission failure lost gap", status, err)
	}
}

func TestStage3C02NativeUnmountGap(t *testing.T) {
	native := stage3NativeMount(t, "small")
	mount := native.directory
	s, w, _ := sourceFixture(t, mount)
	if err := s.store.BindRoot(testContext, RootBinding{RootID: "root", MappingID: "map", ServerIdentity: "server", RemoteRootID: "remote", DeviceID: "device", SourceIdentity: w.SetID}); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachSourceSet(testContext, w.SetID, w.Revision, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	r, err := s.store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Dir(s.store.filename), 0700)
	if err = r.enableHTTPBindings(testContext); err != nil {
		t.Fatal(err)
	}
	if err = r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	o, err := NewLinuxObserver(testContext, s, w)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	b, _ := s.Binding(testContext, w.SetID, "source")
	if err = o.Watch(testContext, "source", mount, b.Destination); err != nil {
		t.Fatal(err)
	}
	status, _ := s.ObserverStatus(testContext, w)
	s.ReconciledObserver(testContext, w, status.GapSequence)
	if err = native.unmount(); err != nil {
		t.Fatal(err)
	}
	stage3Wait(t, func() bool { v, _ := s.ObserverStatus(testContext, w); return v.Gap })
	if err = o.Health(testContext, []string{"source"}); err == nil {
		t.Fatal("unmount accepted as continuity")
	}
}

func TestStage3C03NativeDiskFullPreservesCommit(t *testing.T) {
	native := stage3NativeMount(t, "large")
	directory := native.directory
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.BindRoot(testContext, testBinding); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnableSources(testContext, SourceLimits{64 << 20, 8 << 20, 64 << 20, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnableArtifacts(testContext, DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	r, err := store.EnableRemoteImport(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err = r.enableHTTPBindings(testContext); err != nil {
		t.Fatal(err)
	}
	if err = r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	capture(t, store, fileObservation("committed", "latest-committed"))
	var committed string
	if err = store.db.QueryRow("SELECT descriptor_json FROM local_entries WHERE entry_id='committed'").Scan(&committed); err != nil {
		t.Fatal(err)
	}
	t.Logf("committed descriptor SHA256 %s", hashBytes([]byte(committed)))
	fill, err := os.Create(filepath.Join(directory, "quota-fill"))
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1<<20)
	var full error
	var filled int64
	for i := 0; i < 128; i++ {
		var written int
		written, full = fill.Write(block)
		filled += int64(written)
		if full != nil {
			break
		}
	}
	fill.Close()
	if !errors.Is(full, syscall.ENOSPC) {
		t.Fatal("fixture did not reach native ENOSPC", full)
	}
	t.Logf("native ENOSPC after %d bytes, block=%d maxWrites=128", filled, len(block))
	_, err = store.db.Exec("UPDATE local_entries SET descriptor_json=json_set(descriptor_json,'$.quotaProbe',?) WHERE entry_id='committed'", strings.Repeat("uncommitted", 1<<18))
	if err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatal("expected native SQLITE_FULL", err)
	}
	t.Log("native SQLite refusal", err)
	if err = os.Remove(filepath.Join(directory, "quota-fill")); err != nil {
		t.Fatal(err)
	}
	var saved string
	if err = store.db.QueryRow("SELECT descriptor_json FROM local_entries WHERE entry_id='committed'").Scan(&saved); err != nil || saved != committed {
		t.Fatal("latest commit lost", saved, err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.db.QueryRow("SELECT descriptor_json FROM local_entries WHERE entry_id='committed'").Scan(&saved); err != nil || saved != committed {
		t.Fatal("reopened commit lost", err)
	}
	t.Logf("reopened descriptor SHA256 %s", hashBytes([]byte(saved)))
}

func TestStage3C02ObserverDeathPeriodicCapture(t *testing.T) {
	r, w, session, dir := stage3Daemon(t, 1)
	o, err := NewLinuxObserver(testContext, r.sources, w)
	if err != nil {
		t.Fatal(err)
	}
	opts := scanOptions(t, r, w, session)
	opts.Hooks.Before = o.BeforeClaim
	opts.Hooks.Entry = o.ObserveEntry
	if report, err := r.RunCapturedScan(testContext, opts); err != nil || report.Uploaded != 1 {
		t.Fatal(report, err)
	}
	// Closing this owned native inotify fd makes the actual reader exit with
	// EBADF. No filesystem writes happen until that goroutine has joined.
	if err = unix.Close(o.fd); err != nil {
		t.Fatal(err)
	}
	select {
	case <-o.done:
	case <-time.After(5 * time.Second):
		t.Fatal("observer death not joined")
	}
	o.fd = -1
	defer o.Close()
	state, err := r.sources.ObserverStatus(testContext, w)
	if err != nil || !state.Gap || o.Healthy() {
		t.Fatal(state, err)
	}
	file := filepath.Join(dir, "file-0000")
	info, _ := os.Stat(file)
	if err = os.WriteFile(file, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(file, info.ModTime(), info.ModTime())
	// This is the same full guarded traversal used by the periodic fallback.
	opts = scanOptions(t, r, w, session)
	opts.Hooks.Before = o.BeforeClaim
	opts.Hooks.Entry = o.ObserveEntry
	report, err := r.RunCapturedScan(testContext, opts)
	if err != nil || report.Uploaded != 1 || !report.Complete {
		t.Fatal("missed same-mtime write", report, err)
	}
	state, _ = r.sources.ObserverStatus(testContext, w)
	if !state.Gap {
		t.Fatal("dead observer silently certified continuity")
	}
}

func TestStage3C02Native65536Watches(t *testing.T) {
	r, w, _, dir := stage3Daemon(t, 0)
	o, err := NewLinuxObserver(testContext, r.sources, w)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	for i := 0; i < maximumObserverWatches; i++ {
		path := filepath.Join(dir, strconv.Itoa(i))
		if err = os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal("native fixture file", i, err)
		}
		if err = o.Watch(testContext, "source", path, "files/"+strconv.Itoa(i)); err != nil {
			t.Fatal("native watch capacity unavailable", i, err)
		}
	}
	if len(o.paths) != 65536 || len(o.watches) != 65536 {
		t.Fatal("actual inotify registrations", len(o.paths), len(o.watches))
	}
	path := filepath.Join(dir, "over-budget")
	os.WriteFile(path, nil, 0600)
	if err = o.ObserveEntry(testContext, "source", SourceDescriptor{PhysicalPath: path, Destination: "files/over-budget", Kind: "file"}); err != nil {
		t.Fatal(err)
	}
	state, err := r.sources.ObserverStatus(testContext, w)
	if err != nil || !state.Gap || o.Healthy() || len(o.paths) != 65536 {
		t.Fatal("watch admission lost gap/bound", state, err)
	}
}

func TestStage3C02CrashAfterDurableHint(t *testing.T) {
	if directory := os.Getenv("STAGE3_C_HINT_STATE"); directory != "" {
		store, err := Open(testContext, directory)
		if err != nil {
			t.Fatal(err)
		}
		s, err := store.EnableSources(testContext, DefaultSourceLimits())
		if err != nil {
			t.Fatal(err)
		}
		set, err := s.Set(testContext, os.Getenv("STAGE3_C_HINT_SET"))
		if err != nil {
			t.Fatal(err)
		}
		w, err := s.BeginSourceOwner(testContext, set.ID, set.Revision, "crash-after-hint")
		if err != nil {
			t.Fatal(err)
		}
		if err = s.StartObserver(testContext, w); err != nil {
			t.Fatal(err)
		}
		b, err := s.Binding(testContext, set.ID, "source")
		if err != nil {
			t.Fatal(err)
		}
		if err = s.RecordDirty(testContext, w, []DirtyHint{{SourceID: "source", Destination: b.Destination + "/durable", PhysicalPath: filepath.Join(b.PhysicalPath, "durable"), Mask: 1}}); err != nil {
			t.Fatal(err)
		}
		os.Exit(86)
	}
	r, w, _, source := stage3Daemon(t, 0)
	originalRoot, err := r.store.Root(testContext, "root")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(r.store.filename)
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	backup := qualifyStage3DrainedHintBackup(t, directory, source, originalRoot.RootBinding)
	child := exec.Command(os.Args[0], "-test.run=^TestStage3C02CrashAfterDurableHint$")
	child.Env = append(os.Environ(), "STAGE3_C_HINT_STATE="+directory, "STAGE3_C_HINT_SET="+w.SetID)
	raw, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatal("native hint crash", string(raw), err)
	}
	backup.recordActualExit(t, "TestStage3C02CrashAfterDurableHint", child.Process.Pid, exit.ExitCode())
	store, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err = store.db.QueryRow("SELECT COUNT(*) FROM source_dirty WHERE set_id=? AND generation>0 AND destination LIKE '%/durable'", w.SetID).Scan(&count); err != nil || count != 1 {
		t.Fatal("committed hint lost on crash", count, err)
	}
	preserveStage3HintOutcome(t, store, backup, w.SetID, source)
}

func (f *stage3WireFixture) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/sync/v1/roots/"+f.base.binding.RootID+"/")
	if path == "directories/batch" {
		raw, err := io.ReadAll(io.LimitReader(req.Body, HTTPMetadataBytes+1))
		if err != nil || len(raw) > HTTPMetadataBytes {
			f.t.Error("unbounded folder batch")
			w.WriteHeader(413)
			return
		}
		var body struct {
			Binding any `json:"binding"`
			Items   []struct {
				Ref   string `json:"ref"`
				Input any    `json:"input"`
			} `json:"items"`
		}
		if json.Unmarshal(raw, &body) != nil || len(body.Items) > 500 {
			f.t.Error("folder batch limit")
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		f.folderBatches = append(f.folderBatches, len(body.Items))
		f.mu.Unlock()
		rows := []any{}
		for _, item := range body.Items {
			individual := req.Clone(req.Context())
			individual.URL.Path = strings.TrimSuffix(req.URL.Path, "batch") + "ensure-v2"
			individual.Body = io.NopCloser(bytes.NewReader(mustJSON(map[string]any{"binding": body.Binding, "input": item.Input})))
			out := httptest.NewRecorder()
			f.base.ServeHTTP(out, individual)
			if out.Code != 200 {
				rows = append(rows, map[string]any{"ref": item.Ref, "code": "precondition_failed"})
			} else {
				rows = append(rows, map[string]any{"ref": item.Ref, "outcome": jsonRawValue(out.Body.Bytes())})
			}
		}
		f.base.json(w, map[string]any{"schema": "saturn.folder-batch-result.v1", "items": rows})
		return
	}
	if !strings.HasPrefix(path, "stream-uploads/") && !strings.HasPrefix(path, "mutations/") && path != "content/lookup" {
		f.base.ServeHTTP(w, req)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, err := io.ReadAll(io.LimitReader(req.Body, StreamChunkBytes+HTTPMetadataBytes+5))
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(500)
		return
	}
	var payload []byte
	if path == "stream-uploads/chunk" {
		if len(raw) < 4 {
			w.WriteHeader(400)
			return
		}
		n := int(binary.BigEndian.Uint32(raw))
		if n > HTTPMetadataBytes || 4+n > len(raw) {
			w.WriteHeader(400)
			return
		}
		payload = raw[4+n:]
		raw = raw[4 : 4+n]
		if req.Header.Get("Content-Encoding") != "" {
			f.t.Error("binary was compressed")
		}
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		w.WriteHeader(400)
		return
	}
	if path == "content/lookup" {
		f.base.json(w, map[string]any{"reference": f.lookup})
		return
	}
	if strings.HasPrefix(path, "mutations/") {
		execute := func(input map[string]any) map[string]any {
			id, _ := input["operationId"].(string)
			if result := f.mutations[id]; result != nil {
				return result
			}
			op, e := f.base.r.store.Operation(req.Context(), id)
			if e != nil || op.Mutation == nil || op.Stage != "SUBMITTED" {
				f.t.Error("mutation before durable original", e)
				return nil
			}
			if input["kind"] == "move" || input["kind"] == "delete" {
				f.t.Error("backup caller acquired destructive authority")
			}
			f.base.mu.Lock()
			defer f.base.mu.Unlock()
			parent := op.Captured.Parents[len(op.Captured.Parents)-1].Remote.NodeID
			d := fileRemote(remoteVersion(8100+len(f.mutations)), parent, op.Name, "")
			d.SizeBytes = remoteDecimal(op.SizeBytes)
			sha := op.SHA256
			d.ContentSHA256 = &sha
			content := remoteVersion(8200 + len(f.mutations))
			d.ContentVersionID = &content
			d.Version = remoteVersion(8300 + len(f.mutations))
			if input["kind"] == "metadata-patch" {
				d.NodeID = op.ExpectedNodeID
				content = op.Captured.ExpectedContentVersionID
				d.ContentVersionID = &content
			}
			f.base.emit(d, id)
			result := map[string]any{"schema": "saturn.namespace-mutation-status.v1", "operationId": id, "intentHash": hashBytes([]byte("opaque:" + id)), "state": "PUBLISHED", "result": map[string]any{"description": wireDescriptor(d), "firstSeq": remoteDecimal(f.base.seq), "lastSeq": remoteDecimal(f.base.seq), "tombstone": false}}
			f.mutations[id] = result
			return result
		}
		if path == "mutations/batch" {
			rows := body["items"].([]any)
			out := []any{}
			for _, v := range rows {
				row := v.(map[string]any)
				input := row["input"].(map[string]any)
				if input["name"] == f.rejectName {
					out = append(out, map[string]any{"ref": row["ref"], "code": "precondition_failed"})
				} else {
					out = append(out, map[string]any{"ref": row["ref"], "outcome": execute(input)})
				}
			}
			if f.loseMutation {
				f.loseMutation = false
				f.base.lose(w)
				return
			}
			f.base.json(w, map[string]any{"outcomes": out})
			return
		}
		input := body["input"].(map[string]any)
		id := input["operationId"].(string)
		if path == "mutations/status" {
			if saved := f.mutations[id]; saved != nil {
				f.base.json(w, saved)
			} else {
				w.WriteHeader(404)
			}
			return
		}
		f.base.json(w, execute(input))
		return
	}
	input := body["input"].(map[string]any)
	id := input["operationId"].(string)
	op, e := f.base.r.store.Operation(req.Context(), id)
	if e != nil || op.Stream == nil {
		f.t.Error("stream before durable prepare", e)
		w.WriteHeader(500)
		return
	}
	if !reflect.DeepEqual(jsonRawValue(op.Stream.Input), jsonRawValue(mustJSON(input))) {
		f.t.Error("immutable stream input changed")
		w.WriteHeader(409)
		return
	}
	status, exists := f.streams[id]
	if !exists {
		status = StreamStatus{Schema: "saturn.stream-upload-status.v1", OperationID: id, State: "RECEIVING", Received: "0", Chunks: []StreamChunk{}, Publication: json.RawMessage("null")}
	}
	switch path {
	case "stream-uploads/prepare", "stream-uploads/status":
		if f.streamFault == "quota" {
			w.WriteHeader(507)
			return
		}
		if f.streamFault == "unknown" {
			status.State = "UNKNOWN"
		}
	case "stream-uploads/chunk":
		var chunk StreamChunk
		if json.Unmarshal(mustJSON(body["chunk"]), &chunk) != nil {
			w.WriteHeader(400)
			return
		}
		if chunk.Index != len(status.Chunks) || chunk.SHA256 != hashBytes(payload) || chunk.Offset != remoteDecimal(int64(len(f.data[id]))) {
			f.t.Error("duplicate/incorrect stream chunk", chunk.Index)
			w.WriteHeader(409)
			return
		}
		f.chunkCalls[chunk.Index]++
		if chunk.Index == 0 {
			if op.SHA256 != "" {
				f.t.Error("stream waited for final seal")
			}
			f.firstHashBytes = CaptureMetricSnapshot().SourceHashBytes
			if f.mutateFirst != nil {
				f.mutateFirst()
			}
		}
		f.data[id] = append(f.data[id], payload...)
		status.Chunks = append(status.Chunks, chunk)
		status.Received = remoteDecimal(int64(len(f.data[id])))
		if f.streamFault == "chunk" {
			status.Chunks[len(status.Chunks)-1].SHA256 = strings.Repeat("0", 64)
		}
		f.streams[id] = status
		if f.loseChunk {
			f.loseChunk = false
			f.base.lose(w)
			return
		}
	case "stream-uploads/seal", "stream-uploads/complete":
		if status.State != "PUBLISHED" {
			if op.SHA256 == "" || op.SHA256 != hashBytes(f.data[id]) {
				f.t.Error("invalid whole source seal")
				w.WriteHeader(422)
				return
			}
			f.base.mu.Lock()
			defer f.base.mu.Unlock()
			sha := op.SHA256
			d := fileRemote(remoteVersion(9100+len(f.streams)), op.Stream.RemoteParent, op.Name, "")
			d.SizeBytes = remoteDecimal(op.SizeBytes)
			d.ContentSHA256 = &sha
			cv := remoteVersion(9200 + len(f.streams))
			d.ContentVersionID = &cv
			f.base.emit(d, id)
			intentHash, e := streamSealedIntentHash(op)
			if e != nil {
				f.t.Error(e)
				w.WriteHeader(500)
				return
			}
			rc := map[string]any{"schema": "saturn.upload-publication.v1", "uploadId": id, "operationId": id, "intentHash": intentHash, "rootId": f.base.binding.RootID, "resourceId": d.NodeID, "versionId": cv, "parentId": op.Stream.RemoteParent, "name": op.Name, "sizeBytes": remoteDecimal(op.SizeBytes), "sha256": sha, "etag": fmt.Sprintf("\"sha256-%s\"", sha), "publishedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z")}
			result := map[string]any{"schema": "saturn.catalog-upload-result.v2", "status": "PUBLISHED", "uploadId": id, "operationId": id, "rootId": f.base.binding.RootID, "intentHash": intentHash, "publicationReceipt": rc, "publishedDescription": wireDescriptor(d), "firstSeq": remoteDecimal(f.base.seq), "lastSeq": remoteDecimal(f.base.seq)}
			status.State = "PUBLISHED"
			status.FinalSHA256 = &sha
			if f.streamFault == "final" {
				bad := strings.Repeat("0", 64)
				status.FinalSHA256 = &bad
			}
			status.Publication = mustJSON(map[string]any{"session": map[string]any{"uploadId": id, "operationId": id, "rootId": f.base.binding.RootID, "intentHash": intentHash, "expectedSizeBytes": remoteDecimal(op.SizeBytes), "receivedSizeBytes": remoteDecimal(op.SizeBytes), "phase": "published", "transferPending": false}, "replayed": false, "result": result})
		}
	default:
		f.t.Error("unexpected stream path", path)
		w.WriteHeader(404)
		return
	}
	f.streams[id] = status
	f.base.json(w, status)
}

func stage3Wire(t *testing.T, count int) (*RemoteImport, SourceWitness, *IsolatedHTTPSession, *stage3WireFixture, string) {
	t.Helper()
	r, _, w, old, base, dir := actualHTTPFixture(t, count)
	old.Close()
	f := &stage3WireFixture{t: t, base: base, streams: map[string]StreamStatus{}, data: map[string][]byte{}, mutations: map[string]map[string]any{}, chunkCalls: map[int]int{}}
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)
	s, err := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: server.URL, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(base.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"})
	if err != nil {
		t.Fatal(err)
	}
	f.session = s
	t.Cleanup(s.Close)
	s.SetRecoveryReader(artifactTestReader)
	if err = s.InitializeRemote(testContext); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Dir(r.store.filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err = r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	s.features = map[string]bool{}
	s.namespace = map[string]any{"codec": "legacy", "policyHash": hashBytes([]byte("fixture-policy"))}
	return r, w, s, f, dir
}
func stage3HTTPScan(t *testing.T, r *RemoteImport, w SourceWitness, s *IsolatedHTTPSession) (CapturedScanReport, error) {
	t.Helper()
	return r.RunCapturedScan(testContext, CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: s, AcquireRecovery: artifactTestReader, AcquireStream: artifactTestReader, Capture: func(ctx context.Context, w SourceWitness, e SourceEntry) (*VerifiedSnapshot, error) {
		return CaptureGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	}})
}

func TestStage3C08EmptyAndMetadataProof(t *testing.T) {
	r, w, s, f, dir := stage3Wire(t, 0)
	s.features["namespace-mutations-v1"] = true
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := stage3HTTPScan(t, r, w, s)
	if err != nil || report.Uploaded != 1 {
		t.Fatal(report, err)
	}
	if s.Metrics().DataBytes != 0 || len(f.mutations) != 1 {
		t.Fatal("empty sent data", s.Metrics(), f.mutations)
	}
	before, _ := os.Stat(path)
	stamp := before.ModTime().Add(2 * time.Second)
	if err = os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	report, err = stage3HTTPScan(t, r, w, s)
	if err != nil || report.Uploaded != 1 {
		t.Fatal("metadata", report, err)
	}
	var patches int
	if err = r.store.db.QueryRow("SELECT COUNT(*) FROM operations WHERE kind='METADATA_PATCH' AND stage='CLIENT_ACKED'").Scan(&patches); err != nil || patches != 1 {
		t.Fatal("metadata original", patches, err)
	}
	if s.Metrics().DataBytes != 0 {
		t.Fatal("metadata sent data")
	}
	if err = os.WriteFile(path, []byte("changed bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, stamp, stamp)
	report, err = stage3HTTPScan(t, r, w, s)
	if err != nil || report.Uploaded != 1 || s.Metrics().DataBytes != 13 {
		t.Fatal("mtime silence bypassed capture", report, s.Metrics(), err)
	}
}
func TestStage3C08MixedMutationBatchAndLostACK(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(fmt.Sprint(loss), func(t *testing.T) {
			r, w, s, f, dir := stage3Wire(t, 0)
			s.features["namespace-mutations-v1"] = true
			f.loseMutation = loss
			if !loss {
				f.rejectName = "reject"
			}
			for _, name := range []string{"accept", "reject"} {
				if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := stage3HTTPScan(t, r, w, s)
			if err == nil {
				t.Fatal("expected partial/lost ACK", report)
			}
			if !loss {
				var ack int
				r.store.db.QueryRow("SELECT COUNT(*) FROM operations WHERE kind='PUT' AND stage='CLIENT_ACKED'").Scan(&ack)
				if ack != 1 {
					t.Fatal("batch acknowledged rejected item", ack)
				}
				return
			}
			var ids []string
			rows, e := r.store.db.Query("SELECT operation_id FROM operations WHERE kind='PUT'")
			if e != nil {
				t.Fatal(e)
			}
			for rows.Next() {
				var id string
				rows.Scan(&id)
				ids = append(ids, id)
			}
			rows.Close()
			r.store.db.Exec("UPDATE operation_retry SET next_ms=0")
			for _, id := range ids {
				op, e := r.store.Operation(testContext, id)
				if e != nil {
					t.Fatal(e)
				}
				if op.Stage == "CLIENT_ACKED" {
					continue
				}
				pub, e := s.Recover(testContext, op)
				if e != nil || pub == nil {
					t.Fatal("lost mutation recovery", e)
				}
				if e = r.AckCaptured(testContext, *pub); e != nil {
					t.Fatal(e)
				}
			}
			if len(f.mutations) != 2 {
				t.Fatal("replacement mutation", len(f.mutations))
			}
		})
	}
}

func TestStage3C05AdditionalUnicodeConflictKeepsOriginalNames(t *testing.T) {
	r, w, s, f, dir := stage3Wire(t, 0)
	a, err := syncproto.NameKey("Ö", "portable_v1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := syncproto.NameKey("ö", "portable_v1")
	if err != nil || a == b {
		t.Fatal("portable Unicode pair unexpectedly aliases", a, b, err)
	}
	if _, err = r.store.db.Exec("UPDATE roots SET name_codec='portable_v1' WHERE root_id='root'"); err != nil {
		t.Fatal(err)
	}
	s.namespace["codec"] = "portable_v1"
	s.features["namespace-mutations-v1"] = true
	// Server-side lower(name) uniqueness may be stricter than portable keys.
	// Exercise its typed rejection at the real mutation caller boundary.
	f.rejectName = "ö"
	for _, name := range []string{"Ö", "ö"} {
		if err = os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := stage3HTTPScan(t, r, w, s)
	if err == nil || report.Complete {
		t.Fatal("server collision reported successful", report, err)
	}
	rows, err := r.store.db.Query("SELECT operation_id FROM operations WHERE kind='PUT'")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatal("collision created replacement operations", ids)
	}
	for _, id := range ids {
		op, e := r.store.Operation(testContext, id)
		if e != nil {
			t.Fatal(e)
		}
		if op.Name != "Ö" && op.Name != "ö" {
			t.Fatal("silent server conflict rename", op.Name)
		}
		if op.Name == "ö" && op.Stage == "CLIENT_ACKED" || op.Name == "Ö" && op.Stage != "CLIENT_ACKED" {
			t.Fatal("wrong per-item outcome", op.Name, op.Stage)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("source changed after conflict", entries, err)
	}
	for _, e := range entries {
		if e.Name() != "Ö" && e.Name() != "ö" {
			t.Fatal("source renamed", e.Name())
		}
	}
}
func TestStage3C08CloneAndCapabilityOff(t *testing.T) {
	for _, mode := range []string{"clone", "no-match", "off", "wrong-hash", "foreign-scope"} {
		t.Run(mode, func(t *testing.T) {
			r, w, s, f, _ := stage3Wire(t, 1)
			if mode != "off" {
				s.features["namespace-mutations-v1"] = true
				s.features["clone-content-v1"] = true
			}
			if mode == "clone" || mode == "wrong-hash" || mode == "foreign-scope" {
				sha := hashBytes([]byte("one"))
				if mode == "wrong-hash" {
					sha = hashBytes([]byte("bad"))
				}
				f.lookup = map[string]any{"nodeId": remoteVersion(7001), "contentVersionId": remoteVersion(7002), "metadataVersion": remoteVersion(7003), "sizeBytes": "3", "sha256": sha}
				if mode == "foreign-scope" {
					f.lookup.(map[string]any)["rootId"] = remoteVersion(7999)
				}
			}
			report, err := stage3HTTPScan(t, r, w, s)
			if mode == "wrong-hash" || mode == "foreign-scope" {
				if err == nil || report.Uploaded != 0 {
					t.Fatal("bad clone accepted", report, err)
				}
				return
			}
			if err != nil || report.Uploaded != 1 {
				t.Fatal(report, err)
			}
			if mode == "clone" {
				if s.Metrics().DataBytes != 0 || len(f.mutations) != 1 {
					t.Fatal("clone data", s.Metrics())
				}
			} else if s.Metrics().DataBytes != 3 {
				t.Fatal("fallback data", s.Metrics())
			}
		})
	}
}
func TestStage3C09EarlyChunksAndRestart(t *testing.T) {
	for _, size := range []int{8<<20 + 1, 12<<20 + 17} {
		for _, loss := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-loss-%v", size, loss), func(t *testing.T) {
				r, w, s, f, dir := stage3Wire(t, 0)
				s.features["stream-upload-v1"] = true
				f.loseChunk = loss
				data := make([]byte, size)
				for i := range data {
					data[i] = byte((314159 + i*31) % 251)
				}
				if err := os.WriteFile(filepath.Join(dir, "large"), data, 0600); err != nil {
					t.Fatal(err)
				}
				metrics := CaptureMetricSnapshot()
				report, err := stage3HTTPScan(t, r, w, s)
				f.mu.Lock()
				firstHashBytes := f.firstHashBytes
				f.mu.Unlock()
				if firstHashBytes-metrics.SourceHashBytes != StreamChunkBytes {
					t.Fatal("first send did not precede full hash", firstHashBytes-metrics.SourceHashBytes)
				}
				if loss {
					if err == nil {
						t.Fatal("lost response accepted", report)
					}
					var id string
					if e := r.store.db.QueryRow("SELECT operation_id FROM operations WHERE kind='STREAM_PUT'").Scan(&id); e != nil {
						t.Fatal(e)
					}
					original, e := r.store.Operation(testContext, id)
					if e != nil {
						t.Fatal(e)
					}
					directory := filepath.Dir(r.store.filename)
					s.Close()
					if e = r.store.Close(); e != nil {
						t.Fatal(e)
					}
					reopened, e := Open(testContext, directory)
					if e != nil {
						t.Fatal(e)
					}
					defer reopened.Close()
					if _, e = reopened.EnableSources(testContext, DefaultSourceLimits()); e != nil {
						t.Fatal(e)
					}
					if _, e = reopened.EnableArtifacts(testContext, DefaultArtifactLimits()); e != nil {
						t.Fatal(e)
					}
					rr, e := reopened.EnableRemoteImport(testContext)
					if e != nil {
						t.Fatal(e)
					}
					f.base.r = rr
					next, e := NewIsolatedHTTPSession(testContext, rr, "root", s.requested)
					if e != nil {
						t.Fatal(e)
					}
					defer next.Close()
					next.SetRecoveryReader(artifactTestReader)
					next.features = s.features
					next.namespace = s.namespace
					reopened.db.Exec("UPDATE operation_retry SET next_ms=0")
					if e = next.StreamOriginal(testContext, original, artifactTestReader); e != nil {
						t.Fatal("stream restart", e)
					}
					r = rr
				} else if err != nil || report.Uploaded != 1 {
					t.Fatal(report, err)
				}
				var id string
				if e := r.store.db.QueryRow("SELECT operation_id FROM operations WHERE kind='STREAM_PUT'").Scan(&id); e != nil {
					t.Fatal(e)
				}
				op, e := r.store.Operation(testContext, id)
				if e != nil || op.Stage != "CLIENT_ACKED" || op.SHA256 != hashBytes(data) {
					t.Fatal(op.Stage, e)
				}
				for index, n := range f.chunkCalls {
					if n != 1 {
						t.Fatal("ACKed chunk resent", index, n)
					}
				}
				if len(f.chunkCalls) != (size+StreamChunkBytes-1)/StreamChunkBytes {
					t.Fatal(f.chunkCalls)
				}
			})
		}
	}
}
func TestStage3C09ChangedSourceRetainsOriginal(t *testing.T) {
	for _, fault := range []string{"replace", "delete"} {
		t.Run(fault, func(t *testing.T) {
			r, w, s, f, dir := stage3Wire(t, 0)
			s.features["stream-upload-v1"] = true
			path := filepath.Join(dir, "large")
			data := bytes.Repeat([]byte("a"), 8<<20+1)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			f.mutateFirst = func() {
				if fault == "replace" {
					if err := os.Rename(path, path+".old"); err != nil {
						t.Error(err)
					}
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Error(err)
					}
				} else if err := os.Remove(path); err != nil {
					t.Error(err)
				}
			}
			report, err := stage3HTTPScan(t, r, w, s)
			if err == nil || report.Uploaded != 0 {
				t.Fatal("changed source published", report, err)
			}
			var n int
			r.store.db.QueryRow("SELECT COUNT(*) FROM operations WHERE kind='STREAM_PUT' AND stage='SUBMITTED'").Scan(&n)
			if n != 1 {
				t.Fatal("original missing", n)
			}
			for _, status := range f.streams {
				if status.State == "PUBLISHED" {
					t.Fatal("published without source proof")
				}
			}
		})
	}
}

func stage3Daemon(t *testing.T, files int) (*RemoteImport, SourceWitness, *fixtureCapturedSession, string) {
	t.Helper()
	r, w, s, dir := scanExecutorFixture(t, files)
	if err := os.Chmod(filepath.Dir(r.store.filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := r.enableHTTPBindings(testContext); err != nil {
		t.Fatal(err)
	}
	if err := r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	return r, w, s, dir
}
func stage3Wait(t *testing.T, condition func() bool) {
	t.Helper()
	stage3WaitWithin(t, 5*time.Second, condition)
}
func stage3WaitWithin(t *testing.T, watchdog time.Duration, condition func() bool) {
	t.Helper()
	until := time.Now().Add(watchdog)
	for !condition() {
		if time.Now().After(until) {
			t.Fatal("native condition watchdog")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStage3C02DurableGenerationsDebounceAndGap(t *testing.T) {
	r, w, _, dir := stage3Daemon(t, 0)
	s := r.sources
	if err := s.StartObserver(testContext, w); err != nil {
		t.Fatal(err)
	}
	b, _ := s.Binding(testContext, w.SetID, "source")
	h := DirtyHint{SourceID: "source", Destination: b.Destination + "/file", PhysicalPath: filepath.Join(dir, "file"), Mask: 1}
	if err := s.RecordDirty(testContext, w, []DirtyHint{h}); err != nil {
		t.Fatal(err)
	}
	first, err := s.DirtyPage(testContext, w, time.Now().Add(time.Second))
	if err != nil || len(first) != 1 {
		t.Fatal(first, err)
	}
	if page, err := s.DirtyPage(testContext, w, time.UnixMilli(first[0].LastMS+749)); err != nil || len(page) != 0 {
		t.Fatal("debounce", page, err)
	}
	if page, err := s.DirtyPage(testContext, w, time.UnixMilli(first[0].LastMS+750)); err != nil || len(page) != 1 {
		t.Fatal("750ms boundary", page, err)
	}
	if err = s.RecordDirty(testContext, w, []DirtyHint{h}); err != nil {
		t.Fatal(err)
	}
	// Continuous writes cannot postpone a hint beyond five seconds.
	if _, err = s.store.db.Exec("UPDATE source_dirty SET first_ms=?,last_ms=? WHERE set_id=?", time.Now().Add(-5*time.Second).UnixMilli(), time.Now().UnixMilli(), w.SetID); err != nil {
		t.Fatal(err)
	}
	if page, e := s.DirtyPage(testContext, w, time.Now()); e != nil || len(page) != 1 {
		t.Fatal("maximum age", page, e)
	}
	if err = s.AckDirty(testContext, w, first[0]); err != nil {
		t.Fatal(err)
	}
	next, _ := s.DirtyPage(testContext, w, time.Now().Add(time.Second))
	if len(next) != 1 || next[0].Generation <= first[0].Generation {
		t.Fatal("late ACK consumed g+1", next)
	}
	before, _ := s.ObserverStatus(testContext, w)
	if err = s.ObserverGap(testContext, w, "overflow fixture"); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconciledObserver(testContext, w, before.GapSequence); err != nil {
		t.Fatal(err)
	}
	after, _ := s.ObserverStatus(testContext, w)
	if !after.Gap {
		t.Fatal("old proof closed new gap")
	}
	if err = s.ReconciledObserver(testContext, w, after.GapSequence); err != nil {
		t.Fatal(err)
	}
	after, _ = s.ObserverStatus(testContext, w)
	if after.Gap {
		t.Fatal("matching proof failed")
	}
	stateDir := filepath.Dir(r.store.filename)
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(testContext, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var generation int64
	if err = reopened.db.QueryRow("SELECT generation FROM source_dirty WHERE set_id=?", w.SetID).Scan(&generation); err != nil || generation != next[0].Generation {
		t.Fatal("hint lost on reopen", generation, err)
	}
}

func TestStage3C02NativeEventsAndReplacement(t *testing.T) {
	r, w, _, dir := stage3Daemon(t, 0)
	s := r.sources
	b, _ := s.Binding(testContext, w.SetID, "source")
	o, err := NewLinuxObserver(testContext, s, w)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.Watch(testContext, "source", dir, b.Destination); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "COMLPT1.md")
	if err = os.WriteFile(path, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	stage3Wait(t, func() bool { p, _ := s.DirtyPage(testContext, w, time.Now().Add(time.Second)); return len(p) > 0 })
	if err = o.Watch(testContext, "source", path, b.Destination+"/COMLPT1.md"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".tmp", []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
	stage3Wait(t, func() bool { o.mu.Lock(); defer o.mu.Unlock(); return !o.paths["source\x00"+path] })
	if err = o.Watch(testContext, "source", path, b.Destination+"/COMLPT1.md"); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ObserverStatus(testContext, w)
	if err = os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	stage3Wait(t, func() bool { v, _ := s.ObserverStatus(testContext, w); return v.Sequence > before.Sequence })
	if err = os.Mkdir(filepath.Join(dir, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	stage3Wait(t, func() bool {
		p, _ := s.DirtyPage(testContext, w, time.Now().Add(time.Second))
		for _, h := range p {
			if strings.HasSuffix(h.Destination, "/empty") {
				return true
			}
		}
		return false
	})
	if err = os.Rename(path, filepath.Join(dir, "renamed")); err != nil {
		t.Fatal(err)
	}
	stage3Wait(t, func() bool {
		p, _ := s.DirtyPage(testContext, w, time.Now().Add(time.Second))
		for _, h := range p {
			if strings.HasSuffix(h.Destination, "/renamed") {
				return true
			}
		}
		return false
	})
}

func TestStage3C02WatchBudgetAndTargetScope(t *testing.T) {
	r, w, _, dir := stage3Daemon(t, 0)
	s := r.sources
	b, _ := s.Binding(testContext, w.SetID, "source")
	o, err := NewLinuxObserver(testContext, s, w)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	status, _ := s.ObserverStatus(testContext, w)
	if err = s.ReconciledObserver(testContext, w, status.GapSequence); err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	for i := 0; i < maximumObserverWatches; i++ {
		o.paths[fmt.Sprint(i)] = true
	}
	o.mu.Unlock()
	if err = o.ObserveEntry(testContext, "source", SourceDescriptor{PhysicalPath: dir, Destination: b.Destination}); err != nil {
		t.Fatal(err)
	}
	status, _ = s.ObserverStatus(testContext, w)
	if !status.Gap || o.Healthy() {
		t.Fatal("watch exhaustion lost gap", status)
	}
	child := filepath.Join(dir, "only")
	if err = os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	_, err = s.BeginTargetScan(testContext, w, DirtyHint{SourceID: "source", PhysicalPath: child, Destination: b.Destination + "/only"}, "targeted")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimScanFrontier(testContext, w, "targeted")
	if err != nil || claim.PhysicalPath != child {
		t.Fatal("target broadened", claim, err)
	}
	if _, err = s.BeginTargetScan(testContext, w, DirtyHint{SourceID: "source", PhysicalPath: filepath.Dir(dir), Destination: b.Destination}, "escape"); err == nil {
		t.Fatal("escaped source")
	}
}

func TestStage3C03V7WALMigrationOriginalsBackup(t *testing.T) {
	d, _, plan, _ := dispatchFixture(t, 6)
	r := d.session.r
	before := map[string]string{}
	for _, e := range plan.entries {
		var raw string
		if err := r.store.db.QueryRow("SELECT intent_json FROM operations WHERE operation_id=?", e.original.OperationID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		before[e.original.OperationID] = raw
	}
	if _, err := r.store.db.Exec("UPDATE roots SET legacy_checkpoint='wal-c03' WHERE root_id='root'"); err != nil {
		t.Fatal(err)
	}
	if err := r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	if err := r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	var version int
	r.store.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 8 {
		t.Fatal(version)
	}
	var raw string
	if err := r.store.db.QueryRow("SELECT manifest_json FROM schema_migrations WHERE version=8").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Backup string `json:"backup"`
		SHA    string `json:"backupSHA256"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(filepath.Dir(r.store.filename), "sync-state-backups", m.Backup)
	data, err := os.ReadFile(backupPath)
	if err != nil || hashBytes(data) != m.SHA {
		t.Fatal("backup hash", err)
	}
	db, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 7 {
		t.Fatal("backup version", version)
	}
	if err = db.QueryRow("SELECT legacy_checkpoint FROM roots WHERE root_id='root'").Scan(&raw); err != nil || raw != "wal-c03" {
		t.Fatal("WAL missing", raw, err)
	}
	for id, want := range before {
		for _, q := range []*sql.DB{db, r.store.db} {
			if err = q.QueryRow("SELECT intent_json FROM operations WHERE operation_id=?", id).Scan(&raw); err != nil || raw != want {
				t.Fatal("original changed", id, err)
			}
		}
	}
}

func stage3Capabilities(s *IsolatedHTTPSession) map[string]any {
	return map[string]any{"schema": "saturn.sync-capabilities.v1", "binding": bindingHTTP(s.binding), "device_id": s.identity.DeviceID, "backend_identity": s.identity.BackendIdentity, "qualification_receipt_sha256": s.identity.ContractReceiptSHA256, "features": []string{"snapshot-v1", "changes-v1", "folder-v2", "catalog-upload-v2", "changes-wait-v1", "folder-batch-v1", "namespace-mutations-v1", "stream-upload-v1", "metadata-gzip-v1", "clone-content-v1"}, "extensions": map[string]any{"revisions": map[string]int{"K1": 2, "K2": 2, "K3": 2, "K4": 1}, "namespace": map[string]string{"codec": "legacy", "policyHash": hashBytes([]byte("policy"))}, "minimum_writer": "saturn.namespace-mutation.v1", "backend_policy": "managed-exclusive", "limits": map[string]int{"metadata_items": 500, "metadata_bytes": 4194304, "long_poll_ms": 25000, "gzip_threshold_bytes": 16384, "stream_chunk_bytes": 4194304, "stream_maximum_chunks": 256}}}
}
func TestStage3C04NegotiationStrictQualification(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "null", "string", "array", "revision", "epoch", "device", "backend", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			_, _, _, s, _, _ := actualHTTPFixture(t, 0)
			caps := stage3Capabilities(s)
			switch kind {
			case "missing":
				delete(caps, "binding")
			case "null":
				caps["binding"] = nil
			case "string":
				caps["binding"] = "bad"
			case "array":
				caps["binding"] = []any{}
			case "revision":
				caps["extensions"].(map[string]any)["revisions"].(map[string]int)["K1"] = 999
			case "epoch":
				caps["binding"].(map[string]any)["server_epoch"] = remoteVersion(999)
			case "device":
				caps["device_id"] = remoteVersion(999)
			case "backend":
				caps["backend_identity"] = "foreign"
			case "receipt":
				caps["qualification_receipt_sha256"] = strings.Repeat("0", 64)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(caps)
			}))
			defer server.Close()
			s.origin = server.URL
			err := s.Negotiate(testContext)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"clone-content-v1", "namespace-mutations-v1", "stream-upload-v1"} {
					if s.Features()[name] {
						t.Fatal("default enabled", name)
					}
				}
			} else if !errors.Is(err, ErrRemoteUnqualified) {
				t.Fatal("bad qualification accepted", err)
			}
		})
	}
}

func TestStage3C06PolicyPagingReadOnlyAndPending(t *testing.T) {
	r, w, session, _ := stage3Daemon(t, 260)
	if report, err := r.RunCapturedScan(testContext, scanOptions(t, r, w, session)); err != nil || report.Uploaded != 260 {
		t.Fatal(report, err)
	}
	include := func(string) bool { return true }
	exclude := func(p string) bool { return !strings.Contains(p, "file-00") }
	hash := hashBytes([]byte("reviewed-policy"))
	before, _ := r.store.Root(testContext, "root")
	p, err := r.store.PreviewPolicy(testContext, "root", "portable_v1", hash, include, exclude)
	if err != nil || p.Entries <= 250 || !p.CopiesRetained || p.NewlyExcluded == 0 {
		t.Fatal(p, err)
	}
	after, _ := r.store.Root(testContext, "root")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("preview mutated root")
	}
	repeat, err := r.store.PreviewPolicy(testContext, "root", "portable_v1", hash, include, exclude)
	if err != nil || repeat.Digest != p.Digest {
		t.Fatal("unstable plan", err)
	}
	if err = r.store.ApplyPolicy(testContext, "root", "portable_v1", hash, 1, []byte(`{"revision":1}`)); err != nil {
		t.Fatal(err)
	}
	if err = r.store.ApplyPolicy(testContext, "root", "portable_v1", hash, 1, []byte(`{"revision":1}`)); err != nil {
		t.Fatal("idempotence", err)
	}
	if err = r.store.ApplyPolicy(testContext, "root", "portable_v1", hashBytes([]byte("different")), 1, []byte(`{}`)); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("same revision drift", err)
	}
}

func TestStage3C07SixOriginalsV8Batch(t *testing.T) {
	d, f, p, _ := dispatchFixture(t, 6)
	if err := d.session.r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	if err := d.dispatch(testContext, p); err != nil {
		t.Fatal(err)
	}
	assertDispatchedOriginals(t, d, p, false)
	if f.calls["data"] != 1 {
		t.Fatal(f.calls)
	}
	if err := d.dispatch(testContext, p); err != nil {
		t.Fatal(err)
	}
	if f.calls["data"] != 1 {
		t.Fatal("resent ACKed members")
	}
}
func TestStage3C07OriginalRestartFaults(t *testing.T) {
	TestSmallBatchDispatchLostPrepareAndDataRestartSubset(t)
}

func TestStage3C07OrdinaryModesAndRecovery(t *testing.T) {
	for _, mode := range []string{"", "bulk"} {
		t.Run("mode-"+mode, func(t *testing.T) {
			r, w, f, _ := engineFixture(t, []int{0, 1, 7, 1024, 262144, 262145}, true)
			if err := r.EnableDaemonState(testContext); err != nil {
				t.Fatal(err)
			}
			report, err := runEngineFixture(t, testContext, r, w, f, mode)
			if err != nil || report.Uploaded != 6 || !report.Complete {
				t.Fatal(report, err)
			}
			f.mu.Lock()
			data := f.calls["data"]
			f.mu.Unlock()
			if (data > 0) != (mode == "bulk") {
				t.Fatal("default-off/batch caller", data, mode)
			}
			report, err = runEngineFixture(t, testContext, r, w, f, mode)
			if err != nil || report.Adopted != 6 || report.Uploaded != 0 {
				t.Fatal(report, err)
			}
		})
	}
	t.Run("lost-data-new-owner", TestSmallBatchEngineLostDataNewOwnerRecoversOriginalsWithoutCapture)
	t.Run("disable-recover-originals", TestSmallBatchEngineDisabledModeRetiresAggregateAndRecoversIndividually)
	t.Run("cancel-join", TestSmallBatchEngineCancellationJoinsCaptureQueueAndAggregate)
}

func TestStage3C06PendingCollisionAndRestart(t *testing.T) {
	t.Run("pending-preserved", func(t *testing.T) {
		d, _, p, _ := dispatchFixture(t, 1)
		r := d.session.r
		if err := r.EnableDaemonState(testContext); err != nil {
			t.Fatal(err)
		}
		preview, err := r.store.PreviewPolicy(testContext, "root", "portable_v1", hashBytes([]byte("pending")), nil, nil)
		if err != nil || preview.PendingOriginals != 1 {
			t.Fatal(preview, err)
		}
		before, _ := r.store.Operation(testContext, p.entries[0].original.OperationID)
		if err = r.store.ApplyPolicy(testContext, "root", "portable_v1", hashBytes([]byte("pending")), 1, []byte(`{}`)); !errors.Is(err, ErrArtifactRetained) {
			t.Fatal(err)
		}
		after, _ := r.store.Operation(testContext, before.OperationID)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("incompatible original changed")
		}
	})
	t.Run("collision-readonly", func(t *testing.T) {
		r, _, _, _ := stage3Daemon(t, 0)
		capture(t, r.store, fileObservation("case-A", "Name"))
		capture(t, r.store, fileObservation("case-B", "name"))
		before, _ := r.store.Root(testContext, "root")
		p, err := r.store.PreviewPolicy(testContext, "root", "portable_v1", hashBytes([]byte("collision")), nil, nil)
		if err != nil || p.Collisions != 2 {
			t.Fatal(p, err)
		}
		after, _ := r.store.Root(testContext, "root")
		if !reflect.DeepEqual(before, after) {
			t.Fatal("preview changed state")
		}
	})
}

func TestStage3C09ConflictingAcknowledgementsUnknownQuota(t *testing.T) {
	for _, fault := range []string{"chunk", "final", "unknown", "quota"} {
		t.Run(fault, func(t *testing.T) {
			r, w, s, f, dir := stage3Wire(t, 1)
			s.features["stream-upload-v1"] = true
			s.features["metadata-gzip-v1"] = true
			f.streamFault = fault
			if err := os.WriteFile(filepath.Join(dir, "file-000"), bytes.Repeat([]byte{17}, (8<<20)+1), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := stage3HTTPScan(t, r, w, s)
			if err == nil || report.Uploaded != 0 {
				t.Fatal("unproven publication", report, err)
			}
			pending, err := r.store.PendingPage(testContext, "root", "", 128)
			if err != nil || len(pending) != 1 || pending[0].Stream == nil || pending[0].Stage != "SUBMITTED" {
				t.Fatal("original not retained", pending, err)
			}
			id, hash := pending[0].OperationID, pending[0].IntentFingerprint
			if fault == "unknown" || fault == "quota" {
				f.mu.Lock()
				f.streamFault = ""
				if status, ok := f.streams[id]; ok {
					status.State = "RECEIVING"
					f.streams[id] = status
				}
				f.mu.Unlock()
				r.store.db.Exec("UPDATE operation_retry SET next_ms=0")
				recovered, recoveryErr := r.RecoverOriginals(testContext, CapturedScanOptions{Witness: w, RootID: "root", Session: s, AcquireStream: artifactTestReader})
				if recoveryErr != nil || recovered != 1 {
					t.Fatal("recover retained original", recovered, recoveryErr)
				}
				op, e := r.store.Operation(testContext, id)
				if e != nil || op.IntentFingerprint != hash || op.Stage != "CLIENT_ACKED" {
					t.Fatal(op, e)
				}
			}
		})
	}
}

func TestStage3C04WaitEventCancellationAndFallback(t *testing.T) {
	r, witness, s, f, source := stage3Wire(t, 0)
	s.features["changes-wait-v1"] = true
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var localMu sync.Mutex
	held := false
	server := httptest.NewServer(http.HandlerFunc(func(out http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/changes") {
			raw, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(raw))
			var body map[string]any
			json.Unmarshal(raw, &body)
			if body["wait_ms"] != float64(25000) {
				t.Error("unbounded/missing wait", body["wait_ms"])
			}
			entered <- struct{}{}
			localMu.Lock()
			block := held
			localMu.Unlock()
			if block {
				select {
				case <-req.Context().Done():
					return
				case <-release:
				}
			}
		}
		f.base.ServeHTTP(out, req)
	}))
	defer server.Close()
	oldOrigin := s.origin
	s.origin = server.URL
	defer func() { s.origin = oldOrigin }()
	f.base.mu.Lock()
	f.base.emit(folderRemote(remoteVersion(9900), f.base.binding.RootID, "event"), "event-op")
	f.base.mu.Unlock()
	if err := s.WaitChanges(testContext); err != nil {
		t.Fatal(err)
	}
	<-entered
	before, err := r.Candidate(testContext, "root")
	if err != nil || before.Position < 1 {
		t.Fatal(before, err)
	}
	localMu.Lock()
	held = true
	localMu.Unlock()
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() { done <- s.WaitChanges(ctx) }()
	<-entered
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	after, _ := r.Candidate(testContext, "root")
	if after.Cursor != before.Cursor || after.Position != before.Position {
		t.Fatal("cancel advanced cursor")
	}
	observer, e := NewLinuxObserver(testContext, r.sources, witness)
	if e != nil {
		t.Fatal(e)
	}
	binding, e := r.sources.Binding(testContext, witness.SetID, "source")
	if e != nil {
		t.Fatal(e)
	}
	if e = observer.Watch(testContext, "source", source, binding.Destination); e != nil {
		t.Fatal(e)
	}
	local, stop := context.WithCancel(testContext)
	go func() { done <- s.WaitChanges(local) }()
	<-entered
	if e = os.WriteFile(filepath.Join(source, "local-wake"), []byte{1}, 0600); e != nil {
		t.Fatal(e)
	}
	select {
	case <-observer.Wake():
	case <-time.After(5 * time.Second):
		t.Fatal("local hint did not wake poll")
	}
	stop()
	if e = <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e = observer.Close(); e != nil {
		t.Fatal(e)
	}
	close(release)
	s.origin = oldOrigin
	s.features["changes-wait-v1"] = false
	if err = s.WaitChanges(testContext); err != nil {
		t.Fatal("polling fallback", err)
	}
	filename := filepath.Dir(r.store.filename)
	if err = r.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(testContext, filename)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var cursor string
	if err = store.db.QueryRow("SELECT json_extract(descriptor_json,'$.Cursor') FROM remote_candidate_roots WHERE root_id='root'").Scan(&cursor); err != nil || cursor != after.Cursor {
		t.Fatal("durable feed cursor", cursor, err)
	}
}

func TestStage3C04FeedGapRestartAndParentCache(t *testing.T) {
	t.Run("gap-original", TestHTTPRebootstrapExpiredAndGapRetainOriginalAndRecover)
	t.Run("page-crash", TestHTTPRebootstrapCommitAndPageFaultsReuseUUIDAfterRealRestart)
	t.Run("cache", func(t *testing.T) {
		r, _, s, f, _ := stage3Wire(t, 0)
		c, err := r.Candidate(testContext, "root")
		if err != nil {
			t.Fatal(err)
		}
		parent := s.binding.RootID
		for _, name := range []string{"changed", "unrelated"} {
			if err = r.store.transaction(testContext, func(tx *sql.Tx) error {
				return rememberParent(testContext, tx, c.RemoteWitness, "legacy", parent, name, nil)
			}); err != nil {
				t.Fatal(err)
			}
		}
		f.base.mu.Lock()
		f.base.emit(folderRemote(remoteVersion(9901), parent, "changed"), "cache-event")
		f.base.mu.Unlock()
		if err = s.Refresh(testContext); err != nil {
			t.Fatal(err)
		}
		c, _ = r.Candidate(testContext, "root")
		if err = r.store.transaction(testContext, func(tx *sql.Tx) error {
			if _, hit, e := cachedParent(testContext, tx, c.RemoteWitness, "legacy", parent, "changed"); e != nil || hit {
				return fmt.Errorf("negative cache not invalidated: %v", e)
			}
			if entry, hit, e := cachedParent(testContext, tx, c.RemoteWitness, "legacy", parent, "unrelated"); e != nil || !hit || entry != nil {
				return fmt.Errorf("unrelated negative discarded: %v", e)
			}
			entry, e := readJSON[RemoteEntry](testContext, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", "root", c.Generation, remoteVersion(9901))
			if e != nil {
				return e
			}
			return rememberParent(testContext, tx, c.RemoteWitness, "legacy", parent, "changed", &entry)
		}); err != nil {
			t.Fatal(err)
		}
		f.base.mu.Lock()
		updated := folderRemote(remoteVersion(9901), parent, "renamed")
		updated.Version = remoteVersion(9902)
		f.base.emit(updated, "cache-rename")
		f.base.mu.Unlock()
		if err = s.Refresh(testContext); err != nil {
			t.Fatal(err)
		}
		c, _ = r.Candidate(testContext, "root")
		if err = r.store.transaction(testContext, func(tx *sql.Tx) error {
			if _, hit, e := cachedParent(testContext, tx, c.RemoteWitness, "legacy", parent, "changed"); e != nil || hit {
				return fmt.Errorf("positive stale cache: %v", e)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStage3C04ConcurrentSameParentOriginal(t *testing.T) {
	r, w, s, f, _ := stage3Wire(t, 1)
	s.features["folder-batch-v1"] = true
	if report, err := stage3HTTPScan(t, r, w, s); err != nil || report.Uploaded != 1 {
		t.Fatal(report, err)
	}
	var id string
	if err := r.store.db.QueryRow("SELECT operation_id FROM operations WHERE kind='ENSURE_DIRECTORY' ORDER BY operation_id LIMIT 1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	op, err := r.store.Operation(testContext, id)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	before := len(f.folderBatches)
	f.mu.Unlock()
	start := make(chan struct{})
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			<-start
			raw, e := s.sendFolder(testContext, op)
			if e == nil {
				_, e = readFolderHTTPReceipt(raw, op)
			}
			done <- e
		}()
	}
	close(start)
	for i := 0; i < 16; i++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.folderBatches) != before+1 {
		t.Fatal("same original was not singleflight", len(f.folderBatches)-before)
	}
}

func TestStage3C04Parents501ThreeLevels(t *testing.T) {
	started := time.Now()
	r, w, s, f, dir := stage3Wire(t, 0)
	s.features["folder-batch-v1"] = true
	for i := 0; i < 501; i++ {
		leaf := filepath.Join(dir, fmt.Sprintf("parent-%03d", i), "child", "leaf")
		if err := os.MkdirAll(leaf, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(leaf, "file"), []byte{1}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("parents501 setup complete after %s", time.Since(started))
	initialStarted := time.Now()
	report, err := stage3HTTPScan(t, r, w, s)
	t.Logf("parents501 initial scan complete after %s", time.Since(initialStarted))
	if err != nil || !report.Complete {
		t.Fatal(report, err)
	}
	f.mu.Lock()
	batches := append([]int(nil), f.folderBatches...)
	f.mu.Unlock()
	if len(batches) == 0 {
		t.Fatal("batch transport unused")
	}
	f.base.mu.Lock()
	folders := len(f.base.folders)
	f.base.mu.Unlock()
	if folders < 501*3 {
		t.Fatal("topology missing", folders)
	}
	for _, count := range batches {
		if count < 1 || count > 500 {
			t.Fatal("batch bound", count)
		}
	}
	repeatStarted := time.Now()
	t.Logf("parents501 repeat scan starting after %s total", time.Since(started))
	report, err = stage3HTTPScan(t, r, w, s)
	t.Logf("parents501 repeat scan complete after %s", time.Since(repeatStarted))
	if err != nil || !report.Complete {
		t.Fatal("repeat", report, err)
	}
	f.base.mu.Lock()
	defer f.base.mu.Unlock()
	if len(f.base.folders) != folders {
		t.Fatal("duplicate parent original")
	}
}
func TestStage3C07PartialIndividualResume(t *testing.T) {
	TestSmallBatchDispatchAcceptedOriginalContinuesBeforeMissingSubset(t)
}
func TestStage3C07LateAckGeneration(t *testing.T) {
	TestSmallBatchDispatchAckCrashAndNewSourceGeneration(t)
}

func TestStage3C10LimitsFairnessCancellation(t *testing.T) {
	b := &transportBudget{target: 2, finishes: map[string]float64{}, paceSlot: make(chan struct{}, 1)}
	a, err := b.acquire(testContext, true, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	c, err := b.acquire(testContext, true, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer c()
	ctx, cancel := context.WithCancel(testContext)
	done := make(chan error, 1)
	go func() {
		release, err := b.acquire(ctx, true, 4096)
		if release != nil {
			release()
		}
		done <- err
	}()
	stage3Wait(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.queue) == 1 })
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("queued cancellation")
	}
	a()
	c()
	var wg sync.WaitGroup
	for _, class := range []string{"live", "recovery", "bootstrap"} {
		wg.Add(1)
		go func(class string) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				release, err := b.acquire(WithWorkClass(testContext, class), i%2 == 0, int64(4096*(i+1)))
				if err != nil {
					t.Error(err)
					return
				}
				release()
			}
		}(class)
	}
	wg.Wait()
	if b.data != 0 || b.metadata != 0 || len(b.queue) != 0 {
		t.Fatal("resource leak", b)
	}
	cancelled, stop := context.WithCancel(testContext)
	stop()
	if !errors.Is(b.pace(cancelled, MaxFileBytes, 1), context.Canceled) {
		t.Fatal("uncancellable pacing")
	}
	if len(b.paceSlot) != 0 {
		t.Fatal("pacing slot leak")
	}
	if err = b.pace(testContext, 1, 1<<41); !errors.Is(err, ErrSourceQuota) {
		t.Fatal("user cap", err)
	}
}
func TestStage3C10DurableRetryDegraded(t *testing.T) {
	d, _, p, _ := dispatchFixture(t, 1)
	s := d.session.r.store
	if err := d.session.r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	id := p.entries[0].original.OperationID
	var last *RetryWait
	for i := 1; i <= 8; i++ {
		err := s.RecordRetry(testContext, id, io.ErrUnexpectedEOF)
		if !errors.As(err, &last) {
			t.Fatal(err)
		}
	}
	if last.State != "DEGRADED" || time.Until(last.Until) < 14*time.Minute {
		t.Fatal(last)
	}
	if err := s.RetryReady(testContext, id); err == nil {
		t.Fatal("durable deadline ignored")
	}
	directory := filepath.Dir(s.filename)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var resumed *RetryWait
	if err = s.RetryReady(testContext, id); !errors.As(err, &resumed) || resumed.State != "DEGRADED" || resumed.Until.UnixMilli() != last.Until.UnixMilli() {
		t.Fatal("retry reset on reopen", resumed, err)
	}
	if _, err := s.db.Exec("UPDATE operation_retry SET next_ms=? WHERE operation_id=?", time.Now().Add(-time.Second).UnixMilli(), id); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryReady(testContext, id); err != nil {
		t.Fatal("controlled deadline", err)
	}
	op, err := s.Operation(testContext, id)
	if err != nil || op.IntentFingerprint != p.entries[0].original.IntentFingerprint {
		t.Fatal("retry rewrote original", err)
	}
}

func TestStage3C10ProcessRootsPublicationCooldownAndAging(t *testing.T) {
	old := transportResources
	b := &transportBudget{target: 1, finishes: map[string]float64{}, paceSlot: make(chan struct{}, 1)}
	transportResources = b
	defer func() { transportResources = old }()
	// Two independent sessions share exactly this pool; receipt/received bytes
	// alone never call the publication controller.
	_, _, a, _, _ := stage3Wire(t, 0)
	_, _, c, _, _ := stage3Wire(t, 0)
	a.data.Store(256 << 20)
	c.data.Store(256 << 20)
	if m := TransportMetrics(); m.TargetData != 1 || m.PublishedBytes != 0 || m.PublishedOperations != 0 {
		t.Fatal("received adapted controller", m)
	}
	for i := 0; i < 8; i++ {
		RecordPublication(1<<20, time.Second)
	}
	if m := TransportMetrics(); m.TargetData != 2 || m.PublishedOperations != 8 {
		t.Fatal(m)
	}
	b.failed(io.ErrUnexpectedEOF)
	for i := 0; i < 16; i++ {
		RecordPublication(1<<20, time.Second)
	}
	if m := TransportMetrics(); m.TargetData != 1 || m.CooldownUntil == "" {
		t.Fatal("cooldown ignored", m)
	}
	// Deterministic age barrier, without sleeping for the production 5 s clock.
	b.mu.Lock()
	b.data = 1
	b.queue = []*transportTicket{
		{data: true, class: "live", finish: 1, queued: time.Now(), ready: make(chan struct{})},
		{data: true, class: "bootstrap", finish: 1 << 30, queued: time.Now().Add(-6 * time.Second), ready: make(chan struct{})},
	}
	aged := b.queue[1]
	b.data = 0
	b.dispatch()
	b.mu.Unlock()
	select {
	case <-aged.ready:
	default:
		t.Fatal("large old bootstrap starved")
	}
	b.mu.Lock()
	b.data = 0
	b.dispatch()
	b.data = 0
	b.mu.Unlock()
	if m := TransportMetrics(); m.Queued != 0 || m.ActiveData != 0 {
		t.Fatal("shared pool leak", m)
	}
}

func TestStage3C10TwoRootsShareHTTPAdmission(t *testing.T) {
	old := transportResources
	b := &transportBudget{target: 1, finishes: map[string]float64{}, paceSlot: make(chan struct{}, 1)}
	transportResources = b
	defer func() { transportResources = old }()
	ra, wa, a, _ := engineFixture(t, []int{1, 1024, 262144}, true)
	rb, wb, c, _ := engineFixture(t, []int{7, 1024, 262144}, true)
	a.hold, a.entered, a.completed = make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(a.hold) }) }
	ctx, cancel := context.WithCancel(testContext)
	var workers sync.WaitGroup
	defer func() { cancel(); release(); workers.Wait() }()
	type result struct {
		report CapturedScanReport
		err    error
	}
	results := make(chan result, 2)
	launch := func(r *RemoteImport, w SourceWitness, f *dispatchHTTPFixture, class string) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			report, err := runEngineFixture(t, WithWorkClass(ctx, class), r, w, f, "bulk")
			results <- result{report, err}
		}()
	}
	launch(ra, wa, a, "live")
	select {
	case <-a.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("first HTTP data barrier")
	}
	launch(rb, wb, c, "bootstrap")
	stage3Wait(t, func() bool { return TransportMetrics().Queued > 0 })
	if m := TransportMetrics(); m.ActiveData != 1 || m.TargetData != 1 || m.PublishedOperations != 0 {
		t.Fatal("roots multiplied pool or received counted as published", m)
	}
	release()
	for i := 0; i < 2; i++ {
		select {
		case v := <-results:
			if v.err != nil || !v.report.Complete || v.report.Uploaded != 3 {
				t.Fatal(v.report, v.err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("second root did not progress")
		}
	}
	workers.Wait()
	if m := TransportMetrics(); m.ActiveData != 0 || m.ActiveMetadata != 0 || m.Queued != 0 {
		t.Fatal("HTTP admission leaked", m)
	}
}

func TestStage3C04SnapshotBindingTransitionRequiresReview(t *testing.T) {
	r, _, s, _, _ := stage3Wire(t, 0)
	if err := r.EnableDaemonState(testContext); err != nil {
		t.Fatal(err)
	}
	old, err := r.pendingHTTPSnapshot(s.binding)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(filepath.Dir(r.store.filename), "http-snapshot-"+hashBytes([]byte(s.binding.RootID))+".json")
	before, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	next := s.binding
	next.ServerEpoch = "00000000-0000-4000-8000-000000009991"
	next.BindingVersion = "00000000-0000-4000-8000-000000009992"
	scoped := filepath.Join(filepath.Dir(r.store.filename), "http-snapshot-binding-"+fingerprint(next)+".json")
	if _, err = r.pendingHTTPSnapshot(next); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("unreviewed binding accepted", err)
	}
	if _, err = os.Lstat(scoped); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal created journal", err)
	}
	if err = r.store.AuthorizeBindingTransition(testContext, "root", s.binding, next); err != nil {
		t.Fatal(err)
	}
	id, err := r.pendingHTTPSnapshot(next)
	if err != nil || id == old {
		t.Fatal("reviewed binding lacks distinct original", id, err)
	}
	again, err := r.pendingHTTPSnapshot(next)
	if err != nil || again != id {
		t.Fatal("snapshot original changed", again, err)
	}
	after, err := os.ReadFile(legacy)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("old snapshot journal changed", err)
	}
}

func TestStage3C11GzipBoundariesAndMalformed(t *testing.T) {
	for _, size := range []int{16384, 16385} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-%v", size, enabled), func(t *testing.T) {
				_, _, _, s, _, _ := actualHTTPFixture(t, 0)
				s.features = map[string]bool{"metadata-gzip-v1": enabled}
				raw := []byte(`{"v":"` + strings.Repeat("x", size-8) + `"}`)
				if len(raw) != size {
					t.Fatal(len(raw))
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					compressed := r.Header.Get("Content-Encoding") == "gzip"
					if compressed != (enabled && size > 16384) {
						t.Error("threshold", compressed)
					}
					got, err := readMetadataResponse(r.Body, r.Header.Get("Content-Encoding"), 4<<20, true)
					if err != nil || !bytes.Equal(got, raw) {
						t.Error("canonical payload changed", err)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{}`))
				}))
				defer server.Close()
				s.origin = server.URL
				if _, err := s.request(testContext, "POST", "probe", "application/json", raw, len(raw)); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	z.Write(bytes.Repeat([]byte("x"), 1025))
	z.Close()
	compressed := buf.Bytes()
	if _, err := readMetadataResponse(bytes.NewReader(compressed), "gzip", 1024, true); !errors.Is(err, syncproto.ErrLimit) {
		t.Fatal("expanded overflow", err)
	}
	for _, bad := range [][]byte{[]byte("broken"), compressed[:len(compressed)-4]} {
		if _, err := readMetadataResponse(bytes.NewReader(bad), "gzip", 4096, true); err == nil {
			t.Fatal("malformed accepted")
		}
	}
	if _, err := readMetadataResponse(bytes.NewReader(compressed), "gzip", 4096, false); err == nil {
		t.Fatal("unnegotiated gzip")
	}
}

// Parent preparation keeps fully proved no-ops free of auxiliary cache writes.

func profileParentCacheFixture(t *testing.T) (*RemoteImport, SourceWitness, *IsolatedHTTPSession, *stage3WireFixture, string) {
	t.Helper()
	r, w, s, f, dir := stage3Wire(t, 0)
	leaf := filepath.Join(dir, "cache-parent", "child", "leaf")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "file"), []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	if report, err := stage3HTTPScan(t, r, w, s); err != nil || !report.Complete || report.Uploaded != 1 {
		t.Fatal("initial parent originals", report, err)
	}
	var entry string
	if err := r.store.db.QueryRow("SELECT entry_id FROM local_entries WHERE root_id='root' AND json_extract(descriptor_json,'$.Name')='leaf' AND json_extract(descriptor_json,'$.Kind')='folder'").Scan(&entry); err != nil {
		t.Fatal(err)
	}
	var base string
	if err := r.store.db.QueryRow("SELECT descriptor_json FROM baselines WHERE root_id='root' AND entry_id=?", entry).Scan(&base); err != nil || base == "" {
		t.Fatal("real folder B prerequisite", err)
	}
	return r, w, s, f, entry
}

func profileParentCacheState(t *testing.T, r *RemoteImport) map[string]string {
	t.Helper()
	queries := map[string]string{
		"cache":     "SELECT * FROM parent_cache ORDER BY root_id,binding_key,destination",
		"baselines": "SELECT * FROM baselines ORDER BY root_id,entry_id",
		"originals": "SELECT * FROM operations ORDER BY operation_id",
	}
	result := map[string]string{}
	for name, query := range queries {
		rows, err := r.store.db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		var records []json.RawMessage
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			raw, e := json.Marshal(values)
			if e != nil {
				rows.Close()
				t.Fatal(e)
			}
			records = append(records, raw)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(records)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = string(raw)
	}
	return result
}

func profileForbidParentCacheWrites(t *testing.T, r *RemoteImport) {
	t.Helper()
	for _, event := range []string{"INSERT", "UPDATE", "DELETE"} {
		// The owned private SQLite fixture, not the product, installs guards.
		// INSERT trigger fires before UPSERT, even when its conflict updates.
		query := "CREATE TRIGGER profile_cache_forbid_" + strings.ToLower(event) + " BEFORE " + event + " ON parent_cache BEGIN SELECT RAISE(ABORT,'profile-parent-cache-write-forbidden'); END"
		if _, err := r.store.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreparedExistingParentDoesNotWriteAuxiliaryCache(t *testing.T) {
	for _, mode := range []string{"warm", "expired"} {
		t.Run(mode, func(t *testing.T) {
			r, w, s, f, entry := profileParentCacheFixture(t)
			// Seed one exact positive hint from this fixture's current R.
			// Feed invalidation during initial publication may leave no hint.
			var key, destination string
			if err := r.store.transaction(testContext, func(tx *sql.Tx) error {
				c, err := readCandidate(testContext, tx, "root")
				if err != nil {
					return err
				}
				base, err := readJSON[Baseline](testContext, tx, "SELECT descriptor_json FROM baselines WHERE root_id='root' AND entry_id=?", entry)
				if err != nil {
					return err
				}
				remote, err := readJSON[RemoteEntry](testContext, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id='root' AND generation=? AND node_id=?", c.Generation, base.NodeID)
				if err != nil {
					return err
				}
				root, err := readRoot(testContext, tx, "root")
				if err != nil {
					return err
				}
				if !c.Valid || !currentRemoteBinding(remote, c.RemoteWitness) || remote.Kind != "folder" || remote.Presence != "PRESENT" || remote.Availability != "AVAILABLE" {
					return ErrRemoteUnqualified
				}
				key = parentCacheKey(c.RemoteWitness, root.NameCodec)
				destination = remote.ParentID + "/" + remote.Name
				return rememberParent(testContext, tx, c.RemoteWitness, root.NameCodec, remote.ParentID, remote.Name, &remote)
			}); err != nil {
				t.Fatal("current-R positive hint prerequisite", err)
			}
			if mode == "expired" {
				// Expire only the selected own-fixture hint BEFORE snapshot
				// and write guards. Current R/B remain intact for fallback.
				result, err := r.store.db.Exec("UPDATE parent_cache SET expires_ms=0 WHERE root_id='root' AND binding_key=? AND destination=?", key, destination)
				if err != nil {
					t.Fatal(err)
				}
				count, err := result.RowsAffected()
				if err != nil || count != 1 {
					t.Fatal("exact own hint not expired", count, err)
				}
			}
			before := profileParentCacheState(t, r)
			f.base.mu.Lock()
			folders := len(f.base.folders)
			f.base.mu.Unlock()
			profileForbidParentCacheWrites(t, r)
			// Folder target exercises the complete current-R/B/owner chain.
			if err := s.PrepareParents(testContext, w, "root", entry); err != nil {
				t.Fatal("fully proved no-op parent attempted cache mutation", err)
			}
			if after := profileParentCacheState(t, r); !reflect.DeepEqual(before, after) {
				t.Fatal("no-op changed cache, B, or immutable originals", before, after)
			}
			f.base.mu.Lock()
			defer f.base.mu.Unlock()
			if len(f.base.folders) != folders {
				t.Fatal("no-op created another remote folder")
			}
		})
	}
}

func TestPreparedNewParentBaselineStillPropagatesCacheWriteFailure(t *testing.T) {
	r, w, s, _, entry := profileParentCacheFixture(t)
	// Fixture-only removal forces real new-B adoption of the same current R.
	// Product code never deletes an existing B to evade an original.
	if _, err := r.store.db.Exec("DELETE FROM baselines WHERE root_id='root' AND entry_id=?", entry); err != nil {
		t.Fatal(err)
	}
	before := profileParentCacheState(t, r)
	profileForbidParentCacheWrites(t, r)
	err := s.PrepareParents(testContext, w, "root", entry)
	if err == nil || !strings.Contains(err.Error(), "profile-parent-cache-write-forbidden") {
		t.Fatal("new B bypassed retained cache write/error path", err)
	}
	if after := profileParentCacheState(t, r); !reflect.DeepEqual(before, after) {
		t.Fatal("refused adoption changed cache/B/originals", before, after)
	}
}

func TestPreparedExistingParentStillRequiresCurrentSourceOwner(t *testing.T) {
	r, w, s, _, entry := profileParentCacheFixture(t)
	before := profileParentCacheState(t, r)
	profileForbidParentCacheWrites(t, r)
	w.OwnerSequence++
	if err := s.PrepareParents(testContext, w, "root", entry); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("matching B authorized a stale source owner", err)
	}
	if after := profileParentCacheState(t, r); !reflect.DeepEqual(before, after) {
		t.Fatal("stale owner changed cache/B/originals", before, after)
	}
}
