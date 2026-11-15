package syncstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pluto/internal/syncproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureAttempts struct{ db *sql.DB }

func newFixtureAttempts(t *testing.T) *fixtureAttempts {
	t.Helper()
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "attempts.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("PRAGMA cache_size=-2048; PRAGMA max_page_count=262144; CREATE TABLE attempts(path TEXT PRIMARY KEY)"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return &fixtureAttempts{db}
}
func (a *fixtureAttempts) ClaimAttempt(ctx context.Context, path string) (bool, error) {
	r, e := a.db.ExecContext(ctx, "INSERT OR IGNORE INTO attempts(path) VALUES(?)", path)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}

type fixtureCapturedSession struct {
	r                             *RemoteImport
	mu                            sync.Mutex
	results                       map[string]CapturedPublication
	active, maxActive             atomic.Int64
	writes, recoveries, hashBytes atomic.Int64
	lostAck                       atomic.Bool
	published                     chan struct{}
	once                          sync.Once
}

func (s *fixtureCapturedSession) Authority(ctx context.Context) (*RemoteAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, e := readCandidate(ctx, s.r.store.db, "root")
	if e != nil {
		return nil, e
	}
	return fixtureRemoteAuthority(c), nil
}
func (s *fixtureCapturedSession) Publish(ctx context.Context, op Operation, reader io.Reader) (pub CapturedPublication, err error) {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		old := s.maxActive.Load()
		if active <= old || s.maxActive.CompareAndSwap(old, active) {
			break
		}
	}
	stored, e := s.r.store.Operation(ctx, op.OperationID)
	if e != nil || stored.Stage != "SUBMITTED" || stored.SealedFingerprint != op.SealedFingerprint {
		return pub, ErrInvalidReceipt
	}
	hash := newHashFixtureReader(reader)
	s.hashBytes.Add(hash.n)
	if hash.err != nil {
		return pub, hash.err
	}
	if hash.digest != op.SHA256 || hash.n != op.SizeBytes {
		return pub, ErrInvalidReceipt
	}
	select {
	case <-time.After(15 * time.Millisecond):
	case <-ctx.Done():
		return pub, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, e := readCandidate(ctx, s.r.store.db, "root")
	if e != nil {
		return pub, e
	}
	parent := c.Binding.RootID
	if len(op.Captured.Parents) > 0 {
		parent = op.Captured.Parents[len(op.Captured.Parents)-1].Remote.NodeID
	}
	tx, e := s.r.store.db.BeginTx(ctx, nil)
	if e != nil {
		return pub, e
	}
	existing, e := namespaceCandidate(ctx, tx, c.RemoteWitness, parent, op.Name)
	tx.Rollback()
	if e != nil {
		return pub, e
	}
	if op.ExpectedAbsent && existing != nil || !op.ExpectedAbsent && (existing == nil || existing.NodeID != op.ExpectedNodeID || existing.Version != op.ExpectedVersion || existing.ContentVersionID != op.Captured.ExpectedContentVersionID) {
		return pub, ErrIdentityConflict
	}
	seq := c.Position + 1
	node := fmt.Sprintf("published-%06d", seq)
	if existing != nil {
		node = existing.NodeID
	}
	d := fileRemote(node, parent, op.Name, "")
	sha := op.SHA256
	content := remoteVersion(int(seq) + 300)
	d.ContentSHA256 = &sha
	d.ContentVersionID = &content
	d.SizeBytes = remoteDecimal(op.SizeBytes)
	d.Version = remoteVersion(int(seq) + 200)
	_, e = s.r.ImportFeed(ctx, c.RemoteWitness, wireFeed(c.RemoteWitness, []syncproto.FeedItem{{Descriptor: d, Seq: remoteDecimal(seq), Kind: "upsert", OperationID: op.OperationID}}, "execution-feed-"+remoteDecimal(seq)))
	if e != nil {
		return pub, e
	}
	pub = publicationFixture(op)
	pub.Description = remoteFromDescriptor(op.RootID, c.Generation, seq, c.Binding, d, op.OperationID)
	pub.Receipt.NodeID = node
	pub.Receipt.Version = d.Version
	pub.Receipt.Seq = seq
	pub.FirstSeq = seq
	s.results[op.OperationID] = pub
	s.writes.Add(1)
	s.once.Do(func() { close(s.published) })
	if s.lostAck.CompareAndSwap(true, false) {
		return pub, io.ErrUnexpectedEOF
	}
	return pub, nil
}

type fixtureHashResult struct {
	digest string
	n      int64
	err    error
}

func newHashFixtureReader(r io.Reader) fixtureHashResult {
	b, e := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	return fixtureHashResult{hashBytes(b), int64(len(b)), e}
}
func (s *fixtureCapturedSession) Recover(ctx context.Context, op Operation) (*CapturedPublication, error) {
	s.recoveries.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.results[op.OperationID]
	if !ok {
		return nil, nil
	}
	return &p, nil
}

func scanExecutorFixture(t *testing.T, files int) (*RemoteImport, SourceWitness, *fixtureCapturedSession, string) {
	t.Helper()
	dir := t.TempDir()
	for i := 0; i < files; i++ {
		if e := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%04d", i)), []byte("one"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	s, w, binding := sourceFixture(t, dir)
	root := testBinding
	root.SourceIdentity = w.SetID
	if e := s.store.BindRoot(testContext, root); e != nil {
		t.Fatal(e)
	}
	if e := s.AttachSourceSet(testContext, w.SetID, w.Revision, "root"); e != nil {
		t.Fatal(e)
	}
	a, e := s.store.EnableArtifacts(testContext, DefaultArtifactLimits())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Reconcile(testContext, artifactTestReader); e != nil {
		t.Fatal(e)
	}
	r, e := s.store.EnableRemoteImport(testContext)
	if e != nil {
		t.Fatal(e)
	}
	descriptors := []syncproto.Descriptor{folderRemote("remote-root", "", "root")}
	parent := "remote-root"
	for i, name := range strings.Split(binding.Destination, "/") {
		id := fmt.Sprintf("ancestor-%04d", i)
		descriptors = append(descriptors, folderRemote(id, parent, name))
		parent = id
	}
	publishRemote(t, r, descriptors)
	return r, w, &fixtureCapturedSession{r: r, results: make(map[string]CapturedPublication), published: make(chan struct{})}, dir
}
func scanOptions(t *testing.T, r *RemoteImport, w SourceWitness, s *fixtureCapturedSession) CapturedScanOptions {
	t.Helper()
	return CapturedScanOptions{Witness: w, RootID: "root", SourceIDs: []string{"source"}, Attempts: newFixtureAttempts(t), Session: s, Now: func() time.Time { return remoteNow }, Capture: func(ctx context.Context, w SourceWitness, e SourceEntry) (*VerifiedSnapshot, error) {
		if _, err := r.store.artifacts.PruneDisposed(ctx, MaxSourcePage); err != nil {
			return nil, err
		}
		return CaptureGuarded(ctx, w, e, r.store.artifacts.Directory(), &registryFixtureLimiter{a: r.store.artifacts, reader: newTestCaptureLimiter()})
	}}
}
func TestCapturedScanActualInitialFreshRepeatAndCoarseByteChange(t *testing.T) {
	r, w, s, dir := scanExecutorFixture(t, 6)
	o := scanOptions(t, r, w, s)
	first, e := r.RunCapturedScan(testContext, o)
	if e != nil || first.Uploaded != 6 || first.Verified != 6 || !first.Complete {
		t.Fatal(first, e)
	}
	if s.maxActive.Load() > 2 || s.maxActive.Load() < 1 {
		t.Fatal("transport bound", s.maxActive.Load())
	}
	second, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, s))
	if e != nil || second.Uploaded != 0 || second.Adopted != 6 || second.Verified != 6 {
		t.Fatal(second, e)
	}
	if s.writes.Load() != 6 || s.hashBytes.Load() != 18 {
		t.Fatal("repeat sent unchanged bytes", s.writes.Load(), s.hashBytes.Load())
	}
	file := filepath.Join(dir, "file-0000")
	info, e := os.Stat(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, []byte("two"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chtimes(file, info.ModTime(), info.ModTime()); e != nil {
		t.Fatal(e)
	}
	third, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, s))
	if e != nil || third.Uploaded != 1 || third.Adopted != 5 || third.Verified != 6 {
		t.Fatal(third, e)
	}
	if s.writes.Load() != 7 {
		t.Fatal("coarse metadata hid changed bytes")
	}
	root, _ := r.store.Root(testContext, "root")
	if root.EngineReady || root.AllowsDelete || root.MaxFileBytes != MaxFileBytes || root.MaxActiveVersions != 10 {
		t.Fatal(root)
	}
	t.Logf("actual own source: first=%+v repeat=%+v changed=%+v PUT=%d maxData=%d; local contents rehashed each cycle", first, second, third, s.writes.Load(), s.maxActive.Load())
}
func TestCapturedScanLostAckOriginalIDAndCancelJoin(t *testing.T) {
	r, w, s, _ := scanExecutorFixture(t, 1)
	s.lostAck.Store(true)
	first, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, s))
	if e == nil || first.Failed != 1 || s.writes.Load() != 1 {
		t.Fatal(first, e)
	}
	page, e := r.store.PendingPage(testContext, "root", "", MaxSourcePage)
	if e != nil || len(page) != 1 {
		t.Fatal(page, e)
	}
	original := page[0]
	second, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, s))
	if e != nil || second.Recovered != 1 || s.writes.Load() != 1 {
		t.Fatal(second, e)
	}
	stored, e := r.store.Operation(testContext, original.OperationID)
	if e != nil || stored.Stage != "CLIENT_ACKED" || stored.IntentFingerprint != original.IntentFingerprint {
		t.Fatal(stored, e)
	}
	charge, e := r.store.artifacts.Charge(testContext)
	if e != nil || charge != 0 {
		t.Fatal("retained leaked", charge, e)
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	report, e := r.RunCapturedScan(ctx, scanOptions(t, r, w, s))
	if !errors.Is(e, context.Canceled) || report.Complete || s.active.Load() != 0 {
		t.Fatal(report, e)
	}
}
func TestCapturedScanFirstPublicationBeforeWideDirectoryEOF(t *testing.T) {
	r, w, s, _ := scanExecutorFixture(t, 129)
	o := scanOptions(t, r, w, s)
	seen := false
	o.OnPage = func(c FrontierClaim) error {
		if c.Page >= 2 && !seen {
			select {
			case <-s.published:
				seen = true
			case <-time.After(10 * time.Second):
				return errors.New("first publish blocked until enumeration EOF")
			}
		}
		return nil
	}
	report, e := r.RunCapturedScan(testContext, o)
	if e != nil || report.Uploaded != 129 || !seen || !report.Complete {
		t.Fatal(report, e, seen)
	}
}
func TestCapturedScanSourceSetAdmissionHasNoSilentSubset(t *testing.T) {
	r, w, s, _ := scanExecutorFixture(t, 1)
	o := scanOptions(t, r, w, s)
	o.SourceIDs = []string{"missing"}
	report, e := r.RunCapturedScan(testContext, o)
	if !errors.Is(e, ErrIdentityConflict) || s.writes.Load() != 0 || report.Observed != 0 {
		t.Fatal(report, e)
	}
	o.SourceIDs = []string{"source", "source"}
	if _, e = r.RunCapturedScan(testContext, o); !errors.Is(e, ErrIdentityConflict) {
		t.Fatal(e)
	}
}
func TestCapturedScanActualRestartRetainedIdentityAndPrunedHistory(t *testing.T) {
	r, w, s, _ := scanExecutorFixture(t, 1)
	s.lostAck.Store(true)
	if _, e := r.RunCapturedScan(testContext, scanOptions(t, r, w, s)); e == nil {
		t.Fatal("lost ACK fixture not exercised")
	}
	pending, e := r.store.PendingPage(testContext, "root", "", 128)
	if e != nil || len(pending) != 1 {
		t.Fatal(pending, e)
	}
	original := pending[0]
	dir := filepath.Dir(r.store.filename)
	if e = r.store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(testContext, dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { reopened.Close() })
	sources, e := reopened.EnableSources(testContext, DefaultSourceLimits())
	if e != nil {
		t.Fatal(e)
	}
	a, e := reopened.EnableArtifacts(testContext, DefaultArtifactLimits())
	if e != nil {
		t.Fatal(e)
	}
	if report, e := a.Reconcile(testContext, artifactTestReader); e != nil || report.RecoveryOperations != 1 {
		t.Fatal(report, e)
	}
	r2, e := reopened.EnableRemoteImport(testContext)
	if e != nil {
		t.Fatal(e)
	}
	w2, e := sources.BeginSourceOwner(testContext, w.SetID, w.Revision, "owner-after-restart")
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := a.RecoveryOperation(testContext, original.SnapshotID)
	if e != nil || recovered.IntentFingerprint != original.IntentFingerprint || recovered.OperationID != original.OperationID {
		t.Fatal(recovered, e)
	}
	s2 := &fixtureCapturedSession{r: r2, results: s.results, published: make(chan struct{})}
	out, e := r2.ExecuteCaptured(testContext, w2, "root", original.EntryID, nil, s2, remoteNow)
	if e != nil || !out.Recovered || s2.writes.Load() != 0 {
		t.Fatal(out, e)
	}
	var before string
	if e = reopened.db.QueryRow("SELECT receipt_json FROM operations WHERE operation_id=?", original.OperationID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if n, e := a.PruneDisposed(testContext, 128); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	stored, e := reopened.Operation(testContext, original.OperationID)
	if e != nil || stored.Stage != "CLIENT_ACKED" || stored.IntentFingerprint != original.IntentFingerprint {
		t.Fatal(stored, e)
	}
	var after string
	reopened.db.QueryRow("SELECT receipt_json FROM operations WHERE operation_id=?", original.OperationID).Scan(&after)
	if before != after {
		t.Fatal("receipt history rewritten")
	}
	state, e := reopened.Entry(testContext, "root", original.EntryID)
	if e != nil || state.Base == nil || state.Dirty == nil {
		t.Fatal("restart gap cleared new verification", state, e)
	}
}
