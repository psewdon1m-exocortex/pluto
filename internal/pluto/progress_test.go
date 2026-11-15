package pluto

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgressKnownUnknownTotalsAndGrowth(t *testing.T) {
	start := time.Now()
	p := newRunProgress(start)
	for i := 0; i < 4; i++ {
		p.discover()
	}
	p.enumerationComplete()
	zero := p.snapshot(start.Add(time.Second), "", false, 0)
	if zero.ETASeconds != nil || zero.Percent != nil || zero.ETAState != "estimating" {
		t.Fatal("zero speed fabricated ETA", zero)
	}
	p.checkedFile(true)
	known := p.snapshot(start.Add(2*time.Second), "", false, 0)
	if known.ETASeconds == nil || *known.ETASeconds != 6 || known.Percent == nil || *known.Percent != 25 {
		t.Fatal("known total estimate", known)
	}
	for i := 0; i < 4; i++ {
		p.discover()
	}
	unknown := p.snapshot(start.Add(2500*time.Millisecond), "", false, 0)
	if unknown.ETASeconds != nil || unknown.TotalFiles != nil || unknown.RunID != known.RunID || unknown.ElapsedMS <= known.ElapsedMS {
		t.Fatal("growing discovery pretended total or reset clock", unknown)
	}
	p.enumerationComplete()
	grown := p.snapshot(start.Add(3*time.Second), "", false, 0)
	if grown.Percent == nil || *grown.Percent >= *known.Percent || grown.ETASeconds == nil || *grown.ETASeconds <= *known.ETASeconds {
		t.Fatal("growth did not revise estimate", grown)
	}
	for i := 1; i < 8; i++ {
		p.checkedFile(false)
	}
	finalizing := p.snapshot(start.Add(4*time.Second), "", false, 0)
	if finalizing.Percent != nil || finalizing.ETASeconds != nil || finalizing.ETAState != "finalizing" {
		t.Fatal("active finalization showed false100/zeroETA", finalizing)
	}
	p.finish(start.Add(5*time.Second), "completed")
	done := p.snapshot(start.Add(30*time.Second), "", false, 0)
	if done.ElapsedMS != 5000 || done.Percent == nil || *done.Percent != 100 || done.ETASeconds != nil {
		t.Fatal("completion clock/percentage", done)
	}
}

func TestProgressIndexedConfirmedCountsUseOnlyLiveSession(t *testing.T) {
	s := &Service{runProgress: newRunProgress(time.Now()), progressMetrics: func() int64 { return 16 }, progressPhase: "reconciling", Observation: Observation{Engine: &EngineObservation{Captured: 3, Published: 2}}}
	got := s.Status().Progress
	if got.CheckedFiles != 3 || got.PublishedFiles != 2 || got.TotalFiles != nil || got.ETASeconds != nil {
		t.Fatal("local status failed to reuse existing confirmed indexed counters", got)
	}
	s.progressMetrics = nil
	s.progressPhase = ""
	s.runProgress = newRunProgress(time.Now())
	fresh := s.Status().Progress
	if fresh.CheckedFiles != 0 || fresh.PublishedFiles != 0 {
		t.Fatal("new run borrowed historical engine counters", fresh)
	}
}

func TestProgressNoRecentCounterDoesNotDiagnoseTransportStall(t *testing.T) {
	start := time.Now()
	p := newRunProgress(start)
	p.requestData(4 << 20)
	got := p.snapshot(start.Add(6*time.Second), "", false, 4<<20)
	if got.State != "waiting_progress" || got.ETASeconds != nil {
		t.Fatal("an admitted request counter cannot diagnose a real network stall; show unconfirmed progress", got)
	}
}

func TestProgressKnownETAWhileActualLegacyWorkersFinish(t *testing.T) {
	f := newPipelineFixture(t)
	gate := make(chan struct{}, 1)
	f.release = gate
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(source, fmt.Sprint(i)), []byte(strings.Repeat("k", 4096)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := newRunProgress(time.Now())
	ctx := context.WithValue(context.Background(), progressKey{}, p)
	done := make(chan error, 1)
	go func() {
		_, err := Copy(ctx, Remote{f.server.Client(), f.server.URL, "fixture"}, []string{source}, filepath.Join(dir, "spool"))
		done <- err
	}()
	defer func() {
		close(gate)
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("legacy workers did not join")
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-f.started:
		case <-time.After(3 * time.Second):
			t.Fatal("workers not active")
		}
	}
	gate <- struct{}{}
	s := &Service{running: true, runProgress: p}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got := s.Status().Progress
		if got.TotalFiles != nil && *got.TotalFiles == 3 && got.CheckedFiles == 1 {
			if got.ETASeconds == nil || *got.ETASeconds < 1 || got.Percent == nil || *got.Percent <= 0 || *got.Percent >= 100 || !strings.Contains(renderRunProgress(got), "file checks)") {
				t.Fatal("actual partially completed legacy work lacks conservative ETA", got)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("known live total/check progress not exposed")
}

func TestProgressStallOfflineRecoveryPauseAndNewRun(t *testing.T) {
	start := time.Now()
	p := newRunProgress(start)
	p.requestData(4 << 20)
	initial := p.snapshot(start.Add(time.Second), "", false, 4<<20)
	if initial.ETASeconds != nil || initial.TotalFiles != nil {
		t.Fatal("unknown total fabricated estimate", initial)
	}
	stalled := p.snapshot(start.Add(6*time.Second), "", false, 4<<20)
	if stalled.State != "waiting_progress" || stalled.ETASeconds != nil {
		t.Fatal("no recent progress ETA", stalled)
	}
	p.finish(start.Add(7*time.Second), "waiting")
	offline := p.snapshot(start.Add(9*time.Second), "", true, 4<<20)
	if offline.ElapsedMS != 9000 || offline.State != "waiting" || offline.ETASeconds != nil {
		t.Fatal("offline froze/lost elapsed", offline)
	}
	p.beginAttempt(start.Add(10 * time.Second))
	recovered := p.snapshot(start.Add(11*time.Second), "", false, 1<<20)
	if recovered.RunID != initial.RunID || recovered.ElapsedMS != 11000 || recovered.Attempt != 2 || recovered.DataRequestBytes != 5<<20 {
		t.Fatal("retry reset clock/counters", recovered)
	}
	observing := p.snapshot(start.Add(12*time.Second), "observing", false, 1<<20)
	if observing.State != "observing" || observing.ETASeconds != nil {
		t.Fatal("continuous observation invented remaining work", observing)
	}
	p.finish(start.Add(13*time.Second), "paused")
	paused := p.snapshot(start.Add(100*time.Second), "", false, 1<<20)
	if paused.ElapsedMS != 13000 || paused.State != "paused" || paused.ETASeconds != nil {
		t.Fatal("pause did not freeze run", paused)
	}
	newRun := newRunProgress(start.Add(101*time.Second)).snapshot(start.Add(101*time.Second), "", false, 0)
	if newRun.RunID == initial.RunID || newRun.ElapsedMS != 0 || newRun.DataRequestBytes != 0 {
		t.Fatal("new run reused history", newRun)
	}
	if (&Service{Observation: Observation{LastAttemptAt: start.Format(time.RFC3339Nano)}}).Status().Progress != nil {
		t.Fatal("new process invented a continuous monotonic clock from saved wall time")
	}
}

func TestProgressNoopAndUnavailableRendering(t *testing.T) {
	start := time.Now()
	p := newRunProgress(start)
	p.enumerationComplete()
	p.finish(start.Add(time.Second), "completed")
	done := p.snapshot(start.Add(time.Minute), "", false, 0)
	if done.ElapsedMS != 1000 || !done.NoDataPayload || done.Percent != nil || done.ETASeconds != nil {
		t.Fatal("empty/noop run fabricated totals", done)
	}
	p.finish(start.Add(time.Minute), "paused")
	if p.snapshot(start.Add(time.Hour), "", false, 0).State != "completed" {
		t.Fatal("later pause erased successful completion")
	}
	for _, sample := range []*RunProgress{nil, done, newRunProgress(start).snapshot(start.Add(6*time.Second), "", true, 0)} {
		text := renderRunProgress(sample)
		if !strings.Contains(text, "Elapsed:") || !strings.Contains(text, "ETA:") || strings.Contains(text, "NaN") || strings.Contains(text, "Inf") || strings.Contains(text, "~0s") {
			t.Fatal("invalid progress display", text)
		}
	}
}

func TestProgressLegacyHooksCountChecksAndPayloadWithoutExtraCopies(t *testing.T) {
	f := newPipelineFixture(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(source, fmt.Sprint(i)), []byte(strings.Repeat("x", 49152)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	remote := Remote{f.server.Client(), f.server.URL, "fixture"}
	for attempt := 0; attempt < 2; attempt++ {
		p := newRunProgress(time.Now())
		ctx := context.WithValue(context.Background(), progressKey{}, p)
		n, err := Copy(ctx, remote, []string{source}, filepath.Join(dir, fmt.Sprintf("spool%d", attempt)))
		if err != nil {
			t.Fatal(err)
		}
		p.finish(time.Now(), "completed")
		got := p.snapshot(time.Now(), "", false, 0)
		want := int64(3)
		bytes := int64(3 * 49152)
		if attempt == 1 {
			want = 0
			bytes = 0
		}
		if int64(n) != want || got.PublishedFiles != want || got.CheckedFiles != 3 || got.TotalFiles == nil || *got.TotalFiles != 3 || got.DataRequestBytes != bytes || got.NoDataPayload != (attempt == 1) {
			t.Fatal("passive telemetry changed copy/noop behavior", attempt, n, got)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.files) != 3 {
		t.Fatal("extra physical copies", len(f.files))
	}
}

func TestProgressStatusElapsedSurvivesAttachAndStaysLocal(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "file")
	if err := os.WriteFile(source, []byte("progress"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	s := &Service{Config: Config{SaturnURL: server.URL, AccessToken: "test", Sources: []string{source}, IntervalSeconds: 60}, StateDir: filepath.Join(dir, "state"), HTTP: server.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); s.jobs.Wait() }()
	s.mu.Lock()
	s.startLocked(ctx)
	s.mu.Unlock()
	read := func() map[string]any {
		raw, err := json.Marshal(s.Status())
		if err != nil {
			t.Fatal(err)
		}
		var status map[string]any
		if err = json.Unmarshal(raw, &status); err != nil {
			t.Fatal(err)
		}
		p, ok := status["progress"].(map[string]any)
		if !ok {
			t.Fatal("active run status has no elapsed/progress/ETA telemetry")
		}
		return p
	}
	first := read()
	time.Sleep(25 * time.Millisecond)
	second := read()
	if first["runId"] != second["runId"] || second["elapsedMs"].(float64) < first["elapsedMs"].(float64)+10 {
		t.Fatal("status reattach reset run clock", first, second)
	}
	raw, _ := json.Marshal(s.Status().Observation)
	if strings.Contains(string(raw), "elapsedMs") || strings.Contains(string(raw), "etaSeconds") {
		t.Fatal("local telemetry leaked into strict legacy check-in", string(raw))
	}
}
