package pluto

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RunProgress is local, optional UI telemetry. It is deliberately outside
// Observation: old Saturn check-in schemas and durable state stay unchanged.
type RunProgress struct {
	RunID            string   `json:"runId"`
	ClockScope       string   `json:"clockScope"`
	State            string   `json:"state"`
	Attempt          int64    `json:"attempt"`
	ElapsedMS        int64    `json:"elapsedMs"`
	CheckedFiles     int64    `json:"checkedFiles"`
	PublishedFiles   int64    `json:"publishedFiles"`
	TotalFiles       *int64   `json:"totalFiles,omitempty"`
	DataRequestBytes int64    `json:"dataRequestBytes"`
	ETAState         string   `json:"etaState"`
	ETASeconds       *int64   `json:"etaSeconds,omitempty"`
	Percent          *float64 `json:"percent,omitempty"`
	NoDataPayload    bool     `json:"noDataPayload"`
}

type progressKey struct{}

var progressSequence atomic.Uint64

type runProgress struct {
	mu                                                      sync.Mutex
	id                                                      string
	started, ended, lastProgress                            time.Time
	state                                                   string
	attempt, checked, discovered, published, dataBase, data int64
	known                                                   bool
}

func newRunProgress(now time.Time) *runProgress {
	return &runProgress{id: fmt.Sprintf("%x-%x", now.UnixNano(), progressSequence.Add(1)), started: now, lastProgress: now, state: "active", attempt: 1}
}
func progressFrom(ctx context.Context) *runProgress {
	p, _ := ctx.Value(progressKey{}).(*runProgress)
	return p
}
func (p *runProgress) terminal() bool { p.mu.Lock(); defer p.mu.Unlock(); return !p.ended.IsZero() }
func (p *runProgress) beginAttempt(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dataBase += p.data
	p.data = 0
	p.checked = 0
	p.discovered = 0
	p.published = 0
	p.known = false
	p.attempt++
	p.state = "active"
	p.lastProgress = now
}
func (p *runProgress) finish(now time.Time, state string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ended.IsZero() {
		return
	}
	p.state = state
	if state != "waiting" && p.ended.IsZero() {
		p.ended = now
	}
}
func (p *runProgress) discover() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discovered++
	p.known = false
}
func (p *runProgress) enumerationComplete() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.known = true
}
func (p *runProgress) checkedFile(published bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked++
	if published {
		p.published++
	}
	p.lastProgress = time.Now()
}
func (p *runProgress) requestData(n int64) {
	if p == nil || n <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.data += n
	p.lastProgress = time.Now()
}
func (p *runProgress) publicationCount(n int64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if n > p.published {
		p.published = n
		p.lastProgress = time.Now()
	}
}
func (p *runProgress) verifiedCount(n int64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if n > p.checked {
		p.checked = n
		p.lastProgress = time.Now()
	}
}
func (p *runProgress) observeData(n int64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if n > p.data {
		p.data = n
		p.lastProgress = time.Now()
	}
}
func (p *runProgress) snapshot(now time.Time, phase string, waiting bool, liveData int64) *RunProgress {
	p.mu.Lock()
	defer p.mu.Unlock()
	if liveData > p.data {
		p.data = liveData
		p.lastProgress = now
	}
	end := now
	if !p.ended.IsZero() {
		end = p.ended
	}
	elapsed := max(time.Duration(0), end.Sub(p.started)) // time.Now carries Go's monotonic component.
	r := &RunProgress{RunID: p.id, ClockScope: "process_monotonic", State: p.state, Attempt: p.attempt, ElapsedMS: elapsed.Milliseconds(), CheckedFiles: p.checked, PublishedFiles: p.published, DataRequestBytes: p.dataBase + p.data, ETAState: "unknown_total", NoDataPayload: p.dataBase+p.data == 0}
	if p.known {
		n := p.discovered
		r.TotalFiles = &n
	}
	if !p.ended.IsZero() {
		r.ETAState = p.state
		if p.state == "completed" && p.known && p.discovered > 0 && p.checked >= p.discovered {
			v := 100.0
			r.Percent = &v
		}
		return r
	}
	if waiting || p.state == "waiting" {
		r.State = "waiting"
		r.ETAState = "unavailable_waiting"
		return r
	}
	if phase == "observing" {
		r.State = "observing"
		r.ETAState = "unavailable_observing"
		return r
	}
	if now.Sub(p.lastProgress) >= 5*time.Second {
		// Admission counters do not measure socket flow. One healthy in-flight
		// upload can be long; report unobserved progress, not a network diagnosis.
		r.State = "waiting_progress"
		r.ETAState = "unavailable_no_recent_progress"
		return r
	}
	if !p.known {
		return r
	}
	remaining := p.discovered - p.checked
	if remaining <= 0 {
		r.ETAState = "finalizing"
		return r
	}
	if p.checked == 0 || elapsed <= 0 {
		r.ETAState = "estimating"
		return r
	}
	seconds := math.Ceil(float64(remaining) * elapsed.Seconds() / float64(p.checked))
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 1 || seconds > 365*24*60*60 {
		r.ETAState = "estimating"
		return r
	}
	eta := int64(seconds)
	r.ETASeconds = &eta
	r.ETAState = "estimate_file_checks"
	percent := min(99.9, 100*float64(p.checked)/float64(p.discovered))
	if percent > 0 {
		r.Percent = &percent
	}
	return r
}

func (s *Service) progressLocked(now time.Time) *RunProgress {
	if s.runProgress == nil {
		return nil
	}
	var data int64
	if s.progressMetrics != nil {
		data = s.progressMetrics()
		if s.progressPhase != "" && s.Observation.Engine != nil {
			s.runProgress.verifiedCount(s.Observation.Engine.Captured)
			s.runProgress.publicationCount(s.Observation.Engine.Published)
		}
	}
	return s.runProgress.snapshot(now, s.progressPhase, s.networkWaiting, data)
}

func progressDuration(ms int64) string {
	ms = max(0, ms)
	seconds := ms / 1000
	if seconds < 60 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dh%02dm%02ds", seconds/3600, seconds/60%60, seconds%60)
}
func renderRunProgress(p *RunProgress) string {
	if p == nil {
		return "Elapsed: unknown (no run in this process) | ETA: unavailable\n"
	}
	eta := "unknown (total not known)"
	if p.ETAState == "estimating" {
		eta = "estimating"
	}
	if strings.HasPrefix(p.ETAState, "unavailable") || p.ETAState == "completed" || p.ETAState == "paused" || p.ETAState == "failed" || p.ETAState == "finalizing" {
		eta = "unavailable (" + strings.ReplaceAll(strings.TrimPrefix(p.ETAState, "unavailable_"), "_", " ") + ")"
	}
	if p.ETASeconds != nil {
		eta = fmt.Sprintf("~%ds (file checks)", *p.ETASeconds)
	}
	total := "unknown"
	if p.TotalFiles != nil {
		total = fmt.Sprint(*p.TotalFiles)
	}
	return fmt.Sprintf("Run: %s | Attempt: %d | Elapsed: %s | ETA: %s\nProgress: %d/%s file checks | Published (attempt): %d | Data request bytes: %d\n", terminalText(strings.ReplaceAll(p.State, "_", " ")), p.Attempt, progressDuration(p.ElapsedMS), eta, p.CheckedFiles, total, p.PublishedFiles, p.DataRequestBytes)
}
