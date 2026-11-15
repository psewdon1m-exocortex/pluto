package pluto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

type SourcePolicy struct {
	Revision int64    `json:"revision"`
	Codec    string   `json:"codec"`
	Excludes []string `json:"excludes"`
	Sources  []string `json:"sources,omitempty"` // Optional explicit scope transition; server copies are retained.
}
type IndexedConfig struct {
	Activated bool                 `json:"activated"`
	Profile   IndexedCommandConfig `json:"profile"`
	Policy    SourcePolicy         `json:"policy"`
}
type EngineObservation struct {
	Mode                                           string `json:"mode"`
	Phase                                          string `json:"phase"`
	Queued, Captured, Published, Recovered, Failed int64
	OldestPendingMS                                int64                    `json:"oldestPendingMs"`
	Gap                                            bool                     `json:"gap"`
	WaitReason                                     string                   `json:"waitReason,omitempty"`
	HTTP                                           syncstate.HTTPMetrics    `json:"http"`
	Capture                                        syncstate.CaptureMetrics `json:"capture"`
	Features                                       map[string]bool          `json:"features,omitempty"`
}

func (p SourcePolicy) Validate() error {
	if p.Revision < 1 || p.Codec != "legacy" && p.Codec != "portable_v1" || len(p.Excludes) > 500 {
		return errors.New("invalid source policy")
	}
	if p.Sources != nil {
		if len(p.Sources) < 1 || len(p.Sources) > 128 {
			return errors.New("source scope must contain 1 to 128 paths")
		}
		seen := map[string]bool{}
		for _, source := range p.Sources {
			if !filepath.IsAbs(source) || filepath.Clean(source) != source || source == "/" || strings.ContainsRune(source, 0) || seen[source] {
				return errors.New("invalid or duplicate source scope path")
			}
			seen[source] = true
		}
	}
	for _, rule := range p.Excludes {
		if rule == "" || len(rule) > 4096 || strings.HasPrefix(rule, "/") || strings.ContainsAny(rule, "\\\x00") || strings.Contains(rule, "//") {
			return errors.New("exclude must be a relative destination prefix")
		}
		for _, part := range strings.Split(rule, "/") {
			if part == "." || part == ".." || part == "" {
				return errors.New("invalid exclude prefix")
			}
		}
	}
	return nil
}
func (p SourcePolicy) Includes(destination string) bool {
	for _, rule := range p.Excludes {
		if destination == rule || strings.HasPrefix(destination, rule+"/") {
			return false
		}
	}
	return true
}
func (p SourcePolicy) Digest() string {
	raw, _ := json.Marshal(p)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func daemonProfile(c Config) (IndexedCommandConfig, error) {
	if c.Indexed == nil || !c.Indexed.Activated {
		return IndexedCommandConfig{}, syncstate.ErrRemoteUnqualified
	}
	if err := c.Indexed.Policy.Validate(); err != nil {
		return IndexedCommandConfig{}, err
	}
	p := c.Indexed.Profile
	if p.Schema != IndexedProfileSchema || p.Remote.Domain != syncstate.DaemonHTTPContract || p.Remote.Origin != c.SaturnURL {
		return p, syncstate.ErrIdentityConflict
	}
	p.Remote.Token = c.AccessToken
	p.Remote.Proxy = c.Proxy
	p.Remote.NameCodec = c.Indexed.Policy.Codec
	prior := map[string]IndexedSourceConfig{}
	for _, s := range p.Sources {
		prior[s.SelectedPath] = s
	}
	p.Sources = nil
	for _, path := range c.Sources {
		s, ok := prior[path]
		if !ok {
			hash := sha256.Sum256([]byte(path))
			s = IndexedSourceConfig{ID: "source-" + hex.EncodeToString(hash[:16]), SelectedPath: path}
		}
		p.Sources = append(p.Sources, s)
	}
	return p, nil
}

func (s *Service) runBackup(ctx context.Context, c Config) (countOut int, resultErr error) {
	marker := filepath.Join(s.StateDir, "indexed-activation.json")
	if c.Indexed == nil || !c.Indexed.Activated {
		if _, err := os.Lstat(marker); err == nil {
			return 0, errors.New("indexed profile is activated; legacy writer is fenced")
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		return Copy(ctx, Remote{s.HTTP, c.SaturnURL, c.AccessToken}, c.Sources, filepath.Join(s.StateDir, "spool"))
	}
	cfg, err := daemonProfile(c)
	if err != nil {
		return 0, err
	}
	x, err := OpenIndexedSession(ctx, cfg, filepath.Join(s.StateDir, "indexed"), true)
	if err != nil {
		return 0, fmt.Errorf("open indexed session: %w", err)
	}
	defer func() {
		closeErr := x.Close()
		resultErr = errors.Join(resultErr, closeErr)
		if closeErr == nil {
			resultErr = errors.Join(resultErr, SaveJSON(filepath.Join(s.StateDir, "indexed-session.json"), map[string]any{"schema": "pluto.session-lifecycle.v1", "rootId": cfg.LocalRootID, "ownerId": x.Witness.OwnerID, "state": "STOPPED", "minimumWriter": daemonWriterVersion, "at": time.Now().UTC().Format(time.RFC3339Nano)}))
		}
	}()
	if err = SaveJSON(filepath.Join(s.StateDir, "indexed-session.json"), map[string]any{"schema": "pluto.session-lifecycle.v1", "rootId": cfg.LocalRootID, "ownerId": x.Witness.OwnerID, "state": "RUNNING", "minimumWriter": daemonWriterVersion}); err != nil {
		return 0, err
	}
	policyJSON, _ := json.Marshal(c.Indexed.Policy)
	liveHTTP := x.HTTP
	s.mu.Lock()
	s.progressMetrics = func() int64 { return liveHTTP.Metrics().DataBytes }
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		progressFrom(ctx).observeData(liveHTTP.Metrics().DataBytes)
		s.progressMetrics = nil
		s.progressPhase = ""
		s.mu.Unlock()
	}()
	if err = x.Store.CheckPolicy(ctx, cfg.LocalRootID, c.Indexed.Policy.Codec, c.Indexed.Policy.Digest(), c.Indexed.Policy.Revision, policyJSON); err != nil {
		return 0, err
	}
	before := syncstate.CaptureMetricSnapshot()
	count := int64(0)
	var captured, recovered, failed int64
	update := func(phase, reason string) {
		state, _ := x.Sources.ObserverStatus(ctx, x.Witness)
		if state.OldestMS > 0 {
			state.OldestMS = max(0, time.Now().UnixMilli()-state.OldestMS)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.Observation.Engine = &EngineObservation{Mode: "indexed", Phase: phase, Queued: state.Pending, Captured: captured, Published: count, Recovered: recovered, Failed: failed, OldestPendingMS: state.OldestMS, Gap: state.Gap, WaitReason: reason, HTTP: x.HTTP.Metrics(), Capture: syncstate.CaptureMetricSnapshot().Since(before), Features: x.HTTP.Features()}
		s.Observation.UploadedFiles = int(count)
		s.progressPhase = phase
		progressFrom(ctx).publicationCount(count)
		progressFrom(ctx).verifiedCount(captured)
		if phase == "observing" {
			s.Observation.LastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
	interval := time.Duration(c.IntervalSeconds) * time.Second
	include := scopeIncludes(c.Indexed.Policy, c.Sources)
	nextHealth := time.Now()
	for {
		if err = ctx.Err(); err != nil {
			return int(count), err
		}
		state, e := x.Sources.ObserverStatus(ctx, x.Witness)
		if e != nil {
			return int(count), fmt.Errorf("observer status: %w", e)
		}
		full := state.Gap || !time.Now().Before(nextHealth)
		var targets []syncstate.DirtyHint
		if !full {
			targets, e = x.ReadyHints(ctx, include)
			if e != nil {
				return int(count), fmt.Errorf("ready hints: %w", e)
			}
		}
		if full || len(targets) > 0 {
			update("reconciling", "")
			report, e := x.Cycle(ctx, targets, include)
			count += report.Uploaded
			// These counters describe this owner session, like Published. A retry
			// or an empty observation cycle must not erase completed capture work.
			captured += report.Verified
			recovered += report.Recovered
			failed += report.Failed
			for _, h := range report.CompletedHints {
				if ackErr := x.Sources.AckDirty(ctx, x.Witness, h); ackErr != nil {
					return int(count), ackErr
				}
			}
			if e != nil {
				e = fmt.Errorf("indexed cycle: %w", e)
				if !c.Enabled {
					return int(count), e
				}
				reason, _ := syncstate.RetryClass(e)
				if reason == "" {
					reason = "reconciliation_required"
				}
				update("retry_wait", reason)
				var waiting *syncstate.RetryWait
				if errors.As(e, &waiting) {
					select {
					case <-ctx.Done():
						return int(count), ctx.Err()
					case <-x.Observer.Wake():
					case <-time.After(max(time.Millisecond, time.Until(waiting.Until))):
					}
					continue
				}
				return int(count), e
			}
			if !report.Complete {
				return int(count), syncstate.ErrSourceIncomplete
			}
			if full {
				if x.Observer.Healthy() {
					if e = x.Sources.ReconciledObserver(ctx, x.Witness, state.GapSequence); e != nil {
						return int(count), e
					}
				}
				nextHealth = time.Now().Add(interval)
			} else {
				for _, h := range targets {
					if e = x.Sources.AckDirty(ctx, x.Witness, h); e != nil {
						return int(count), e
					}
				}
			}
			remaining, pendingErr := x.Sources.ObserverStatus(ctx, x.Witness)
			if pendingErr != nil {
				return int(count), pendingErr
			}
			state = remaining
			if remaining.Pending == 0 {
				update("observing", "")
			}
			if !c.Enabled && remaining.Pending == 0 {
				return int(count), nil
			}
		}
		// A live observer keeps its owner and dirty generations between cycles.
		// Long polling is cancellable by local work and never gates source reads.
		waitCtx, cancel := context.WithCancel(ctx)
		var feedDone chan error
		if x.HTTP.Features()["changes-wait-v1"] {
			feedDone = make(chan error, 1)
			go func() { feedDone <- x.HTTP.WaitChanges(waitCtx) }()
		} else if e = x.HTTP.Refresh(waitCtx); e != nil {
			cancel()
			return int(count), fmt.Errorf("feed refresh: %w", e)
		}
		delay := min(25*time.Second, time.Until(nextHealth))
		if state.Pending > 0 {
			delay = min(delay, 750*time.Millisecond)
		}
		if delay < time.Millisecond {
			delay = time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
		case <-x.Observer.Wake():
		case <-timer.C:
		case e = <-feedDone:
			feedDone = nil
		}
		cancel()
		timer.Stop()
		if feedDone != nil {
			<-feedDone
		}
		if ctx.Err() != nil {
			return int(count), ctx.Err()
		}
		if e != nil && !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
			return int(count), e
		}
		if e = x.Observer.Health(ctx, x.SourceIDs); e != nil && x.Observer.Healthy() {
			return int(count), e
		}
		if !x.Observer.Healthy() { // Watch exhaustion/unsupported observations use periodic catch-up, not a busy full-scan loop.
			select {
			case <-ctx.Done():
				return int(count), ctx.Err()
			case <-time.After(min(interval, time.Minute)):
			}
		}
	}
}

type AdoptionPlan struct {
	Schema, Digest   string
	SourceCount      int
	Codec            string
	CopiesRetained   bool
	MaximumFileBytes int64
	RetainedVersions int
	Activated        bool
	NewBinding       syncstate.RootBinding
	RemoteBinding    syncstate.RemoteBinding
	Existing         *syncstate.AdoptionState `json:"existing,omitempty"`
	Compatible       bool
}

func adoptionPlan(c Config, candidate IndexedCommandConfig) (AdoptionPlan, error) {
	prospective := c
	policy := SourcePolicy{Revision: 1, Codec: "legacy", Excludes: []string{}}
	if candidate.Remote.NameCodec != "" {
		policy.Codec = candidate.Remote.NameCodec
	}
	if c.Indexed != nil && c.Indexed.Activated {
		policy = c.Indexed.Policy
	}
	if err := policy.Validate(); err != nil {
		return AdoptionPlan{}, err
	}
	safeCandidate := candidate
	safeCandidate.Remote.Token = ""
	prospective.Indexed = &IndexedConfig{Activated: true, Profile: safeCandidate, Policy: policy}
	if raw, e := json.MarshalIndent(prospective, "", "  "); e != nil {
		return AdoptionPlan{}, e
	} else if len(raw) > 65536 {
		return AdoptionPlan{}, errors.New("adopted configuration exceeds its 64 KiB bound")
	}
	if candidate.Schema != IndexedProfileSchema || candidate.Remote.Domain != syncstate.DaemonHTTPContract || candidate.Remote.Origin != c.SaturnURL || len(c.Sources) == 0 || len(c.Sources) != len(candidate.Sources) {
		return AdoptionPlan{}, syncstate.ErrIdentityConflict
	}
	for i, path := range c.Sources {
		if candidate.Sources[i].SelectedPath != path {
			return AdoptionPlan{}, errors.New("adoption must preserve the current ordered source list")
		}
	}
	if _, err := HTTPSOrigin(candidate.Remote.Origin); err != nil {
		return AdoptionPlan{}, err
	}
	// Digest includes credentials as a one-way binding, never prints them.
	raw, err := json.Marshal(struct {
		Config    Config
		Candidate IndexedCommandConfig
	}{c, candidate})
	if err != nil {
		return AdoptionPlan{}, err
	}
	h := sha256.Sum256(raw)
	b, err := syncproto.ReadBinding(candidate.Remote.Binding)
	if err != nil {
		return AdoptionPlan{}, err
	}
	return AdoptionPlan{Schema: "pluto.adoption-plan.v1", Digest: hex.EncodeToString(h[:]), SourceCount: len(c.Sources), Codec: "legacy", CopiesRetained: true, MaximumFileBytes: MaxFileBytes, RetainedVersions: 10, Activated: c.Indexed != nil && c.Indexed.Activated, Compatible: true, RemoteBinding: b, NewBinding: syncstate.RootBinding{RootID: candidate.LocalRootID, MappingID: candidate.MappingID, ServerIdentity: b.ServerIdentity, RemoteRootID: b.RootID, DeviceID: candidate.Remote.DeviceID, SourceIdentity: candidate.SourceSetID}}, nil
}

func inspectAdoption(ctx context.Context, stateDir string, c Config, candidate IndexedCommandConfig) (AdoptionPlan, error) {
	plan, err := adoptionPlan(c, candidate)
	if err != nil {
		return plan, err
	}
	codec := "legacy"
	if candidate.Remote.NameCodec != "" {
		codec = candidate.Remote.NameCodec
	}
	if c.Indexed != nil && c.Indexed.Activated {
		codec = c.Indexed.Policy.Codec
	}
	plan.Codec = codec
	if candidate.Remote.NameCodec != "" && candidate.Remote.NameCodec != codec {
		return plan, syncstate.ErrIdentityConflict
	}
	dir := filepath.Join(stateDir, "indexed")
	if _, err = os.Lstat(filepath.Join(dir, "sync-state.sqlite")); errors.Is(err, os.ErrNotExist) {
		return plan, nil
	} else if err != nil {
		return plan, err
	}
	store, err := syncstate.OpenReadOnly(ctx, dir)
	if err != nil {
		return plan, err
	}
	defer store.Close()
	identity := syncstate.CapturedHTTPIdentity{Domain: candidate.Remote.Domain, Origin: strings.TrimSuffix(candidate.Remote.Origin, "/"), DeviceID: candidate.Remote.DeviceID, BackendIdentity: candidate.Remote.BackendIdentity, ContractReceiptSHA256: candidate.Remote.QualificationReceiptSHA256}
	existing, err := store.PreviewAdoption(ctx, plan.NewBinding, plan.RemoteBinding, identity, codec, c.Indexed != nil && c.Indexed.Activated)
	if err != nil {
		return plan, err
	}
	plan.Existing = &existing
	plan.Compatible = existing.Compatible
	raw, _ := json.Marshal(plan)
	hash := sha256.Sum256(raw)
	plan.Digest = hex.EncodeToString(hash[:])
	return plan, nil
}

func describeIndexedError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("indexed recovery deferred: %v", err)
}
