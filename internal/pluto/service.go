package pluto

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"pluto/internal/pluto/syncstate"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Observation struct {
	Enabled         bool               `json:"enabled"`
	IntervalSeconds int                `json:"intervalSeconds"`
	UploadedFiles   int                `json:"uploadedFiles"`
	LastAttemptAt   string             `json:"lastAttemptAt,omitempty"`
	LastSuccessAt   string             `json:"lastSuccessAt,omitempty"`
	NextRunAt       string             `json:"nextRunAt,omitempty"`
	Error           string             `json:"error,omitempty"`
	NetworkState    string             `json:"networkState,omitempty"`
	Engine          *EngineObservation `json:"engine,omitempty"`
}
type Status struct {
	Version        string       `json:"version"`
	KernelURL      string       `json:"kernelURL"`
	Connected      bool         `json:"connected"`
	ConnectionName string       `json:"connectionName"`
	Sources        []string     `json:"sources"`
	Repository     string       `json:"repository"`
	Running        bool         `json:"running"`
	Observation    Observation  `json:"observation"`
	Progress       *RunProgress `json:"progress,omitempty"`
}
type Control struct {
	Action          string   `json:"action"`
	KernelURL       string   `json:"kernelURL"`
	Token           string   `json:"token"`
	Sources         []string `json:"sources"`
	IntervalSeconds int      `json:"intervalSeconds"`
	Code            string   `json:"code"`
	Enabled         bool     `json:"enabled"`
}
type Service struct {
	persistDirty                  bool
	mu                            sync.Mutex
	Config                        Config
	Observation                   Observation
	ConfigPath, StateDir, Version string
	HTTP                          *http.Client
	running, updating             bool
	resumeAfterStop               bool
	networkWaiting                bool
	networkNotBefore              time.Time
	cancel                        context.CancelFunc
	jobs                          sync.WaitGroup
	runProgress                   *runProgress
	progressMetrics               func() int64
	progressPhase                 string
}

func NewService(configPath, stateDir, version string) (*Service, error) {
	c, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if c.IntervalSeconds < 60 || c.IntervalSeconds > 31536000 {
		return nil, errors.New("configured interval is invalid")
	}
	httpClient, err := NewHTTPClientWithProxy(c.Proxy)
	if err != nil {
		return nil, err
	}
	s := &Service{Config: c, ConfigPath: configPath, StateDir: stateDir, Version: version, HTTP: httpClient}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "status.json"))
	_ = json.Unmarshal(raw, &s.Observation)
	return s, nil
}
func (s *Service) statusLocked() Status {
	o := s.Observation
	o.Enabled = s.Config.Enabled
	o.IntervalSeconds = s.Config.IntervalSeconds
	if !s.Config.Enabled {
		o.NextRunAt = ""
	}
	return Status{s.Version, s.Config.KernelURL, s.Config.AccessToken != "", s.Config.ConnectionName, append([]string{}, s.Config.Sources...), s.Config.ReleaseRepository, s.running, o, s.progressLocked(time.Now())}
}
func (s *Service) Status() Status { s.mu.Lock(); defer s.mu.Unlock(); return s.statusLocked() }
func (s *Service) Apply(ctx context.Context, c Control) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updating && c.Action != "status" {
		return errors.New("update is in progress")
	}
	candidate := s.Config
	sourcesChanged := false
	switch c.Action {
	case "connect":
		origin, err := HTTPSOrigin(c.KernelURL)
		if err != nil {
			return err
		}
		if len(c.Token) < 24 || len(c.Token) > 512 {
			return errors.New("outdoor token is invalid")
		}
		d, err := Discover(ctx, s.HTTP, origin, c.Token)
		if err != nil {
			return err
		}
		if candidate.AccessToken != "" && (candidate.KernelURL != origin || candidate.SaturnURL != d.SaturnURL) {
			return errors.New("disconnect the existing pipeline before changing its Kernel or Saturn")
		}
		candidate.KernelURL = origin
		candidate.OutdoorToken = c.Token
		candidate.SaturnURL = d.SaturnURL
		candidate.ReleaseRepository = d.Repository
	case "sources", "sources-add", "sources-remove":
		if s.running {
			return errors.New("pause copying before changing sources")
		}
		var values []string
		var err error
		switch c.Action {
		case "sources-add":
			values, err = addSources(candidate.Sources, c.Sources)
		case "sources-remove":
			values, err = removeSources(candidate.Sources, c.Sources)
		default:
			values, err = ValidateSources(c.Sources)
		}
		if err != nil {
			return err
		}
		sourcesChanged = !slices.Equal(candidate.Sources, values)
		candidate.Sources = values
		if len(values) == 0 {
			candidate.Enabled = false
		}
	case "interval":
		if c.IntervalSeconds < 60 || c.IntervalSeconds > 31536000 {
			return errors.New("interval must be between 60 and 31536000 seconds")
		}
		candidate.IntervalSeconds = c.IntervalSeconds
		if candidate.Indexed != nil && candidate.Indexed.Activated && s.cancel != nil {
			s.cancel()
		}
	case "enroll":
		if candidate.Indexed != nil && candidate.Indexed.Activated {
			return errors.New("activated indexed binding must be migrated before re-enrollment")
		}
		if candidate.KernelURL == "" || candidate.OutdoorToken == "" {
			return errors.New("configure Kernel discovery first")
		}
		if s.running {
			return errors.New("pause copying before enrollment")
		}
		d, err := Discover(ctx, s.HTTP, candidate.KernelURL, candidate.OutdoorToken)
		if err != nil {
			return err
		}
		b, err := Bind(ctx, Remote{s.HTTP, d.SaturnURL, ""}, c.Code, s.Version)
		if err != nil {
			return err
		}
		candidate.SaturnURL = d.SaturnURL
		candidate.ReleaseRepository = d.Repository
		candidate.AccessToken = b.Token
		candidate.ConnectionName = b.Device.SyncFolderName
		candidate.Enabled = false
		s.Observation = Observation{}
	case "enabled":
		if c.Enabled && (candidate.AccessToken == "" || len(candidate.Sources) == 0) {
			return errors.New("connect a pipeline and choose sources before enabling copying")
		}
		candidate.Enabled = c.Enabled
		if !c.Enabled && s.cancel != nil {
			s.cancel()
		}
	case "run":
		if candidate.AccessToken == "" || len(candidate.Sources) == 0 {
			return errors.New("connect a pipeline and choose sources first")
		}
		if s.running {
			return errors.New("copying is already running")
		}
		s.runProgress = nil // An explicit Copy now is a new logical run, including a NOOP.
		s.startLocked(ctx)
		return nil
	case "disconnect":
		if s.running {
			return errors.New("pause copying before disconnecting")
		}
		candidate.AccessToken = ""
		candidate.ConnectionName = ""
		candidate.Enabled = false
	case "quiesce":
		if s.cancel != nil {
			s.cancel()
		}
		s.updating = true
		return nil
	default:
		return errors.New("unknown Pluto action")
	}
	if err := SaveJSON(s.ConfigPath, candidate); err != nil {
		return err
	}
	resumed := c.Action == "enabled" && candidate.Enabled && !s.Config.Enabled
	if resumed {
		// Resume schedules the next ordinary cycle immediately. A paused run
		// may still be joining; its finalizer must not restore the old delay.
		s.Observation.NextRunAt = ""
		s.resumeAfterStop = s.running
	}
	s.Config = candidate
	if !candidate.Enabled && !s.running {
		s.runProgress.finish(time.Now(), "paused")
	}
	if sourcesChanged {
		// The old source failure describes a different list. Keep unrelated
		// operational failures and historical timestamps until a new run.
		s.Observation.Error = withoutSourceFailure(s.Observation.Error)
	}
	s.auditLocked("configuration.changed", map[string]any{"action": c.Action, "enabled": candidate.Enabled, "sourceCount": len(candidate.Sources), "intervalSeconds": candidate.IntervalSeconds})
	if c.Action == "interval" || sourcesChanged {
		s.Observation.NextRunAt = ""
		if candidate.Enabled {
			next := time.Now()
			if !sourcesChanged {
				next = next.Add(time.Duration(candidate.IntervalSeconds) * time.Second)
			}
			s.Observation.NextRunAt = next.UTC().Format(time.RFC3339Nano)
		}
	}
	if c.Action == "interval" || sourcesChanged || resumed {
		if err := SaveJSON(filepath.Join(s.StateDir, "status.json"), s.statusLocked().Observation); err != nil {
			if !strings.Contains(s.Observation.Error, "status persistence failed") {
				s.Observation.Error = strings.TrimPrefix(s.Observation.Error+"; status persistence failed", "; ")
			}
			return err
		}
	}
	return nil
}

func withoutSourceFailure(message string) string {
	count, _, found := strings.Cut(message, " source entries failed: ")
	n, err := strconv.Atoi(count)
	if !found || err != nil || n < 1 {
		return message
	}
	// These operational warnings may have been appended to a copy failure.
	// Changing sources does not establish that either write has recovered.
	warnings := []string{}
	for {
		removed := false
		for _, warning := range []string{"local audit write failed", "status persistence failed"} {
			if strings.HasSuffix(message, "; "+warning) {
				message = strings.TrimSuffix(message, "; "+warning)
				warnings = append([]string{warning}, warnings...)
				removed = true
				break
			}
		}
		if !removed {
			return strings.Join(warnings, "; ")
		}
	}
}
func (s *Service) startLocked(parent context.Context) {
	s.resumeAfterStop = false
	c := s.Config
	c.Sources = append([]string{}, c.Sources...)
	ctx, cancel := context.WithCancel(parent)
	now := time.Now()
	if s.runProgress == nil || s.runProgress.terminal() {
		s.runProgress = newRunProgress(now)
	} else {
		s.runProgress.beginAttempt(now)
	}
	ctx = context.WithValue(ctx, progressKey{}, s.runProgress)
	s.progressPhase = ""
	s.cancel = cancel
	s.running = true
	s.Observation.LastAttemptAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.Observation.NextRunAt = ""
	s.Observation.Error = ""
	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		defer cancel()
		count, err := s.runBackup(ctx, c)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
		s.cancel = nil
		if s.Observation.Engine != nil {
			engine := *s.Observation.Engine
			engine.Phase = "stopped"
			if err != nil && !errors.Is(err, context.Canceled) {
				engine.Phase = "reconciliation_required"
			}
			s.Observation.Engine = &engine
		}
		s.Observation.UploadedFiles = count
		if err != nil {
			state := "failed"
			if errors.Is(err, context.Canceled) {
				state = "paused"
			} else if networkWaitState(err) != "" {
				state = "waiting"
			}
			s.runProgress.finish(time.Now(), state)
			s.Observation.Error = err.Error()
			if state := networkWaitState(err); state != "" {
				if until := time.Now().Add(networkRetryAfter(err)); until.After(s.networkNotBefore) {
					s.networkNotBefore = until
				}
				s.networkWaiting = true
				s.Observation.NetworkState = state
			}
		} else {
			s.runProgress.finish(time.Now(), "completed")
			s.Observation.NetworkState = "ONLINE"
			s.Observation.LastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		s.Observation.NextRunAt = time.Now().Add(time.Duration(s.Config.IntervalSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
		if err != nil && s.Config.IntervalSeconds > 60 {
			s.Observation.NextRunAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
		}
		if s.resumeAfterStop && s.Config.Enabled {
			s.Observation.NextRunAt = ""
		}
		s.resumeAfterStop = false
		if saveErr := SaveJSON(filepath.Join(s.StateDir, "status.json"), s.statusLocked().Observation); saveErr != nil {
			s.Observation.Error += "; status persistence failed"
		}
		s.auditLocked("copy.completed", copyCompletionFields(count, err))
	}()
}
func (s *Service) Loop(ctx context.Context) {
	heartbeats := newHeartbeatWorker(ctx, 10*time.Second, s.heartbeat)
	defer func() { <-heartbeats.done }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastHeartbeat := time.Time{}
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			if s.cancel != nil {
				s.cancel()
			}
			s.mu.Unlock()
			s.jobs.Wait()
			return
		case now := <-ticker.C:
			s.mu.Lock()
			if s.persistDirty {
				s.persistConfigLocked()
			}
			due := s.Config.Enabled && !s.running && !s.updating && !s.networkWaiting && s.Config.AccessToken != ""
			if next, err := time.Parse(time.RFC3339Nano, s.Observation.NextRunAt); err == nil && now.Before(next) {
				due = false
			}
			if due {
				s.startLocked(ctx)
			}
			c := s.Config
			observation := s.statusLocked().Observation
			probeNotBefore := s.networkNotBefore
			// K3 C20 server extension accepts the bounded engine projection.
			s.mu.Unlock()
			if c.AccessToken != "" && now.Sub(lastHeartbeat) >= 20*time.Second && !now.Before(probeNotBefore) {
				lastHeartbeat = now
				heartbeats.offer(heartbeatUpdate{config: c, observation: observation})
			}
		}
	}
}

func (s *Service) persistConfigLocked() {
	if err := SaveJSON(s.ConfigPath, s.Config); err != nil {
		s.persistDirty = true
		s.Observation.Error = "Configuration persistence failed; credentials are disabled in memory and persistence will be retried"
		s.auditLocked("configuration.persistence_failed", nil)
	} else {
		s.persistDirty = false
		if strings.HasPrefix(s.Observation.Error, "Configuration persistence failed") {
			s.Observation.Error = ""
		}
	}
}

func (s *Service) auditLocked(event string, fields map[string]any) {
	if err := appendAudit(filepath.Join(s.StateDir, "audit.jsonl"), event, fields); err != nil {
		if !strings.Contains(s.Observation.Error, "local audit write failed") {
			s.Observation.Error += "; local audit write failed"
		}
	}
}
func (s *Service) Serve(ctx context.Context, socket string) error {
	releaseLifecycle, err := lifecycleLock(s.StateDir)
	if err != nil {
		return err
	}
	defer releaseLifecycle()
	ctx, cancelService := context.WithCancel(ctx)
	defer cancelService()
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return err
	}
	if _, err := os.Stat(socket); err == nil {
		connection, err := net.DialTimeout("unix", socket, time.Second)
		if err == nil {
			connection.Close()
			return errors.New("a Pluto daemon already owns the socket")
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer os.Remove(socket)
	if err = os.Chmod(socket, 0600); err != nil {
		listener.Close()
		return err
	}
	// A stopped daemon can leave a partial local snapshot. Never reuse it.
	spool := filepath.Join(s.StateDir, "spool")
	entries, readErr := os.ReadDir(spool)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		listener.Close()
		return readErr
	}
	for _, entry := range entries {
		_, activated := os.Lstat(filepath.Join(s.StateDir, "indexed-activation.json"))
		if s.Config.Indexed != nil && s.Config.Indexed.Activated || activated == nil {
			break
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "copy-") {
			if err := os.Remove(filepath.Join(spool, entry.Name())); err != nil {
				listener.Close()
				return err
			}
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /maintenance/{action}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.running || s.Config.Enabled || s.updating {
			http.Error(w, "pause and drain before maintenance", 409)
			return
		}
		action := r.PathValue("action")
		if action != "checkpoint" && action != "backup" {
			http.Error(w, "unknown maintenance action", 400)
			return
		}
		if s.Config.Indexed == nil || !s.Config.Indexed.Activated {
			http.Error(w, "no activated indexed profile", 409)
			return
		}
		if _, e := os.Stat(filepath.Join(s.StateDir, "indexed", "sync-state.sqlite")); e != nil {
			http.Error(w, "state is unavailable", 409)
			return
		}
		store, e := syncstate.Open(r.Context(), filepath.Join(s.StateDir, "indexed"))
		if e != nil {
			http.Error(w, "state is unavailable", 409)
			return
		}
		defer store.Close()
		var result any = map[string]any{"schema": "pluto.checkpoint.v1", "complete": true}
		if action == "checkpoint" {
			e = store.Checkpoint(r.Context())
		} else {
			result, e = store.Backup(r.Context())
		}
		if e != nil {
			http.Error(w, "maintenance requires reconciliation", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("GET /diagnostics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"schema": "pluto.diagnostics.v1", "status": s.Status(), "transport": syncstate.TransportMetrics()})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Status())
	})
	mux.HandleFunc("POST /control", func(w http.ResponseWriter, r *http.Request) {
		var c Control
		decoder := json.NewDecoder(io.LimitReader(r.Body, 65537))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&c) != nil {
			http.Error(w, "invalid control request", 400)
			return
		}
		if err := s.Apply(ctx, c); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Status())
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	loopDone := make(chan struct{})
	go func() { defer close(loopDone); s.Loop(ctx) }()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	cancelService()
	<-loopDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func LocalClient(socket string) *http.Client {
	return &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}
