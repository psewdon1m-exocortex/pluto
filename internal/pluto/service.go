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
	"strings"
	"sync"
	"time"
)

type Observation struct {
	Enabled         bool   `json:"enabled"`
	IntervalSeconds int    `json:"intervalSeconds"`
	UploadedFiles   int    `json:"uploadedFiles"`
	LastAttemptAt   string `json:"lastAttemptAt,omitempty"`
	LastSuccessAt   string `json:"lastSuccessAt,omitempty"`
	NextRunAt       string `json:"nextRunAt,omitempty"`
	Error           string `json:"error,omitempty"`
}
type Status struct {
	Version        string      `json:"version"`
	KernelURL      string      `json:"kernelURL"`
	Connected      bool        `json:"connected"`
	ConnectionName string      `json:"connectionName"`
	Sources        []string    `json:"sources"`
	Repository     string      `json:"repository"`
	Running        bool        `json:"running"`
	Observation    Observation `json:"observation"`
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
	cancel                        context.CancelFunc
}

func NewService(configPath, stateDir, version string) (*Service, error) {
	c, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if c.IntervalSeconds < 60 || c.IntervalSeconds > 31536000 {
		return nil, errors.New("configured interval is invalid")
	}
	s := &Service{Config: c, ConfigPath: configPath, StateDir: stateDir, Version: version, HTTP: NewHTTPClient()}
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
	return Status{s.Version, s.Config.KernelURL, s.Config.AccessToken != "", s.Config.ConnectionName, append([]string{}, s.Config.Sources...), s.Config.ReleaseRepository, s.running, o}
}
func (s *Service) Status() Status { s.mu.Lock(); defer s.mu.Unlock(); return s.statusLocked() }
func (s *Service) Apply(ctx context.Context, c Control) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updating && c.Action != "status" {
		return errors.New("update is in progress")
	}
	candidate := s.Config
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
	case "sources":
		values, err := ValidateSources(c.Sources)
		if err != nil {
			return err
		}
		if s.running {
			return errors.New("pause copying before changing sources")
		}
		candidate.Sources = values
	case "interval":
		if c.IntervalSeconds < 60 || c.IntervalSeconds > 31536000 {
			return errors.New("interval must be between 60 and 31536000 seconds")
		}
		candidate.IntervalSeconds = c.IntervalSeconds
	case "enroll":
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
	s.Config = candidate
	s.auditLocked("configuration.changed", map[string]any{"action": c.Action, "enabled": candidate.Enabled, "sourceCount": len(candidate.Sources), "intervalSeconds": candidate.IntervalSeconds})
	if c.Action == "interval" {
		s.Observation.NextRunAt = ""
		if candidate.Enabled {
			s.Observation.NextRunAt = time.Now().Add(time.Duration(candidate.IntervalSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
		}
		return SaveJSON(filepath.Join(s.StateDir, "status.json"), s.statusLocked().Observation)
	}
	return nil
}
func (s *Service) startLocked(parent context.Context) {
	c := s.Config
	c.Sources = append([]string{}, c.Sources...)
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.running = true
	s.Observation.LastAttemptAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.Observation.NextRunAt = ""
	s.Observation.Error = ""
	go func() {
		defer cancel()
		remote := Remote{s.HTTP, c.SaturnURL, c.AccessToken}
		count, err := Copy(ctx, remote, c.Sources, filepath.Join(s.StateDir, "spool"))
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
		s.cancel = nil
		s.Observation.UploadedFiles = count
		if err != nil {
			s.Observation.Error = err.Error()
			var denied *HTTPError
			if errors.As(err, &denied) && (denied.Status == 401 || denied.Status == 403) {
				s.Config.Enabled = false
				s.Config.AccessToken = ""
				s.persistConfigLocked()
			}
		} else {
			s.Observation.LastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		s.Observation.NextRunAt = time.Now().Add(time.Duration(s.Config.IntervalSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
		if err != nil && s.Config.IntervalSeconds > 60 {
			s.Observation.NextRunAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
		}
		if saveErr := SaveJSON(filepath.Join(s.StateDir, "status.json"), s.statusLocked().Observation); saveErr != nil {
			s.Observation.Error += "; status persistence failed"
		}
		s.auditLocked("copy.completed", map[string]any{"uploadedFiles": count, "success": err == nil})
	}()
}
func (s *Service) Loop(ctx context.Context) {
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
			return
		case now := <-ticker.C:
			s.mu.Lock()
			if s.persistDirty {
				s.persistConfigLocked()
			}
			due := s.Config.Enabled && !s.running && !s.updating && s.Config.AccessToken != ""
			if next, err := time.Parse(time.RFC3339Nano, s.Observation.NextRunAt); err == nil && now.Before(next) {
				due = false
			}
			if due {
				s.startLocked(ctx)
			}
			c := s.Config
			observation := s.statusLocked().Observation
			s.mu.Unlock()
			if c.AccessToken != "" && now.Sub(lastHeartbeat) >= 20*time.Second {
				lastHeartbeat = now
				err := (Remote{s.HTTP, c.SaturnURL, c.AccessToken}).json(ctx, "POST", "/api/v1/pluto/check-in", map[string]any{"version": s.Version, "status": observation}, nil)
				if err != nil {
					var denied *HTTPError
					if errors.As(err, &denied) && (denied.Status == 401 || denied.Status == 403) {
						s.mu.Lock()
						s.Config.Enabled = false
						s.Config.AccessToken = ""
						s.Observation.Error = "Saturn access was revoked; obtain a new setup code"
						if s.cancel != nil {
							s.cancel()
						}
						s.persistConfigLocked()
						s.mu.Unlock()
					}
				}
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
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "copy-") {
			if err := os.Remove(filepath.Join(spool, entry.Name())); err != nil {
				listener.Close()
				return err
			}
		}
	}
	mux := http.NewServeMux()
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
	go s.Loop(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
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
