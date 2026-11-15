package pluto

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

const IndexedCommandSchema = "pluto.copy-indexed-isolated/v1"
const IndexedProfileSchema = "pluto.indexed-profile/v1"

type IndexedSourceConfig struct {
	ID               string `json:"id"`
	SelectedPath     string `json:"selected_path"`
	WorkingDirectory string `json:"working_directory"`
}
type IndexedCommandConfig struct {
	Schema         string                       `json:"schema"`
	LocalRootID    string                       `json:"local_root_id"`
	MappingID      string                       `json:"mapping_id"`
	SourceSetID    string                       `json:"source_set_id"`
	Sources        []IndexedSourceConfig        `json:"sources"`
	Remote         syncstate.IsolatedHTTPConfig `json:"remote"`
	SmallBatchMode string                       `json:"small_batch_mode,omitempty"`
}
type IndexedCommandResult struct {
	Schema           string                       `json:"schema"`
	OK               bool                         `json:"ok"`
	Report           syncstate.CapturedScanReport `json:"report"`
	HTTP             syncstate.HTTPMetrics        `json:"http"`
	Capture          syncstate.CaptureMetrics     `json:"capture"`
	SQL              sql.DBStats                  `json:"sql_pool"`
	Disk             syncstate.SourceDiskUsage    `json:"state_disk"`
	StartupArtifacts syncstate.ArtifactReport     `json:"startup_artifacts"`
	WallMilliseconds int64                        `json:"wall_milliseconds"`
	Error            string                       `json:"error,omitempty"`
	BatchResources   *IndexedBatchResources       `json:"batch_resources,omitempty"`
}

type IndexedBatchResources struct {
	ActiveDataJobs, ActiveSourceReaders, ActiveEnumerations  int
	SpoolReservedBytes, RetainedBytes, MetadataReservedBytes int64
}

func readIndexedConfig(filename string) (IndexedCommandConfig, error) {
	var cfg IndexedCommandConfig
	f, e := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return cfg, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return cfg, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 {
		return cfg, syncstate.ErrIdentityConflict
	}
	raw, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil {
		return cfg, e
	}
	if len(raw) > 1<<20 {
		return cfg, syncstate.ErrSourceQuota
	}
	if _, e = syncproto.Parse(raw); e != nil {
		return cfg, e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&cfg); e != nil {
		return cfg, e
	}
	if cfg.Schema != IndexedCommandSchema && cfg.Schema != IndexedProfileSchema || len(cfg.Sources) < 1 || len(cfg.Sources) > syncstate.MaxSources {
		return cfg, syncstate.ErrIdentityConflict
	}
	if _, e = syncproto.ReadBinding(cfg.Remote.Binding); e != nil {
		return cfg, e
	}
	if cfg.SmallBatchMode != "" && cfg.SmallBatchMode != "bulk" && cfg.SmallBatchMode != "changes" {
		return cfg, syncstate.ErrIdentityConflict
	}
	return cfg, nil
}

func indexedPrivateProfile(filename string) error {
	if !filepath.IsAbs(filename) {
		return syncstate.ErrIdentityConflict
	}
	if e := os.Mkdir(filename, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	f, e := os.OpenFile(filename, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm() != 0700 {
		return syncstate.ErrIdentityConflict
	}
	return nil
}

// RunIndexedCommand is an explicit isolated one-cycle native caller. Its config
// and state are required CLI arguments, never the installed daemon's defaults.
// It reads no daemon config/token/pause/socket and starts no service/watcher.
func RunIndexedCommand(ctx context.Context, configFile, stateDir string, output io.Writer) (err error) {
	started := time.Now()
	beforeMetrics := syncstate.CaptureMetricSnapshot()
	result := IndexedCommandResult{Schema: "pluto.copy-indexed-result/v1"}
	defer func() {
		if result.BatchResources != nil {
			copyResources.mu.Lock()
			*result.BatchResources = IndexedBatchResources{len(copyResources.workers), len(copyResources.readers), len(copyResources.enumerators), copyResources.spoolBytes, copyResources.retainedBytes, copyResources.metadataBytes}
			copyResources.mu.Unlock()
		}
		result.Capture = syncstate.CaptureMetricSnapshot().Since(beforeMetrics)
		result.WallMilliseconds = time.Since(started).Milliseconds()
		result.OK = err == nil
		if err != nil {
			result.Error = err.Error()
		}
		encoded := json.NewEncoder(output)
		err = errors.Join(err, encoded.Encode(result))
	}()
	cfg, e := readIndexedConfig(configFile)
	if e != nil {
		return e
	}
	x, e := OpenIndexedSession(ctx, cfg, stateDir, false)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, x.Close()) }()
	defer func() {
		result.SQL = x.Store.SQLStats()
		result.Disk, _ = x.Sources.DiskUsage(context.Background())
		result.HTTP = x.HTTP.Metrics()
	}()
	result.StartupArtifacts = x.StartupArtifacts
	if cfg.SmallBatchMode != "" {
		result.BatchResources = &IndexedBatchResources{}
	}
	result.Report, e = x.Cycle(ctx, nil, nil)
	return e
}
