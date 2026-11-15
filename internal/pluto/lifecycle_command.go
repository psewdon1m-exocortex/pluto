package pluto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"pluto/internal/pluto/syncstate"
)

// Lifecycle commands do not start the daemon or turn on a feature implicitly.
// Source/config plans are read-only; adopt is bound to the exact printed digest.
func RunLifecycleCommand(ctx context.Context, action, configPath, stateDir, socket, profileFile, digest string, output io.Writer) error {
	encode := func(value any) error { return json.NewEncoder(output).Encode(value) }
	switch action {
	case "pause", "resume":
		var status Status
		err := (Remote{LocalClient(socket), "http://localhost", ""}).json(ctx, "POST", "/control", Control{Action: "enabled", Enabled: action == "resume"}, &status)
		if err != nil {
			return err
		}
		if action == "pause" {
			drain, stop := context.WithTimeout(ctx, 2*time.Minute)
			defer stop()
			for status.Running {
				select {
				case <-drain.Done():
					return errors.New("pause requested; drain has not completed")
				case <-time.After(200 * time.Millisecond):
				}
				if err = (Remote{LocalClient(socket), "http://localhost", ""}).json(drain, "GET", "/status", nil, &status); err != nil {
					return err
				}
			}
		}
		return encode(status)
	case "inspect", "diagnostics":
		if action == "diagnostics" {
			var live any
			if e := (Remote{LocalClient(socket), "http://localhost", ""}).json(ctx, "GET", "/diagnostics", nil, &live); e == nil {
				return encode(live)
			}
		}
		info, err := syncstate.InspectProfile(ctx, filepath.Join(stateDir, "indexed"))
		if err != nil {
			return err
		}
		return encode(info)
	case "checkpoint", "backup":
		var live any
		if e := (Remote{LocalClient(socket), "http://localhost", ""}).json(ctx, "POST", "/maintenance/"+action, nil, &live); e == nil {
			return encode(live)
		} else {
			var status *HTTPError
			if errors.As(e, &status) {
				return e
			}
		}
		release, lockErr := lifecycleLock(stateDir)
		if lockErr != nil {
			return lockErr
		}
		defer release()
		if _, err := os.Stat(filepath.Join(stateDir, "indexed", "sync-state.sqlite")); err != nil {
			return err
		}
		store, err := syncstate.Open(ctx, filepath.Join(stateDir, "indexed"))
		if err != nil {
			return err
		}
		defer store.Close()
		if action == "checkpoint" {
			if err = store.Checkpoint(ctx); err != nil {
				return err
			}
			return encode(map[string]any{"schema": "pluto.checkpoint.v1", "complete": true})
		}
		backup, err := store.Backup(ctx)
		if err != nil {
			return err
		}
		return encode(backup)
	case "migrate-plan", "adopt":
		c, err := LoadConfig(configPath)
		if err != nil {
			return err
		}
		candidate, err := readIndexedConfig(profileFile)
		if err != nil {
			return err
		}
		if action == "adopt" && c.Indexed != nil && c.Indexed.Activated {
			var marker struct {
				PlanDigest string `json:"planDigest"`
				RootID     string `json:"rootId"`
			}
			raw, e := os.ReadFile(filepath.Join(stateDir, "indexed-activation.json"))
			saved, requested := c.Indexed.Profile, candidate
			saved.Remote.Token = ""
			requested.Remote.Token = ""
			savedJSON, _ := json.Marshal(saved)
			requestedJSON, _ := json.Marshal(requested)
			if e == nil && json.Unmarshal(raw, &marker) == nil && digest != "" && marker.PlanDigest == digest && marker.RootID == candidate.LocalRootID && string(savedJSON) == string(requestedJSON) {
				return encode(map[string]any{"schema": "pluto.adoption.v1", "complete": true, "paused": !c.Enabled, "planDigest": digest})
			}
		}
		plan, err := inspectAdoption(ctx, stateDir, c, candidate)
		if err != nil {
			return err
		}
		if action == "migrate-plan" {
			return encode(plan)
		}
		journal := filepath.Join(stateDir, "indexed-adoption.json")
		resumeMatches := func(config Config) (bool, error) {
			raw, e := os.ReadFile(journal)
			if errors.Is(e, os.ErrNotExist) {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			var saved adoptionProgress
			if json.Unmarshal(raw, &saved) != nil {
				return false, syncstate.ErrIdentityConflict
			}
			return saved.Schema == "pluto.adoption-progress.v1" && saved.PlanDigest == digest && saved.InputDigest == adoptionInputDigest(config, candidate) && saved.Phase == "PREPARED", nil
		}
		continuing, err := resumeMatches(c)
		if err != nil {
			return err
		}
		if digest == "" || digest != plan.Digest && !continuing {
			return errors.New("adoption plan is stale or its digest was not supplied")
		}
		if c.Enabled {
			return errors.New("pause the profile before adopting indexed state")
		}
		release, err := lifecycleLock(stateDir)
		if err != nil {
			return err
		}
		defer release()
		// Recheck the read-only plan under the process lifecycle lock. A daemon
		// that stopped between planning and adoption may have committed an ACK.
		c, err = LoadConfig(configPath)
		if err != nil {
			return err
		}
		current, err := inspectAdoption(ctx, stateDir, c, candidate)
		if err != nil {
			return err
		}
		continuing, err = resumeMatches(c)
		if err != nil {
			return err
		}
		if current.Digest != digest && !continuing || c.Enabled {
			return errors.New("adoption plan changed; generate a new paused plan")
		}
		if !current.Compatible {
			// A failed first capability negotiation can leave BindRoot's legacy
			// default behind. Resume only the same reviewed PREPARED initialization,
			// never an activated profile or a state containing originals/imports.
			eligible := false
			if continuing && (c.Indexed == nil || !c.Indexed.Activated) && current.Existing != nil && current.Existing.Pending == 0 && current.Existing.Acknowledged == 0 && current.Existing.IncompatibleOriginals == 0 && !current.Existing.RequiresRebind && current.Existing.Remote == nil {
				store, e := syncstate.OpenReadOnly(ctx, filepath.Join(stateDir, "indexed"))
				if e != nil {
					return e
				}
				eligible, e = store.CanInitializePreparedPolicy(ctx, current.NewBinding, current.Codec)
				e = errors.Join(e, store.Close())
				if e != nil {
					return e
				}
			}
			if !eligible {
				return errors.New("existing binding or original operations are incompatible; retain and reconcile the original profile")
			}
		}
		adoption := adoptionProgress{"pluto.adoption-progress.v1", digest, adoptionInputDigest(c, candidate), "PREPARED"}
		if err = SaveJSON(journal, adoption); err != nil {
			return err
		}
		if current.Existing != nil {
			store, e := syncstate.Open(ctx, filepath.Join(stateDir, "indexed"))
			if e != nil {
				return e
			}
			_, e = store.Backup(ctx)
			if e == nil && current.Existing.RequiresRebind && current.Existing.Remote != nil {
				e = store.AuthorizeBindingTransition(ctx, candidate.LocalRootID, *current.Existing.Remote, current.RemoteBinding)
			}
			e = errors.Join(e, store.Close())
			if e != nil {
				return e
			}
		}
		// A live daemon must acknowledge pause/drain before the on-disk config is
		// replaced; adoption is an offline operation, checked by its admin socket.
		if entries, e := os.ReadDir(filepath.Join(stateDir, "spool")); e == nil && len(entries) > 0 {
			return errors.New("legacy spool is retained; reconcile it before adoption")
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		// A reviewed local plan does not establish remote authority. Qualify
		// the exact daemon credential/binding and import current remote state
		// while the lifecycle lease is still exclusive, before activation.
		qualified := candidate
		qualified.Remote.Token = c.AccessToken
		qualified.Remote.Proxy = c.Proxy
		if c.Indexed != nil && c.Indexed.Activated {
			qualified.Remote.NameCodec = c.Indexed.Policy.Codec
		}
		policy := SourcePolicy{Revision: 1, Codec: "legacy", Excludes: []string{}}
		if candidate.Remote.NameCodec != "" {
			policy.Codec = candidate.Remote.NameCodec
		}
		if c.Indexed != nil && c.Indexed.Activated {
			policy = c.Indexed.Policy
		}
		session, err := openIndexedSession(ctx, qualified, filepath.Join(stateDir, "indexed"), true, &policy)
		if err != nil {
			return err
		}
		if err = session.Close(); err != nil {
			return err
		}
		candidate.Remote.Token = "" // The original daemon credential remains authoritative.
		c.Indexed = &IndexedConfig{Activated: true, Profile: candidate, Policy: policy}
		if raw, e := json.MarshalIndent(c, "", "  "); e != nil {
			return e
		} else if len(raw) > 65536 {
			return errors.New("adopted configuration exceeds its 64 KiB bound")
		}
		progress := map[string]any{"schema": "pluto.indexed-activation.v1", "planDigest": digest, "rootId": candidate.LocalRootID, "minimumWriter": daemonWriterVersion, "phase": "PREPARED"}
		if err = SaveJSON(filepath.Join(stateDir, "indexed-activation.json"), progress); err != nil {
			return err
		}
		if err = SaveJSON(configPath, c); err != nil {
			return err
		}
		progress["phase"] = "COMPLETE"
		if err = SaveJSON(filepath.Join(stateDir, "indexed-activation.json"), progress); err != nil {
			return err
		}
		adoption.Phase = "COMPLETE"
		if err = SaveJSON(journal, adoption); err != nil {
			return err
		}
		return encode(map[string]any{"schema": "pluto.adoption.v1", "complete": true, "paused": true, "planDigest": digest})
	default:
		return errors.New("unknown lifecycle action")
	}
}

const daemonWriterVersion = 8

type adoptionProgress struct{ Schema, PlanDigest, InputDigest, Phase string }

func adoptionInputDigest(config Config, candidate IndexedCommandConfig) string {
	raw, _ := json.Marshal(struct {
		Config    Config
		Candidate IndexedCommandConfig
	}{config, candidate})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
