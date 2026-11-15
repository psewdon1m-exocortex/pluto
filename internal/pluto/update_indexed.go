package pluto

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"pluto/internal/pluto/syncstate"
)

// This is a read-only binary compatibility declaration, not root authority.
func IndexedWriterCompatibility() map[string]any {
	return map[string]any{"schema": "pluto.writer-compatibility.v1", "maximumStateSchema": daemonWriterVersion, "activationFence": true}
}

func requireIndexedWriter(ctx context.Context, candidate, state string) error {
	minimum := 0
	if _, err := os.Lstat(filepath.Join(state, "indexed-activation.json")); err == nil {
		minimum = daemonWriterVersion
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(state, "indexed", "sync-state.sqlite")); err == nil {
		inspection, e := syncstate.InspectProfile(ctx, filepath.Join(state, "indexed"))
		if e != nil {
			return e
		}
		minimum = max(minimum, inspection.SchemaVersion)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if minimum == 0 {
		return nil
	}
	command, cancel := boundedReadOnlyCommand(ctx, candidate, "--writer-schema")
	defer cancel()
	stdout, stderr := &boundedCommandOutput{maximum: 1024, onExceeded: cancel}, &boundedCommandOutput{maximum: 4096, onExceeded: cancel}
	command.Stdout = stdout
	command.Stderr = stderr
	var declaration struct {
		Schema  string `json:"schema"`
		Maximum int    `json:"maximumStateSchema"`
		Fence   bool   `json:"activationFence"`
	}
	if command.Run() != nil || json.Unmarshal(stdout.Bytes(), &declaration) != nil || declaration.Schema != "pluto.writer-compatibility.v1" || !declaration.Fence || declaration.Maximum < minimum {
		return errors.New("binary cannot read activated indexed state; retain the update journal and reconcile without resetting the profile")
	}
	return nil
}

func requireInstalledRollback(executable, candidate string) error {
	if executable != "/usr/local/bin/pluto" {
		return nil
	} // Other paths are isolated installer compositions.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return requireIndexedWriter(ctx, candidate, "/var/lib/pluto")
}

func waitUpdateDrain(ctx context.Context, local Remote) error {
	drain, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		var status Status
		if err := local.json(drain, "GET", "/status", nil, &status); err != nil {
			return err
		}
		if !status.Running {
			return nil
		}
		select {
		case <-drain.Done():
			return errors.New("update is quiesced but indexed drain has not completed")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
