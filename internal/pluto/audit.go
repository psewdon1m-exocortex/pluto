package pluto

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Two bounded files; callers supply operational counters, never credential material.
func appendAudit(filename, event string, fields map[string]any) error {
	if info, err := os.Stat(filename); err == nil && info.Size() >= 512*1024 {
		if err = os.Remove(filename + ".previous"); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err = os.Rename(filename, filename+".previous"); err != nil {
			return err
		}
	}
	correlation := make([]byte, 16)
	if _, err := rand.Read(correlation); err != nil {
		return err
	}
	outcome := "success"
	if strings.Contains(event, "failed") {
		outcome = "failure"
	}
	actor := "pluto_agent"
	if event == "configuration.changed" {
		actor = "local_operator"
	}
	raw, err := json.Marshal(map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano), "actor": actor, "outcome": outcome, "correlation_id": hex.EncodeToString(correlation), "event": event, "details": fields})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return file.Sync()
}
