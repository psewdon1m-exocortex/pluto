package pluto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"pluto/internal/pluto/syncstate"
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
	if strings.Contains(event, "failed") || fields["success"] == false {
		outcome = "failure"
	}
	if fields["cancelled"] == true {
		outcome = "cancelled"
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

// Durable diagnostics intentionally exclude raw errors: HTTP messages and URLs
// may contain credentials or user data. Status and classified cause suffice
// to distinguish retries, cancellation and a product failure after a restart.
func copyCompletionFields(count int, err error) map[string]any {
	fields := map[string]any{"uploadedFiles": count, "success": err == nil}
	if err == nil {
		return fields
	}
	if errors.Is(err, context.Canceled) {
		fields["cancelled"] = true
		fields["errorClass"] = "CANCELLED"
		return fields
	}
	category := networkWaitState(err)
	if category == "" {
		if value, ok := syncstate.RetryClass(err); ok {
			category = value
		}
	}
	if category == "" {
		category = "UNCLASSIFIED_FAILURE"
	}
	fields["errorClass"] = category
	status := syncstate.HTTPStatus(err)
	var remote *HTTPError
	if errors.As(err, &remote) {
		status = remote.Status
	}
	if status != 0 {
		fields["httpStatus"] = status
	}
	if retry := networkRetryAfter(err); retry > 0 {
		fields["retryAfterMs"] = retry.Milliseconds()
	}
	return fields
}
