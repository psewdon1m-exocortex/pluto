package pluto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFailedCopyAuditDoesNotReportSuccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := appendAudit(p, "copy.completed", map[string]any{"uploadedFiles": 3333, "success": false}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Outcome string `json:"outcome"`
	}
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Outcome != "failure" {
		t.Fatalf("failed copy reported %q", record.Outcome)
	}
}
