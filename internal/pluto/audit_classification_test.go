package pluto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCopyCompletionPersistsSafeFailureCategory(t *testing.T) {
	cases := []struct {
		name              string
		err               error
		outcome, category string
	}{
		{"success", nil, "success", ""},
		{"cancelled", fmt.Errorf("wrapped: %w", context.Canceled), "cancelled", "CANCELLED"},
		{"http429", &HTTPError{Status: 429, RetryAfter: 2 * time.Second, Message: "secret-token/private-path"}, "failure", "WAIT_CONNECTIVITY"},
		{"unclassified", errors.New("secret-token/private-path"), "failure", "UNCLASSIFIED_FAILURE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			fields := copyCompletionFields(17, c.err)
			if err := appendAudit(p, "copy.completed", fields); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "secret-token") || strings.Contains(string(raw), "private-path") {
				t.Fatal("raw error leaked")
			}
			var row struct {
				Outcome string         `json:"outcome"`
				Details map[string]any `json:"details"`
			}
			if err = json.Unmarshal(raw, &row); err != nil {
				t.Fatal(err)
			}
			if row.Outcome != c.outcome {
				t.Fatal(row)
			}
			if c.category != "" && row.Details["errorClass"] != c.category {
				t.Fatal(row)
			}
			if c.name == "http429" && (row.Details["httpStatus"] != float64(429) || row.Details["retryAfterMs"] != float64(2000)) {
				t.Fatal(row)
			}
		})
	}
}
