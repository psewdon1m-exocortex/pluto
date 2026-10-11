package pluto

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSourceChangesPreserveExistingPathsAndPersist(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old")
	added := filepath.Join(dir, "added")
	for _, name := range []string{old, added} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	apply := func(action string, paths ...string) {
		t.Helper()
		if err := s.Apply(context.Background(), Control{Action: action, Sources: paths}); err != nil {
			t.Fatal(err)
		}
	}
	apply("sources", old)
	// An old source can disappear temporarily. Adding another must keep it.
	if err := os.Remove(old); err != nil {
		t.Fatal(err)
	}
	apply("sources-add", added, added+"/.")
	apply("sources-add", added)
	want := []string{old, added}
	loaded, err := LoadConfig(s.ConfigPath)
	if err != nil || !reflect.DeepEqual(s.Status().Sources, want) || !reflect.DeepEqual(loaded.Sources, want) {
		t.Fatalf("addition lost or duplicated sources: %+v %v", loaded, err)
	}
	// Removing a missing source does not require access to the old path.
	apply("sources-remove", old)
	if !reflect.DeepEqual(s.Status().Sources, []string{added}) {
		t.Fatal("wrong source removed")
	}
	s.Config.Enabled = true
	apply("sources-remove", added)
	loaded, err = LoadConfig(s.ConfigPath)
	if err != nil || len(loaded.Sources) != 0 || loaded.Enabled || s.Status().Observation.Enabled {
		t.Fatalf("last removal did not disable copying: %+v %v", loaded, err)
	}
}

func TestInvalidOrConcurrentSourceChangesLeaveConfigurationUntouched(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Sources = []string{dir}
	for _, control := range []Control{
		{Action: "sources-add", Sources: []string{filepath.Join(dir, "missing")}},
		{Action: "sources-add"},
		{Action: "sources-remove", Sources: []string{"relative"}},
		{Action: "sources-remove"},
	} {
		if err := s.Apply(context.Background(), control); err == nil {
			t.Fatalf("accepted invalid control: %+v", control)
		}
		if !reflect.DeepEqual(s.Status().Sources, []string{dir}) {
			t.Fatal("failed change mutated sources")
		}
	}
	s.running = true
	for _, action := range []string{"sources", "sources-add", "sources-remove"} {
		if err := s.Apply(context.Background(), Control{Action: action, Sources: []string{dir}}); err == nil {
			t.Fatalf("changed sources during copy: %s", action)
		}
	}
	s.running = false
	s.ConfigPath = dir // Atomic save must fail without changing the live list.
	newPath := t.TempDir()
	if err := s.Apply(context.Background(), Control{Action: "sources-add", Sources: []string{newPath}}); err == nil {
		t.Fatal("ignored persistence failure")
	}
	if !reflect.DeepEqual(s.Status().Sources, []string{dir}) {
		t.Fatal("failed save changed live configuration")
	}
}

func TestSourceAdditionEnforcesCombinedLimit(t *testing.T) {
	current := make([]string, 128)
	for i := range current {
		current[i] = string(rune('a' + i))
	}
	if _, err := addSources(current, []string{t.TempDir()}); err == nil {
		t.Fatal("exceeded combined source limit")
	}
}

func TestRemovingFailedSourceClearsPersistedErrorAndQueuesFreshCopy(t *testing.T) {
	f := fixture(t)
	dir := t.TempDir()
	missing := filepath.Join(dir, "removed-source")
	healthy := filepath.Join(dir, "healthy.conf")
	if err := os.WriteFile(healthy, []byte("healthy"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.HTTP = f.server.Client()
	s.Config.Sources = []string{missing, healthy}
	s.Config.SaturnURL = f.server.URL
	s.Config.AccessToken = strings.Repeat("t", 43)
	s.Config.Enabled = true
	s.Observation.LastSuccessAt = "2026-10-10T18:35:54Z"
	if err := s.Apply(context.Background(), Control{Action: "run"}); err != nil {
		t.Fatal(err)
	}
	waitForCopy := func() {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for s.Status().Running && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if s.Status().Running {
			t.Fatal("copy did not finish")
		}
	}
	waitForCopy()
	before := s.Status().Observation
	if !strings.Contains(before.Error, missing) {
		t.Fatal("did not reproduce stale source failure", before.Error)
	}
	if err := s.Apply(context.Background(), Control{Action: "sources-remove", Sources: []string{missing}}); err != nil {
		t.Fatal(err)
	}
	after := s.Status().Observation
	if after.Error != "" || after.LastSuccessAt != before.LastSuccessAt || after.LastAttemptAt != before.LastAttemptAt || after.UploadedFiles != before.UploadedFiles {
		t.Fatalf("stale error or fabricated copy history: %+v", after)
	}
	next, err := time.Parse(time.RFC3339Nano, after.NextRunAt)
	if err != nil || next.After(time.Now()) {
		t.Fatal("new source list was not scheduled immediately", after.NextRunAt, err)
	}
	restarted, err := NewService(s.ConfigPath, s.StateDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Status().Observation.Error != "" || restarted.Status().Observation.LastSuccessAt != before.LastSuccessAt {
		t.Fatal("daemon restart restored obsolete error or lost history")
	}
	if err := s.Apply(context.Background(), Control{Action: "run"}); err != nil {
		t.Fatal(err)
	}
	waitForCopy()
	if s.Status().Observation.Error != "" || s.Status().Observation.LastSuccessAt == before.LastSuccessAt {
		t.Fatal("copy of remaining sources did not succeed")
	}
}

func TestSourceChangesKeepErrorsOnNoOpAndRejectedChanges(t *testing.T) {
	dir := t.TempDir()
	s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Sources = []string{dir}
	message := "1 source entries failed: " + dir + ": cannot be read"
	s.Observation.Error = message
	s.Observation.NextRunAt = "2030-01-01T00:00:00Z"
	for _, control := range []Control{
		{Action: "sources-add", Sources: []string{dir}},
		{Action: "sources-remove", Sources: []string{filepath.Join(dir, "not-selected")}},
		{Action: "sources", Sources: []string{dir}},
	} {
		if err := s.Apply(context.Background(), control); err != nil {
			t.Fatal(err)
		}
		if s.Status().Observation.Error != message || s.Status().Observation.NextRunAt != "" {
			// Disabled copying hides NextRunAt; the underlying schedule stays intact.
			t.Fatal("no-op changed error or visible schedule")
		}
		if s.Observation.NextRunAt != "2030-01-01T00:00:00Z" {
			t.Fatal("no-op rescheduled copying")
		}
	}
	for _, control := range []Control{
		{Action: "sources-add", Sources: []string{filepath.Join(dir, "missing")}},
		{Action: "sources-remove", Sources: []string{"relative"}},
	} {
		if err := s.Apply(context.Background(), control); err == nil {
			t.Fatal("accepted invalid change")
		}
		if s.Status().Observation.Error != message {
			t.Fatal("rejected change hid copy failure")
		}
	}
	s.ConfigPath = dir
	if err := s.Apply(context.Background(), Control{Action: "sources-remove", Sources: []string{dir}}); err == nil {
		t.Fatal("ignored config persistence failure")
	}
	if s.Status().Observation.Error != message {
		t.Fatal("failed config save cleared old error")
	}
}

func TestChangedSourcesPreserveOperationalErrorsAndReportStatusWriteFailure(t *testing.T) {
	for _, tc := range []struct{ before, after string }{
		{"Saturn access was revoked; obtain a new setup code", "Saturn access was revoked; obtain a new setup code"},
		{"remote request timed out; copying will retry", "remote request timed out; copying will retry"},
		{"Configuration persistence failed", "Configuration persistence failed"},
		{"1 source entries failed: /missing: inaccessible; local audit write failed; status persistence failed", "local audit write failed; status persistence failed"},
	} {
		t.Run(tc.before, func(t *testing.T) {
			dir := t.TempDir()
			s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
			if err != nil {
				t.Fatal(err)
			}
			s.Config.Sources = []string{dir}
			s.Observation.Error = tc.before
			if err := s.Apply(context.Background(), Control{Action: "sources-remove", Sources: []string{dir}}); err != nil {
				t.Fatal(err)
			}
			if s.Status().Observation.Error != tc.after {
				t.Fatalf("operational error hidden: %q", s.Status().Observation.Error)
			}
		})
	}
	dir := t.TempDir()
	s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Sources = []string{dir}
	s.Observation.Error = "1 source entries failed: /missing: inaccessible"
	if err := os.Mkdir(filepath.Join(dir, "status.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), Control{Action: "sources-remove", Sources: []string{dir}}); err == nil {
		t.Fatal("ignored status persistence failure")
	}
	if s.Status().Observation.Error != "status persistence failed" {
		t.Fatal("status write failure not visible", s.Status().Observation.Error)
	}
}
