package pluto

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
