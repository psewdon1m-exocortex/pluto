package pluto

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIndexedConfigProtectedBeforeAnyStateOrNetwork(t *testing.T) {
	for _, kind := range []string{"unknown", "duplicate", "schema", "permission", "symlink", "hardlink", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "config.json")
			state := filepath.Join(dir, "state")
			raw := []byte(`{"schema":"pluto.copy-indexed-isolated/v1","local_root_id":"local","mapping_id":"map","source_set_id":"set","sources":[],"remote":{}}`)
			switch kind {
			case "unknown":
				raw = []byte(`{"unknown":true}`)
			case "duplicate":
				raw = []byte(`{"schema":"a","schema":"b"}`)
			case "schema":
				raw = []byte(`{"schema":"legacy-daemon"}`)
			case "oversize":
				raw = bytes.Repeat([]byte(" "), (1<<20)+1)
			}
			if e := os.WriteFile(file, raw, 0600); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "permission":
				os.Chmod(file, 0644)
			case "symlink":
				other := filepath.Join(dir, "original")
				os.Rename(file, other)
				if e := os.Symlink(other, file); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(file, filepath.Join(dir, "second")); e != nil {
					t.Fatal(e)
				}
			}
			var output bytes.Buffer
			e := RunIndexedCommand(context.Background(), file, state, &output)
			if e == nil {
				t.Fatal("unsafe config accepted")
			}
			if _, e = os.Lstat(state); !os.IsNotExist(e) {
				t.Fatal("effects before config admission", e)
			}
			var result IndexedCommandResult
			if e = json.Unmarshal(output.Bytes(), &result); e != nil || result.OK {
				t.Fatal(output.String(), e)
			}
		})
	}
}
func TestIndexedProfileRejectsAliasPermissionsAndRelative(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private")
	if e := os.Mkdir(private, 0700); e != nil {
		t.Fatal(e)
	}
	if e := indexedPrivateProfile(private); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(dir, "alias")
	if e := os.Symlink(private, alias); e != nil {
		t.Fatal(e)
	}
	if e := indexedPrivateProfile(alias); e == nil {
		t.Fatal("symlink profile admitted")
	}
	os.Chmod(private, 0755)
	if e := indexedPrivateProfile(private); e == nil {
		t.Fatal("shared profile admitted")
	}
	if e := indexedPrivateProfile("relative"); e == nil {
		t.Fatal("relative profile admitted")
	}
}
