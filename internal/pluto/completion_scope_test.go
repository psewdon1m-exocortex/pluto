//go:build linux

package pluto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pluto/internal/pluto/syncstate"
)

// Real native CLI/daemon, owned Saturn/Postgres/SFTP, independently read bytes.
func TestCompletionNativeExcludeReincludePreservesCopies(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("COMPLETION_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	var configs []struct {
		Origin, Authorization, DeviceID, BackendIdentity, Receipt string
		Binding                                                   map[string]any
		Namespace                                                 struct{ Codec, PolicyHash string }
	}
	if err = json.Unmarshal(raw, &configs); err != nil {
		t.Fatal(err)
	}
	c := configs[1]
	host := os.Getenv("COMPLETION_HOST_IP")
	if host == "" {
		t.Fatal("explicit owned host required")
	}
	origin, err := url.Parse(strings.ReplaceAll(c.Origin, "127.0.0.1", host))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	f := cNativeWithHandler(t, func(http.Handler) http.Handler { return proxy })
	f.cfg.AccessToken = strings.TrimPrefix(c.Authorization, "Bearer ")
	f.cfg.Indexed.Policy.Codec = c.Namespace.Codec
	r := &f.cfg.Indexed.Profile.Remote
	r.Binding = c.Binding
	r.DeviceID = c.DeviceID
	r.BackendIdentity = c.BackendIdentity
	r.QualificationReceiptSHA256 = c.Receipt
	r.NameCodec = c.Namespace.Codec
	r.PolicyHash = c.Namespace.PolicyHash
	if err = SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{"edited.md": "before", "excluded.md": "before-excluded", "example (2).md": "legal duplicate name"}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.source, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range expected {
		write(name, content)
	}
	type entry struct{ Path, ID, Version, Sha256, CatalogSha256 string }
	client := &http.Client{Timeout: time.Minute}
	read := func(metadata bool) []entry {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"kind": "pluto", "folder": strings.TrimLeft(filepath.ToSlash(f.source), "/"), "metadataOnly": metadata})
		response, err := client.Post(origin.String()+"__completion/readback", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("readback", response.StatusCode)
		}
		var data struct{ Files []entry }
		if err = json.NewDecoder(response.Body).Decode(&data); err != nil {
			t.Fatal(err)
		}
		return data.Files
	}
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	wait := func() {
		t.Helper()
		until := time.Now().Add(3 * time.Minute)
		for {
			rows := read(true)
			ok := len(rows) == len(expected)
			for _, e := range rows {
				content, present := expected[e.Path]
				ok = ok && present && e.CatalogSha256 == hash(content)
			}
			if ok {
				return
			}
			if time.Now().After(until) {
				t.Fatal("scope convergence", rows, f.status())
			}
			time.Sleep(time.Second)
		}
	}
	verify := func() map[string]entry {
		t.Helper()
		rows := read(false)
		if len(rows) != len(expected) {
			t.Fatal("unexpected remote membership", rows)
		}
		out := map[string]entry{}
		for _, e := range rows {
			if e.Sha256 != hash(expected[e.Path]) || e.Sha256 != e.CatalogSha256 {
				t.Fatal("backend mismatch", e)
			}
			out[e.Path] = e
		}
		return out
	}
	stop := f.start()
	wait()
	before := verify()
	pause := func() {
		t.Helper()
		if raw, err := f.command("pause"); err != nil {
			t.Fatal(string(raw), err)
		}
		stop(false)
	}
	resume := func() {
		t.Helper()
		stop = f.start()
		if raw, err := f.command("resume"); err != nil {
			t.Fatal(string(raw), err)
		}
	}
	apply := func(revision int64, exclude bool) {
		t.Helper()
		cfg, err := LoadConfig(f.config)
		if err != nil {
			t.Fatal(err)
		}
		policy := cfg.Indexed.Policy
		policy.Revision = revision
		policy.Excludes = []string{}
		if exclude {
			policy.Excludes = []string{strings.TrimLeft(filepath.ToSlash(filepath.Join(f.source, "excluded.md")), "/")}
		}
		path := filepath.Join(f.base, "reviewed-policy.json")
		if err = SaveJSON(path, policy); err != nil {
			t.Fatal(err)
		}
		old, _ := os.ReadFile(f.config)
		raw, err := f.command("policy-plan", "--profile", path)
		if err != nil {
			t.Fatal(string(raw), err)
		}
		var plan syncstate.PolicyPreview
		if err = json.Unmarshal(raw, &plan); err != nil {
			t.Fatal(err)
		}
		if !plan.CopiesRetained || exclude && plan.NewlyExcluded != 1 || !exclude && plan.NewlyIncluded != 1 {
			t.Fatal("reviewed membership", plan)
		}
		if _, err = f.command("policy-apply", "--profile", path, "--plan-digest", strings.Repeat("0", 64)); err == nil {
			t.Fatal("stale digest accepted")
		}
		after, _ := os.ReadFile(f.config)
		if !bytes.Equal(old, after) {
			t.Fatal("preview/stale apply mutated config")
		}
		for i := 0; i < 2; i++ {
			raw, err = f.command("policy-apply", "--profile", path, "--plan-digest", plan.Digest)
			if err != nil {
				t.Fatal("apply/replay", string(raw), err)
			}
		}
	}
	pause()
	apply(2, true)
	write("excluded.md", "new-excluded")
	write("edited.md", "after")
	expected["edited.md"] = "after"
	resume()
	wait()
	// Wait until the admitted source work settles; an excluded publication may
	// not race a metadata-only early success and go unnoticed.
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
	})
	middle := verify()
	if middle["excluded.md"] != before["excluded.md"] || middle["example (2).md"] != before["example (2).md"] {
		t.Fatal("exclusion rewrote retained backups")
	}
	pause()
	apply(3, false)
	expected["excluded.md"] = "new-excluded"
	resume()
	wait()
	after := verify()
	pause()
	if after["excluded.md"].ID != before["excluded.md"].ID || after["example (2).md"] != before["example (2).md"] {
		t.Fatal("reinclude duplicated remote object")
	}
	files, err := os.ReadDir(f.source)
	if err != nil || len(files) != len(expected) {
		t.Fatal("unexpected local copies", err, len(files))
	}
	for name, content := range expected {
		data, err := os.ReadFile(filepath.Join(f.source, name))
		if err != nil || string(data) != content {
			t.Fatal("local source changed", name, err)
		}
	}
	if err = SaveJSON(filepath.Join(filepath.Dir(os.Getenv("COMPLETION_CONFIG")), "scope-readback.json"), map[string]any{"status": "PASS", "before": before, "excluded": middle, "reincluded": after, "localCopies": 0, "staleDigestRefused": true, "replayIdempotent": true}); err != nil {
		t.Fatal(err)
	}
}
