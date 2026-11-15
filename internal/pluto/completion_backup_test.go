//go:build linux

package pluto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCompletionNativeBackupVersionsDeletionAndSizeBoundaries(t *testing.T) {
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
		t.Fatal("owned host required")
	}
	origin, err := url.Parse(strings.ReplaceAll(c.Origin, "127.0.0.1", host))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	f := cNativeWithHandler(t, func(_ http.Handler) http.Handler { return proxy })
	f.source = filepath.Join(f.base, "backup-boundaries-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err = os.Mkdir(f.source, 0700); err != nil {
		t.Fatal(err)
	}
	f.cfg.Sources = []string{f.source}
	f.cfg.Indexed.Profile.Sources[0].SelectedPath = f.source
	f.cfg.AccessToken = strings.TrimPrefix(c.Authorization, "Bearer ")
	f.cfg.Indexed.Policy.Codec = c.Namespace.Codec
	remote := &f.cfg.Indexed.Profile.Remote
	remote.Binding = c.Binding
	remote.DeviceID = c.DeviceID
	remote.BackendIdentity = c.BackendIdentity
	remote.QualificationReceiptSHA256 = c.Receipt
	remote.NameCodec = c.Namespace.Codec
	remote.PolicyHash = c.Namespace.PolicyHash
	if err = SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	output := filepath.Dir(os.Getenv("COMPLETION_CONFIG"))
	t.Cleanup(func() {
		if t.Failed() {
			if b, e := f.processes.RunReviewedAuxiliaryCopy("source-sparse", f.source, filepath.Join(output, "pluto-backup-failure-source")); e != nil {
				t.Log(string(b), e)
			}
		}
	})
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	fileHash := func(p string) string {
		t.Helper()
		r, e := os.Open(p)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Close()
		h := sha256.New()
		if _, e = io.Copy(h, r); e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	type version struct {
		ID, State, Sha256, CatalogSha256, Size string
		Exists                                 bool
	}
	type entry struct {
		Path, ID, Version, Sha256, CatalogSha256, CatalogSize string
		Size                                                  int64
		VersionCount                                          int
		Versions                                              []version
	}
	type snapshot struct {
		Files   []entry
		Folders []string
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	read := func(metadata, versions bool) snapshot {
		t.Helper()
		input, _ := json.Marshal(map[string]any{"kind": "pluto", "folder": strings.TrimLeft(filepath.ToSlash(f.source), "/"), "metadataOnly": metadata, "includeVersions": versions})
		r, e := client.Post(origin.String()+"__completion/readback", "application/json", bytes.NewReader(input))
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("oracle status %d", r.StatusCode)
		}
		var s snapshot
		if e = json.NewDecoder(r.Body).Decode(&s); e != nil {
			t.Fatal(e)
		}
		return s
	}
	wait := func(stage string, predicate func(snapshot) bool) snapshot {
		t.Helper()
		until := time.Now().Add(5 * time.Minute)
		last := ""
		for {
			s := read(true, true)
			b, _ := json.Marshal(s)
			fingerprint := hash(b)
			if fingerprint != last {
				until = time.Now().Add(5 * time.Minute)
				last = fingerprint
				t.Logf("%s metadata progress files=%d", stage, len(s.Files))
			}
			if predicate(s) {
				return s
			}
			if time.Now().After(until) {
				status, _ := json.Marshal(f.status())
				_ = os.WriteFile(filepath.Join(output, "pluto-backup-timeout.json"), status, 0600)
				t.Fatalf("%s no progress", stage)
			}
			time.Sleep(time.Second)
		}
	}
	history := filepath.Join(f.source, "history.md")
	versions := map[string]int{}
	if err = os.WriteFile(history, []byte("revision-01"), 0600); err != nil {
		t.Fatal(err)
	}
	versions[hash([]byte("revision-01"))] = 1
	stop := f.start()
	var historyID string
	first := wait("revision-1", func(s snapshot) bool {
		return len(s.Files) == 1 && s.Files[0].CatalogSha256 == hash([]byte("revision-01")) && s.Files[0].VersionCount == 1
	})
	historyID = first.Files[0].ID
	for n := 2; n <= 13; n++ {
		payload := []byte(fmt.Sprintf("revision-%02d", n))
		versions[hash(payload)] = n
		if err = os.WriteFile(history, payload, 0600); err != nil {
			t.Fatal(err)
		}
		s := wait(fmt.Sprintf("revision-%d", n), func(s snapshot) bool {
			return len(s.Files) == 1 && s.Files[0].CatalogSha256 == hash(payload) && s.Files[0].VersionCount == n
		})
		if s.Files[0].ID != historyID {
			t.Fatal("revision changed resource identity")
		}
	}
	wait("retention10", func(s snapshot) bool {
		if len(s.Files) != 1 {
			return false
		}
		active, expired := 0, 0
		for _, v := range s.Files[0].Versions {
			if v.State == "active" && v.Exists {
				active++
			}
			if v.State == "expired" && !v.Exists {
				expired++
			}
		}
		return active == 10 && expired == 3
	})
	retained := read(false, true)
	if len(retained.Files) != 1 || retained.Files[0].Sha256 != hash([]byte("revision-13")) {
		t.Fatal("current backup SHA")
	}
	for _, v := range retained.Files[0].Versions {
		n, ok := versions[v.CatalogSha256]
		if !ok {
			t.Fatal("unknown version bytes")
		}
		if n <= 3 {
			if v.State != "expired" || v.Exists {
				t.Fatal("expired archive still accessible")
			}
		} else if v.State != "active" || !v.Exists || v.Sha256 != v.CatalogSha256 {
			t.Fatal("retained version SHA")
		}
	}
	if _, err = f.command("pause"); err != nil {
		t.Fatal(err)
	}
	stop(false)
	if err = os.Remove(history); err != nil {
		t.Fatal(err)
	}
	stop = f.start()
	resumedAt := time.Now()
	if _, err = f.command("resume"); err != nil {
		t.Fatal(err)
	}
	cAwait(t, func() bool {
		s := f.status()
		at, _ := time.Parse(time.RFC3339Nano, s.Observation.LastSuccessAt)
		return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing" && at.After(resumedAt)
	})
	preserved := read(false, true)
	a, _ := json.Marshal(retained)
	b, _ := json.Marshal(preserved)
	if !bytes.Equal(a, b) {
		t.Fatal("source deletion altered backup history")
	}
	if _, err = os.Stat(history); !os.IsNotExist(err) {
		t.Fatal("deleted local file recreated")
	}
	expected := map[string]string{"history.md": hash([]byte("revision-13"))}
	sizes := map[string]int64{"history.md": int64(len("revision-13"))}
	localExpected := map[string]string{}
	for _, delta := range []int64{-1, 0, 1} {
		name := fmt.Sprintf("boundary-%d.bin", delta)
		size := MaxFileBytes + delta
		p := filepath.Join(f.source, name)
		w, e := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if e = w.Truncate(size); e == nil {
			_, e = w.WriteAt([]byte(name), 0)
		}
		if e == nil {
			_, e = w.WriteAt([]byte("last-byte-proof"), size-15)
		}
		closeErr := w.Close()
		if e != nil || closeErr != nil {
			t.Fatal(e, closeErr)
		}
		h := fileHash(p)
		localExpected[name] = h
		if delta <= 0 {
			expected[name] = h
			sizes[name] = size
		}
	}
	wait("size-boundaries", func(s snapshot) bool {
		if len(s.Files) != 3 {
			return false
		}
		for _, e := range s.Files {
			if expected[e.Path] != e.CatalogSha256 || strconv.FormatInt(sizes[e.Path], 10) != e.CatalogSize {
				return false
			}
		}
		return true
	})
	// Oversized input is an explicit partial failure. Require a fresh failed
	// observation after restart rather than incorrectly demanding all-success.
	if _, err = f.command("pause"); err != nil {
		t.Fatal(err)
	}
	stop(false)
	stop = f.start()
	resumedAt = time.Now()
	if _, err = f.command("resume"); err != nil {
		t.Fatal(err)
	}
	// Resume preserves the ordinary persisted 60-second schedule. The small
	// helper's 45-second startup deadline cannot prove a fresh scheduled scan.
	refusalDeadline := time.Now().Add(100 * time.Second)
	for {
		s := f.status()
		at, _ := time.Parse(time.RFC3339Nano, s.Observation.LastAttemptAt)
		if s.Observation.Engine != nil && s.Observation.Engine.Phase == "reconciliation_required" && s.Observation.Engine.Failed == 1 && at.After(resumedAt) {
			break
		}
		if time.Now().After(refusalDeadline) {
			t.Fatalf("fresh oversized refusal: %+v", s)
		}
		time.Sleep(100 * time.Millisecond)
	}
	refused := f.status()
	final := read(false, false)
	if len(final.Files) != 3 {
		t.Fatal("oversized file published or backup missing")
	}
	for _, e := range final.Files {
		if expected[e.Path] != e.Sha256 || e.Sha256 != e.CatalogSha256 || e.Size != sizes[e.Path] {
			t.Fatal("boundary readback mismatch", e.Path)
		}
	}
	entries, e := os.ReadDir(f.source)
	if e != nil || len(entries) != 3 {
		t.Fatal("local source copies", e, len(entries))
	}
	for _, e := range entries {
		if fileHash(filepath.Join(f.source, e.Name())) != localExpected[e.Name()] {
			t.Fatal("local source mutated")
		}
	}
	// Only shrink the refused source, then require ordinary recovery without
	// resetting profile, binding, baseline or any pending original. This also
	// distinguishes the expected policy refusal from an unrelated fatal error.
	healthy := []byte("oversized source corrected by user")
	if err = os.WriteFile(filepath.Join(f.source, "boundary-1.bin"), healthy, 0600); err != nil {
		t.Fatal(err)
	}
	localExpected["boundary-1.bin"] = hash(healthy)
	expected["boundary-1.bin"] = hash(healthy)
	sizes["boundary-1.bin"] = int64(len(healthy))
	wait("size-policy-recovery", func(s snapshot) bool {
		if len(s.Files) != 4 {
			return false
		}
		for _, e := range s.Files {
			if expected[e.Path] != e.CatalogSha256 {
				return false
			}
		}
		return true
	})
	recovered := read(false, true)
	for _, e := range recovered.Files {
		if e.Sha256 != expected[e.Path] || e.Size != sizes[e.Path] {
			t.Fatal("recovery SHA", e.Path)
		}
		if e.Path != "history.md" && e.VersionCount != 1 {
			t.Fatal("boundary duplicate publication", e.Path)
		}
	}
	stop(false)
	evidence, _ := json.MarshalIndent(map[string]any{"status": "PASS", "maximumFileBytes": MaxFileBytes, "versions": retained, "sourceDeletionRetained": true, "boundaries": final, "localManifest": localExpected, "oversizedRefusedAfterRestart": true, "refusal": refused, "recoveredAfterShrink": recovered}, "", "  ")
	if err = os.WriteFile(filepath.Join(output, "pluto-backup-boundaries.json"), evidence, 0600); err != nil {
		t.Fatal(err)
	}
}
