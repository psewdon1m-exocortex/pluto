//go:build linux

package pluto

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompletionRealOperatorBindingAdoptThroughNativeCLI(t *testing.T) {
	file := os.Getenv("COMPLETION_CONFIG")
	if file == "" {
		t.Fatal("owned API required")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var configs []struct {
		Kind, Origin, Authorization, DeviceID, BackendIdentity, Receipt string
		Binding                                                         map[string]any
		Namespace                                                       struct{ Codec, PolicyHash string }
	}
	if err = json.Unmarshal(raw, &configs); err != nil {
		t.Fatal(err)
	}
	c := configs[1]
	host := os.Getenv("COMPLETION_HOST_IP")
	if host == "" {
		host = "172.18.48.1"
	}
	origin, err := url.Parse(strings.ReplaceAll(c.Origin, "127.0.0.1", host))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	f := cNativeWithHandler(t, func(_ http.Handler) http.Handler { return proxy })
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
	if err = os.WriteFile(filepath.Join(f.source, "Агентность.md"), []byte("retained native adoption"), 0600); err != nil {
		t.Fatal(err)
	}
	stop := f.start()
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Published >= 1
	})
	stop(false)
	f.cfg.Enabled = false
	if err = SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(origin.String()+"__completion/adopt", "application/json", strings.NewReader(`{"kind":"pluto"}`))
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Binding map[string]any `json:"binding"`
		Receipt string         `json:"qualification_receipt_sha256"`
	}
	err = json.NewDecoder(response.Body).Decode(&artifact)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("operator adoption", response.StatusCode, err)
	}
	if artifact.Binding["binding_version"] == c.Binding["binding_version"] {
		t.Fatal("binding not rotated")
	}
	candidate := f.cfg.Indexed.Profile
	candidate.Remote.Binding = artifact.Binding
	candidate.Remote.QualificationReceiptSHA256 = artifact.Receipt
	candidate.Remote.Token = f.cfg.AccessToken
	profile := filepath.Join(f.base, "candidate.json")
	if err = SaveJSON(profile, candidate); err != nil {
		t.Fatal(err)
	}
	raw, err = f.command("migrate-plan", "--profile", profile)
	if err != nil {
		t.Fatal(string(raw), err)
	}
	var plan AdoptionPlan
	if err = json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	if !plan.Compatible || plan.Existing == nil || !plan.Existing.RequiresRebind || plan.Existing.Pending != 0 || plan.Existing.Acknowledged < 1 {
		t.Fatalf("ineligible adoption: %+v", plan)
	}
	if _, err = f.command("adopt", "--profile", profile, "--plan-digest", strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest admitted")
	}
	raw, err = f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest)
	if err != nil {
		t.Fatal(string(raw), err)
	}
	replay, err := f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest)
	if err != nil {
		t.Fatal(string(replay), err)
	}
	current, err := LoadConfig(f.config)
	if err != nil || current.Enabled || current.Indexed == nil || current.Indexed.Profile.Remote.Binding["binding_version"] != artifact.Binding["binding_version"] {
		t.Fatal("activation/pause", err)
	}
	if current.AccessToken != f.cfg.AccessToken {
		t.Fatal("credential changed")
	}
	raw, err = f.command("migrate-plan", "--profile", profile)
	if err != nil {
		t.Fatal(string(raw), err)
	}
	var after AdoptionPlan
	if err = json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if !after.Compatible || after.Existing == nil || after.Existing.RequiresRebind || after.Existing.Pending != 0 || after.Existing.Acknowledged != plan.Existing.Acknowledged {
		t.Fatal("retained originals lost", after)
	}
	if data, err := os.ReadFile(filepath.Join(f.source, "Агентность.md")); err != nil || string(data) != "retained native adoption" {
		t.Fatal("source changed", err)
	}
	evidence, _ := json.MarshalIndent(map[string]any{"before": plan, "after": after, "paused": true, "nativeCLI": true, "replayed": true}, "", "  ")
	if err = os.WriteFile(filepath.Join(filepath.Dir(file), "pluto-real-adoption.json"), evidence, 0600); err != nil {
		t.Fatal(err)
	}
}
