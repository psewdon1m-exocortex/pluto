package pluto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

type sourceRecoveryFixture struct {
	config, state, source string
	set                   syncstate.SourceSet
	binding               syncstate.SourceBinding
}

func newSourceRecoveryFixture(t *testing.T) sourceRecoveryFixture {
	t.Helper()
	ctx := context.Background()
	base := t.TempDir()
	f := sourceRecoveryFixture{config: filepath.Join(base, "config.json"), state: filepath.Join(base, "state"), source: filepath.Join(base, "source")}
	if err := os.Mkdir(f.source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.source, "original.bin"), []byte("original retained source"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := syncstate.Open(ctx, filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	sources, err := store.EnableSources(ctx, syncstate.DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnableArtifacts(ctx, syncstate.DefaultArtifactLimits()); err != nil {
		t.Fatal(err)
	}
	remote, err := store.EnableRemoteImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{"protocol": syncproto.Protocol, "descriptor_schema": syncproto.DescriptorSchema, "server_identity": "recovery-unit", "root_id": "00000000-0000-4000-8000-000000000001", "server_epoch": "00000000-0000-4000-8000-000000000002", "policy_version": "policy", "binding_version": "00000000-0000-4000-8000-000000000003"}
	root := syncstate.RootBinding{RootID: "root", MappingID: "mapping", ServerIdentity: "recovery-unit", RemoteRootID: binding["root_id"].(string), DeviceID: "00000000-0000-4000-8000-000000000004", SourceIdentity: "set"}
	if err = store.BindRoot(ctx, root); err != nil {
		t.Fatal(err)
	}
	// Initialize the existing HTTP association module through its public,
	// non-negotiating isolated constructor. No request is sent by this fixture.
	httpSession, err := syncstate.NewIsolatedHTTPSession(ctx, remote, root.RootID, syncstate.IsolatedHTTPConfig{Domain: syncstate.IsolatedHTTPContract, Origin: "https://127.0.0.1:65534", AllowedAddresses: []string{"127.0.0.1"}, Binding: binding, DeviceID: root.DeviceID, BackendIdentity: "fixture-backend", QualificationReceiptSHA256: strings.Repeat("b", 64), Token: "fixture-credential"})
	if err != nil {
		t.Fatal("HTTP association fixture", err)
	}
	httpSession.Close()
	if err = remote.EnableDaemonState(ctx); err != nil {
		t.Fatal("daemon fixture migration", err)
	}
	specs := []syncstate.SourceSpec{{ID: "source", SelectedPath: f.source}}
	projection, _ := json.Marshal(specs)
	projectionHash := sha256.Sum256(projection)
	set, err := sources.BindSourceSet(ctx, "set", hex.EncodeToString(projectionHash[:]), 0, specs)
	if err != nil {
		t.Fatal(err)
	}
	if err = sources.AttachSourceSet(ctx, set.ID, set.Revision, root.RootID); err != nil {
		t.Fatal(err)
	}
	w, err := sources.BeginSourceOwner(ctx, set.ID, set.Revision, "fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	observation, err := syncstate.ObserveSourceIncarnation(f.source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sources.RecordSourceIncarnation(ctx, w, "source", observation); err != nil {
		t.Fatal(err)
	}
	f.binding, err = sources.Binding(ctx, set.ID, "source")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate only an earlier boot identity in a disposable SQL fixture. This
	// is not a native reboot claim; the original P8 remount is tested separately.
	f.binding.Object.BootIdentity = "previous-boot-identity"
	f.binding.PendingObject = observation.Object()
	f.binding.IncarnationStatus = "UNKNOWN"
	raw, _ := json.Marshal(f.binding)
	db, err := sql.Open("sqlite", filepath.Join(f.state, "indexed", "sync-state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE source_bindings SET descriptor_json=? WHERE set_id='set' AND source_id='source'", string(raw)); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.Enabled = false
	c.Sources = []string{f.source}
	c.SaturnURL = "https://127.0.0.1:65534"
	c.AccessToken = "fixture-credential"
	c.Indexed = &IndexedConfig{Activated: true, Policy: SourcePolicy{Revision: 1, Codec: "legacy", Excludes: []string{}}, Profile: IndexedCommandConfig{Schema: IndexedProfileSchema, LocalRootID: root.RootID, MappingID: root.MappingID, SourceSetID: set.ID, Sources: []IndexedSourceConfig{{ID: "source", SelectedPath: f.source}}, Remote: syncstate.IsolatedHTTPConfig{Domain: syncstate.DaemonHTTPContract, Origin: c.SaturnURL, DeviceID: root.DeviceID, Binding: binding}}}
	if err = SaveJSON(f.config, c); err != nil {
		t.Fatal(err)
	}
	s, err := syncstate.OpenReadOnly(ctx, filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	ss, err := s.EnableSources(ctx, syncstate.DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	f.set, err = ss.Set(ctx, "set")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return f
}

func sourceRecoveryDigest(t *testing.T, f sourceRecoveryFixture) SourceRecoveryPlan {
	t.Helper()
	var out bytes.Buffer
	if err := RunSourceRecoveryCommand(context.Background(), "source-recover-plan", f.config, f.state, "source", "", &out); err != nil {
		t.Fatal(err)
	}
	var plan SourceRecoveryPlan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestSourceRecoveryReviewedPlanPreservesSourceAuthorityAndGap(t *testing.T) {
	f := newSourceRecoveryFixture(t)
	beforeConfig, _ := os.ReadFile(f.config)
	beforeSource, _ := os.ReadFile(filepath.Join(f.source, "original.bin"))
	plan := sourceRecoveryDigest(t, f)
	if !plan.FullGuardedScanRequired || plan.Source.IncarnationStatus != "UNKNOWN" {
		t.Fatal(plan)
	}
	if again := sourceRecoveryDigest(t, f); again.Digest != plan.Digest {
		t.Fatal("readonly plan changed its own inputs")
	}
	var out bytes.Buffer
	if err := RunSourceRecoveryCommand(context.Background(), "source-recover-apply", f.config, f.state, "source", plan.Digest, &out); err != nil {
		t.Fatal(err)
	}
	var receipt SourceRecoveryReceipt
	if err := json.Unmarshal(out.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.FullGuardedScanRequired || receipt.Incarnation != plan.Source.Incarnation+1 || receipt.PlanDigest != plan.Digest {
		t.Fatal(receipt)
	}
	backup, err := os.ReadFile(filepath.Join(f.state, "indexed", "sync-state-backups", receipt.Backup.Filename))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(backup)
	if hex.EncodeToString(hash[:]) != receipt.Backup.SHA256 {
		t.Fatal("backup hash")
	}
	ctx := context.Background()
	store, err := syncstate.OpenReadOnly(ctx, filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sources, err := store.EnableSources(ctx, syncstate.DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.Root(ctx, "root")
	if err != nil || root != plan.Root {
		t.Fatal("remote authority/trust changed", root, err)
	}
	set, err := sources.Set(ctx, "set")
	if err != nil || set.GapGeneration <= plan.Set.GapGeneration || set.ConfigDigest != plan.Set.ConfigDigest {
		t.Fatal("gap lost or config changed", set, err)
	}
	b, err := sources.Binding(ctx, "set", "source")
	if err != nil || b.Object != plan.Observed || b.IncarnationStatus != "LOCAL_OBSERVED" || b.PendingObject != (syncstate.SourceObject{}) {
		t.Fatal(b, err)
	}
	config, _ := os.ReadFile(f.config)
	source, _ := os.ReadFile(filepath.Join(f.source, "original.bin"))
	if !bytes.Equal(config, beforeConfig) || !bytes.Equal(source, beforeSource) {
		t.Fatal("source or configuration changed")
	}
}

func TestSourceRecoveryRefusesStalePlanWithoutOwnerAdmission(t *testing.T) {
	f := newSourceRecoveryFixture(t)
	plan := sourceRecoveryDigest(t, f)
	c, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	c.IntervalSeconds++
	if err = SaveJSON(f.config, c); err != nil {
		t.Fatal(err)
	}
	if err = RunSourceRecoveryCommand(context.Background(), "source-recover-apply", f.config, f.state, "source", plan.Digest, &bytes.Buffer{}); err == nil {
		t.Fatal("stale config accepted")
	}
	ctx := context.Background()
	store, err := syncstate.OpenReadOnly(ctx, filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sources, _ := store.EnableSources(ctx, syncstate.DefaultSourceLimits())
	set, err := sources.Set(ctx, "set")
	if err != nil || !reflect.DeepEqual(set, f.set) {
		t.Fatal("refusal admitted a new owner", set, err)
	}
}

func TestSourceRecoveryRefusesRetainedOriginalArtifacts(t *testing.T) {
	f := newSourceRecoveryFixture(t)
	db, err := sql.Open("sqlite", filepath.Join(f.state, "indexed", "sync-state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO local_artifacts(artifact_id,filename,phase,expected_bytes) VALUES('retained-original','immutable-original','RESERVED',1)")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	err = RunSourceRecoveryCommand(context.Background(), "source-recover-plan", f.config, f.state, "source", "", &bytes.Buffer{})
	if !errors.Is(err, syncstate.ErrArtifactRetained) {
		t.Fatal("retained original accepted", err)
	}
}

func TestSourceRecoveryRefusesReplacedSourceDirectory(t *testing.T) {
	f := newSourceRecoveryFixture(t)
	plan := sourceRecoveryDigest(t, f)
	if err := os.Rename(f.source, f.source+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RunSourceRecoveryCommand(context.Background(), "source-recover-apply", f.config, f.state, "source", plan.Digest, &bytes.Buffer{}); err == nil {
		t.Fatal("replaced root accepted")
	}
}

func TestSourceRecoveryRefusesChangedConfiguredSourceWithSameID(t *testing.T) {
	f := newSourceRecoveryFixture(t)
	c, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	c.Sources = []string{f.source + "-different"}
	if err = os.Mkdir(c.Sources[0], 0700); err != nil {
		t.Fatal(err)
	}
	c.Indexed.Profile.Sources[0].SelectedPath = c.Sources[0]
	if err = SaveJSON(f.config, c); err != nil {
		t.Fatal(err)
	}
	err = RunSourceRecoveryCommand(context.Background(), "source-recover-plan", f.config, f.state, "source", "", &bytes.Buffer{})
	if !errors.Is(err, syncstate.ErrIdentityConflict) {
		t.Fatal("source config changed without its store projection", err)
	}
}

func TestSourceRecoveryReviewsPendingMountFromStoppedContainer(t *testing.T) {
	f := newSourceRecoveryFixture(t)
	db, err := sql.Open("sqlite", filepath.Join(f.state, "indexed", "sync-state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	f.binding.PendingObject.MountID = "900000000000001"
	raw, _ := json.Marshal(f.binding)
	if _, err = db.Exec("UPDATE source_bindings SET descriptor_json=? WHERE set_id='set' AND source_id='source'", string(raw)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	plan := sourceRecoveryDigest(t, f)
	if plan.Observed.MountID == plan.Source.PendingObject.MountID {
		t.Fatal("fixture must represent a later operator container")
	}
	var out bytes.Buffer
	if err = RunSourceRecoveryCommand(context.Background(), "source-recover-apply", f.config, f.state, "source", plan.Digest, &out); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := syncstate.OpenReadOnly(ctx, filepath.Join(f.state, "indexed"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sources, err := store.EnableSources(ctx, syncstate.DefaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	set, err := sources.Set(ctx, "set")
	if err != nil || set.GapGeneration != plan.Set.GapGeneration+2 {
		t.Fatal("owner and pending-mount gaps must remain", set, err)
	}
	b, err := sources.Binding(ctx, "set", "source")
	if err != nil || b.Object != plan.Observed || b.Incarnation != plan.Source.Incarnation+1 {
		t.Fatal(b, err)
	}
}

func TestSourceRecoveryRefusesAnotherPendingIncarnation(t *testing.T) {
	for _, field := range []string{"boot", "file", "link", "mount-unknown"} {
		t.Run(field, func(t *testing.T) {
			f := newSourceRecoveryFixture(t)
			switch field {
			case "boot":
				f.binding.PendingObject.BootIdentity = "another-current-boot"
			case "file":
				f.binding.PendingObject.FileIdentity = "1:2:3"
			case "link":
				f.binding.PendingObject.LinkGuard = "another-link"
			case "mount-unknown":
				f.binding.PendingObject.MountKnown = false
			}
			db, err := sql.Open("sqlite", filepath.Join(f.state, "indexed", "sync-state.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(f.binding)
			if _, err = db.Exec("UPDATE source_bindings SET descriptor_json=? WHERE set_id='set' AND source_id='source'", string(raw)); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if err = RunSourceRecoveryCommand(context.Background(), "source-recover-plan", f.config, f.state, "source", "", &bytes.Buffer{}); err == nil {
				t.Fatal("different pending incarnation accepted")
			}
		})
	}
}
