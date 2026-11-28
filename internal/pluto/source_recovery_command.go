package pluto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

// A reviewed operator may accept a new local incarnation after a host reboot or
// filesystem remount. This does not prove continuity, recover a remote baseline,
// acknowledge an original, or clear a gap. The ordinary complete guarded scan
// remains mandatory. Ordinary daemon startup retains its fail-closed behavior.
type SourceRecoveryPlan struct {
	Schema, Digest, ConfigSHA256 string
	Root                         syncstate.Root
	Set                          syncstate.SourceSet
	Source                       syncstate.SourceBinding
	Observed                     syncstate.SourceObject
	Inspection                   syncstate.ProfileInspection
	FullGuardedScanRequired      bool
}

type SourceRecoveryReceipt struct {
	Schema, PlanDigest, ConfigSHA256 string
	RootID, SourceID                 string
	Previous, Current                syncstate.SourceObject
	Incarnation                      int64
	Backup                           syncstate.ProfileBackup
	FullGuardedScanRequired          bool
}

func sourceRecoveryPath(filename string) error {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return syncstate.ErrIdentityConflict
	}
	for p := filename; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return syncstate.ErrIdentityConflict
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

func sourceRecoveryObject(before, observed syncstate.SourceObject) bool {
	// Device numbers and boot/mount IDs are ephemeral. An explicit plan still
	// requires the same directory inode and mode and an actually observed change.
	// This is local admission only, never a claim of original content continuity.
	a, b := strings.Split(before.FileIdentity, ":"), strings.Split(observed.FileIdentity, ":")
	if len(a) != 3 || len(b) != 3 || before == observed || a[1] != b[1] || a[2] != b[2] ||
		!before.MountKnown || !observed.MountKnown || before.BootIdentity == "" || observed.BootIdentity == "" ||
		before.MountID == "" || observed.MountID == "" || before.LinkGuard == "" || observed.LinkGuard == "" {
		return false
	}
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if parsed, err := strconv.ParseUint(value, 10, 64); err != nil || parsed == 0 {
				return false
			}
		}
	}
	return a[0] != b[0] || before.BootIdentity != observed.BootIdentity
}

func sourceRecoveryPlan(ctx context.Context, store *syncstate.Store, sources *syncstate.Sources, c Config, configSHA, sourceID, directory string) (SourceRecoveryPlan, syncstate.SourceIncarnationObservation, error) {
	var plan SourceRecoveryPlan
	var observed syncstate.SourceIncarnationObservation
	profile, err := daemonProfile(c)
	if err != nil {
		return plan, observed, err
	}
	configured := false
	specs := make([]syncstate.SourceSpec, 0, len(profile.Sources))
	for _, spec := range profile.Sources {
		specs = append(specs, syncstate.SourceSpec{ID: spec.ID, SelectedPath: spec.SelectedPath, WorkingDirectory: spec.WorkingDirectory})
		if spec.ID == sourceID {
			configured = true
		}
	}
	if !configured {
		return plan, observed, syncstate.ErrIdentityConflict
	}
	set, err := sources.Set(ctx, profile.SourceSetID)
	if err != nil || set.AttachedRootID != profile.LocalRootID {
		return plan, observed, errors.Join(syncstate.ErrIdentityConflict, err)
	}
	projection, err := json.Marshal(specs)
	if err != nil {
		return plan, observed, err
	}
	projectionHash := sha256.Sum256(projection)
	if hex.EncodeToString(projectionHash[:]) != set.ConfigDigest {
		return plan, observed, syncstate.ErrIdentityConflict
	}
	root, err := store.Root(ctx, profile.LocalRootID)
	if err != nil {
		return plan, observed, err
	}
	binding, err := syncproto.ReadBinding(profile.Remote.Binding)
	if err != nil || root.RootBinding != (syncstate.RootBinding{RootID: profile.LocalRootID, MappingID: profile.MappingID, ServerIdentity: binding.ServerIdentity, RemoteRootID: binding.RootID, DeviceID: profile.Remote.DeviceID, SourceIdentity: profile.SourceSetID}) {
		return plan, observed, errors.Join(syncstate.ErrIdentityConflict, err)
	}
	source, err := sources.Binding(ctx, set.ID, sourceID)
	if err != nil || !source.Active || source.Revision != set.Revision || source.IncarnationStatus != "UNKNOWN" {
		return plan, observed, errors.Join(syncstate.ErrSourceIncomplete, err)
	}
	if err = sourceRecoveryPath(source.PhysicalPath); err != nil {
		return plan, observed, err
	}
	observed, err = syncstate.ObserveSourceIncarnation(source.PhysicalPath)
	if err != nil {
		return plan, observed, err
	}
	second, err := syncstate.ObserveSourceIncarnation(source.PhysicalPath)
	if err != nil || observed.Object() != second.Object() || !observed.MatchesPendingIncarnation(source.PendingObject) || !sourceRecoveryObject(source.Object, observed.Object()) {
		return plan, observed, errors.Join(syncstate.ErrCaptureChanged, err)
	}
	inspection, err := syncstate.InspectProfile(ctx, directory)
	if err != nil {
		return plan, observed, err
	}
	if inspection.SchemaVersion != 8 {
		return plan, observed, syncstate.ErrUnsupportedSchema
	}
	if inspection.PendingOperations != 0 || inspection.RetainedArtifacts != 0 || inspection.RetainedStreams != 0 || inspection.UnmatchedRebindings != 0 || len(inspection.RetryStates) != 0 {
		return plan, observed, syncstate.ErrArtifactRetained
	}
	for phase, count := range inspection.BindingTransitions {
		if phase != "COMPLETE" && count != 0 {
			return plan, observed, syncstate.ErrArtifactRetained
		}
	}
	plan = SourceRecoveryPlan{Schema: "pluto.source-incarnation-recovery-plan.v1", ConfigSHA256: configSHA, Root: root, Set: set, Source: source, Observed: observed.Object(), Inspection: inspection, FullGuardedScanRequired: true}
	raw, err := json.Marshal(plan)
	if err != nil {
		return plan, observed, err
	}
	hash := sha256.Sum256(raw)
	plan.Digest = hex.EncodeToString(hash[:])
	return plan, observed, nil
}

func RunSourceRecoveryCommand(ctx context.Context, action, configPath, stateDir, sourceID, digest string, output io.Writer) error {
	if action != "source-recover-plan" && action != "source-recover-apply" || sourceID == "" {
		return errors.New("choose an explicit source ID and source-recover-plan or source-recover-apply")
	}
	c, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	if c.Enabled || c.Indexed == nil || !c.Indexed.Activated {
		return errors.New("pause and stop the activated indexed profile before source recovery")
	}
	stateDir, err = filepath.Abs(stateDir)
	if err != nil {
		return err
	}
	if err = sourceRecoveryPath(stateDir); err != nil {
		return err
	}
	release, err := lifecycleLock(stateDir)
	if err != nil {
		return err
	}
	defer release()
	directory := filepath.Join(stateDir, "indexed")
	var store *syncstate.Store
	if action == "source-recover-plan" {
		store, err = syncstate.OpenReadOnly(ctx, directory)
	} else {
		store, err = syncstate.Open(ctx, directory)
	}
	if err != nil {
		return err
	}
	defer store.Close()
	sources, err := store.EnableSources(ctx, syncstate.DefaultSourceLimits())
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	configHash := sha256.Sum256(raw)
	plan, observed, err := sourceRecoveryPlan(ctx, store, sources, c, hex.EncodeToString(configHash[:]), sourceID, directory)
	if err != nil {
		return err
	}
	if action == "source-recover-plan" {
		return json.NewEncoder(output).Encode(plan)
	}
	if digest == "" || digest != plan.Digest {
		return errors.New("source recovery plan is stale or its exact reviewed digest was not supplied")
	}
	backup, err := store.Backup(ctx)
	if err != nil {
		return err
	}
	// Recheck all inputs after the real backup, before admitting any new owner.
	after, current, err := sourceRecoveryPlan(ctx, store, sources, c, plan.ConfigSHA256, sourceID, directory)
	if err != nil || after.Digest != digest || current.Object() != observed.Object() {
		return errors.Join(syncstate.ErrStaleGeneration, err)
	}
	freshConfig, err := os.ReadFile(configPath)
	if err != nil || sha256.Sum256(freshConfig) != configHash {
		return errors.Join(syncstate.ErrStaleGeneration, err)
	}
	owner, err := syncstate.NewOperationID()
	if err != nil {
		return err
	}
	witness, err := sources.BeginSourceOwner(ctx, plan.Set.ID, plan.Set.Revision, owner)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	last, err := syncstate.ObserveSourceIncarnation(plan.Source.PhysicalPath)
	if err != nil || last.Object() != current.Object() {
		return errors.Join(syncstate.ErrCaptureChanged, err)
	}
	witness, err = sources.ReobservePendingIncarnation(ctx, witness, sourceID, plan.Source.Incarnation, plan.Source.PendingObject, current)
	if err != nil {
		return err
	}
	if err = sources.AcceptSourceIncarnation(ctx, witness, sourceID, plan.Source.Incarnation, current); err != nil {
		return err
	}
	receipt := SourceRecoveryReceipt{Schema: "pluto.source-incarnation-recovery.v1", PlanDigest: digest, ConfigSHA256: plan.ConfigSHA256, RootID: plan.Root.RootID, SourceID: sourceID, Previous: plan.Source.Object, Current: current.Object(), Incarnation: plan.Source.Incarnation + 1, Backup: backup, FullGuardedScanRequired: true}
	// Keep a durable receipt even if the caller loses stdout after the commit.
	if err = SaveJSON(filepath.Join(stateDir, fmt.Sprintf("source-recovery-%s.json", digest)), receipt); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(receipt)
}
