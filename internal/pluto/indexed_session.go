package pluto

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

type IndexedSession struct {
	Store            *syncstate.Store
	Sources          *syncstate.Sources
	Remote           *syncstate.RemoteImport
	HTTP             *syncstate.IsolatedHTTPSession
	Admission        *ArtifactAdmission
	Witness          syncstate.SourceWitness
	Config           IndexedCommandConfig
	SourceIDs        []string
	StartupArtifacts syncstate.ArtifactReport
	Observer         *syncstate.LinuxObserver
}

// One owner spans successive daemon cycles. Pause/update/shutdown closes the
// observer before its database; resumption always records a new observation gap.
func OpenIndexedSession(ctx context.Context, cfg IndexedCommandConfig, stateDir string, daemon bool) (out *IndexedSession, err error) {
	return openIndexedSession(ctx, cfg, stateDir, daemon, nil)
}

// Adoption supplies the reviewed policy explicitly. Capability negotiation must
// succeed before the supported initial policy transition or any remote import.
func openIndexedSession(ctx context.Context, cfg IndexedCommandConfig, stateDir string, daemon bool, policy *SourcePolicy) (out *IndexedSession, err error) {
	if err = indexedPrivateProfile(stateDir); err != nil {
		return nil, err
	}
	store, err := syncstate.Open(ctx, stateDir)
	if err != nil {
		return nil, err
	}
	x := &IndexedSession{Store: store, Config: cfg}
	defer func() {
		if err != nil {
			err = errors.Join(err, x.Close())
		}
	}()
	x.Sources, err = store.EnableSources(ctx, syncstate.DefaultSourceLimits())
	if err != nil {
		return nil, err
	}
	b, err := syncproto.ReadBinding(cfg.Remote.Binding)
	if err != nil {
		return nil, err
	}
	root := syncstate.RootBinding{RootID: cfg.LocalRootID, MappingID: cfg.MappingID, ServerIdentity: b.ServerIdentity, RemoteRootID: b.RootID, DeviceID: cfg.Remote.DeviceID, SourceIdentity: cfg.SourceSetID}
	if err = store.BindRoot(ctx, root); err != nil {
		return nil, fmt.Errorf("bind indexed root: %w", err)
	}
	specs := make([]syncstate.SourceSpec, 0, len(cfg.Sources))
	for _, s := range cfg.Sources {
		specs = append(specs, syncstate.SourceSpec{ID: s.ID, SelectedPath: s.SelectedPath, WorkingDirectory: s.WorkingDirectory})
		x.SourceIDs = append(x.SourceIDs, s.ID)
	}
	raw, err := json.Marshal(specs)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	set, err := x.Sources.Set(ctx, cfg.SourceSetID)
	if errors.Is(err, sql.ErrNoRows) {
		set, err = x.Sources.BindSourceSet(ctx, cfg.SourceSetID, hash, 0, specs)
	} else if err == nil && set.ConfigDigest != hash {
		if !daemon {
			return nil, syncstate.ErrIdentityConflict
		}
		set, err = x.Sources.BindSourceSet(ctx, cfg.SourceSetID, hash, set.Revision, specs)
	}
	if err != nil {
		return nil, err
	}
	if set.AttachedRootID == "" {
		err = x.Sources.AttachSourceSet(ctx, set.ID, set.Revision, root.RootID)
	} else if set.AttachedRootID != root.RootID {
		err = syncstate.ErrIdentityConflict
	}
	if err != nil {
		return nil, err
	}
	x.Admission, x.StartupArtifacts, err = BootstrapArtifactAdmission(ctx, store, syncstate.DefaultArtifactLimits())
	if err != nil {
		return nil, fmt.Errorf("bootstrap retained artifacts: %w", err)
	}
	x.Remote, err = store.EnableRemoteImport(ctx)
	if err != nil {
		return nil, err
	}
	if daemon {
		x.HTTP, err = syncstate.NewDaemonHTTPSession(ctx, x.Remote, root.RootID, cfg.Remote)
	} else {
		x.HTTP, err = syncstate.NewIsolatedHTTPSession(ctx, x.Remote, root.RootID, cfg.Remote)
	}
	if err != nil {
		return nil, err
	}
	x.HTTP.SetRecoveryReader(x.Admission.reader)
	if daemon || len(cfg.Remote.Features) > 0 {
		if err = x.Remote.EnableDaemonState(ctx); err != nil {
			return nil, err
		}
	}
	if policy != nil {
		if !daemon || policy.Codec != cfg.Remote.NameCodec && !(policy.Codec == "legacy" && cfg.Remote.NameCodec == "") {
			return nil, syncstate.ErrIdentityConflict
		}
		raw, e := json.Marshal(*policy)
		if e != nil {
			return nil, e
		}
		if err = store.CheckPolicy(ctx, cfg.LocalRootID, policy.Codec, policy.Digest(), policy.Revision, raw); err != nil {
			return nil, err
		}
		identity := syncstate.CapturedHTTPIdentity{Domain: cfg.Remote.Domain, Origin: strings.TrimSuffix(cfg.Remote.Origin, "/"), DeviceID: cfg.Remote.DeviceID, BackendIdentity: cfg.Remote.BackendIdentity, ContractReceiptSHA256: cfg.Remote.QualificationReceiptSHA256}
		strict, e := store.PreviewAdoption(ctx, root, b, identity, policy.Codec, daemon)
		if e != nil {
			return nil, e
		}
		if !strict.Compatible {
			return nil, syncstate.ErrIdentityConflict
		}
	}
	if err = x.HTTP.InitializeRemote(ctx); err != nil {
		return nil, fmt.Errorf("initialize indexed remote: %w", err)
	}
	if daemon {
		if err = x.HTTP.ReconcileBindingTransition(ctx); err != nil {
			return nil, fmt.Errorf("reconcile indexed binding: %w", err)
		}
	}
	owner, err := syncstate.NewOperationID()
	if err != nil {
		return nil, err
	}
	x.Witness, err = x.Sources.BeginSourceOwner(ctx, set.ID, set.Revision, owner)
	if err != nil {
		return nil, fmt.Errorf("begin indexed source owner: %w", err)
	}
	x.Witness, err = x.Sources.RequalifyOwnerMounts(ctx, x.Witness, x.SourceIDs)
	if err != nil {
		return nil, fmt.Errorf("requalify indexed source mounts: %w", err)
	}
	if daemon {
		x.Observer, err = syncstate.NewLinuxObserver(ctx, x.Sources, x.Witness)
		if err != nil {
			return nil, err
		}
		if x.HTTP.Features()["namespace-mutations-v1"] {
			if err = x.Remote.EnableMetadataFollowups(ctx, x.Witness); err != nil {
				return nil, err
			}
		}
	}
	return x, nil
}
func (x *IndexedSession) Close() error {
	var err error
	if x.Observer != nil {
		err = x.Observer.Close()
		x.Observer = nil
	}
	if x.HTTP != nil {
		x.HTTP.Close()
		x.HTTP = nil
	}
	if x.Store != nil {
		checkpoint, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = errors.Join(err, x.Store.Checkpoint(checkpoint))
		cancel()
		err = errors.Join(err, x.Store.Close())
		x.Store = nil
	}
	if x.Admission != nil {
		err = errors.Join(err, x.Admission.Detach())
		x.Admission = nil
	}
	return err
}
func (x *IndexedSession) Cycle(ctx context.Context, targets []syncstate.DirtyHint, include func(string) bool) (syncstate.CapturedScanReport, error) {
	class := "bootstrap"
	if targets != nil {
		class = "live"
	}
	ctx = syncstate.WithWorkClass(ctx, class)
	o := syncstate.CapturedScanOptions{Witness: x.Witness, RootID: x.Config.LocalRootID, SourceIDs: x.SourceIDs, Session: x.HTTP, SmallBatchMode: x.Config.SmallBatchMode, Targets: targets}
	o.Hooks.Include = include
	if x.Observer != nil {
		o.Hooks.Before = x.Observer.BeforeClaim
		o.Hooks.Entry = x.Observer.ObserveEntry
	}
	return CopyIndexed(ctx, x.Remote, x.Admission, o)
}
func (x *IndexedSession) ReadyHints(ctx context.Context, include func(string) bool) ([]syncstate.DirtyHint, error) {
	page, err := x.Sources.DirtyPage(ctx, x.Witness, time.Now())
	if err != nil {
		return nil, err
	}
	result := make([]syncstate.DirtyHint, 0, len(page))
	for _, h := range page {
		if include != nil && !include(h.Destination) {
			if err = x.Sources.AckDirty(ctx, x.Witness, h); err != nil {
				return nil, err
			}
			continue
		}
		_, e := os.Lstat(h.PhysicalPath)
		if errors.Is(e, os.ErrNotExist) {
			// Backup semantics: source disappearance retires only the hint. Server
			// copies/history and any original pending operation are untouched.
			if err = x.Sources.AckDirty(ctx, x.Witness, h); err != nil {
				return nil, err
			}
			continue
		}
		if e != nil {
			return nil, e
		}
		result = append(result, h)
	}
	return result, nil
}
