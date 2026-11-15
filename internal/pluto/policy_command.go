package pluto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
	"strings"
	"syscall"
)

// Shared across daemon and offline apply; the OS releases this on process exit.
func lifecycleLock(state string) (func(), error) {
	if err := os.MkdirAll(state, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(state, "lifecycle.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, syncstate.ErrIdentityConflict
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, syncstate.ErrIdentityConflict
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("stop the daemon before offline profile changes")
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}
func readPolicy(filename string) (SourcePolicy, error) {
	var policy SourcePolicy
	f, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return policy, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return policy, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 65536 {
		return policy, syncstate.ErrIdentityConflict
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return policy, err
	}
	if len(raw) > 65536 {
		return policy, syncstate.ErrSourceQuota
	}
	if _, err = syncproto.Parse(raw); err != nil {
		return policy, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&policy); err != nil {
		return policy, err
	}
	return policy, policy.Validate()
}

type policyApply struct {
	Schema, PlanDigest, PolicyDigest, Phase string
	RootID                                  string
	Policy                                  SourcePolicy
}

func RunPolicyCommand(ctx context.Context, action, configPath, stateDir, filename, digest string, out io.Writer) error {
	c, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	if c.Indexed == nil || !c.Indexed.Activated {
		return errors.New("adopt an indexed profile before planning policy changes")
	}
	policy, err := readPolicy(filename)
	if err != nil {
		return err
	}
	beforeScope := scopeIncludes(c.Indexed.Policy, c.Sources)
	afterSources := c.Sources
	if policy.Sources != nil {
		afterSources = policy.Sources
	}
	prospective := c
	indexCopy := *c.Indexed
	prospective.Indexed = &indexCopy
	prospective.Indexed.Policy = policy
	prospective.Indexed.Profile.Remote.NameCodec = policy.Codec
	prospective.Sources = afterSources
	if raw, e := json.MarshalIndent(prospective, "", "  "); e != nil {
		return e
	} else if len(raw) > 65536 {
		return errors.New("updated configuration exceeds its 64 KiB bound")
	}
	afterScope := scopeIncludes(policy, afterSources)
	alreadyApplied := policy.Digest() == c.Indexed.Policy.Digest()
	if policy.Revision != c.Indexed.Policy.Revision+1 && !(alreadyApplied && action != "policy-plan" && action != "namespace-plan") {
		return errors.New("policy revision must advance by exactly one")
	}
	directory := filepath.Join(stateDir, "indexed")
	if action == "policy-plan" || action == "namespace-plan" {
		store, err := syncstate.OpenReadOnly(ctx, directory)
		if err != nil {
			return err
		}
		defer store.Close()
		plan, err := store.PreviewPolicy(ctx, c.Indexed.Profile.LocalRootID, policy.Codec, policy.Digest(), beforeScope, afterScope)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(plan)
	}
	if c.Enabled {
		return errors.New("pause before applying a policy plan")
	}
	release, err := lifecycleLock(stateDir)
	if err != nil {
		return err
	}
	defer release()
	store, err := syncstate.Open(ctx, directory)
	if err != nil {
		return err
	}
	defer store.Close()
	journal := filepath.Join(stateDir, "policy-apply.json")
	var progress policyApply
	if raw, e := os.ReadFile(journal); e == nil {
		if json.Unmarshal(raw, &progress) != nil {
			return syncstate.ErrIdentityConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	matching := progress.Schema == "pluto.policy-apply.v1" && progress.PlanDigest == digest && progress.PolicyDigest == policy.Digest() && progress.RootID == c.Indexed.Profile.LocalRootID
	if alreadyApplied {
		if !matching {
			return syncstate.ErrIdentityConflict
		}
		progress.Phase = "COMPLETE"
		if err = SaveJSON(journal, progress); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(progress)
	}
	continuing := matching && progress.Phase != "COMPLETE"
	if !continuing {
		plan, err := store.PreviewPolicy(ctx, c.Indexed.Profile.LocalRootID, policy.Codec, policy.Digest(), beforeScope, afterScope)
		if err != nil {
			return err
		}
		if digest == "" || digest != plan.Digest {
			return errors.New("policy plan is stale or its digest was not supplied")
		}
		if plan.InvalidNames > 0 || plan.Collisions > 0 || plan.PendingOriginals > 0 {
			return errors.New("resolve invalid names, collisions and original operations before policy migration")
		}
		if _, err = store.Backup(ctx); err != nil {
			return err
		}
		progress = policyApply{Schema: "pluto.policy-apply.v1", PlanDigest: digest, PolicyDigest: policy.Digest(), Phase: "PREPARED", Policy: policy, RootID: c.Indexed.Profile.LocalRootID}
		if err = SaveJSON(journal, progress); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(policy)
	if err = store.ApplyPolicy(ctx, c.Indexed.Profile.LocalRootID, policy.Codec, policy.Digest(), policy.Revision, raw); err != nil {
		return err
	}
	progress.Phase = "STATE_APPLIED"
	if err = SaveJSON(journal, progress); err != nil {
		return err
	}
	c.Indexed.Policy = policy
	c.Sources = append([]string{}, afterSources...)
	c.Indexed.Profile.Remote.NameCodec = policy.Codec
	if err = SaveJSON(configPath, c); err != nil {
		return err
	}
	progress.Phase = "COMPLETE"
	if err = SaveJSON(journal, progress); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(progress)
}
func scopeIncludes(policy SourcePolicy, sources []string) func(string) bool {
	return func(path string) bool {
		if !policy.Includes(path) {
			return false
		}
		for _, source := range sources {
			prefix := strings.TrimLeft(filepath.ToSlash(source), "/")
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return true
			}
		}
		return false
	}
}
