package pluto

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"pluto/internal/pluto/syncstate"
	"pluto/internal/syncproto"
)

// RunArtifactRestoreCommand is an explicit offline step on the restored copy.
func RunArtifactRestoreCommand(ctx context.Context, configPath, stateDir, backupSHA string, output io.Writer) error {
	stateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return err
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); resolved != stateDir || !ok || st.Uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm() != 0700 {
		return syncstate.ErrIdentityConflict
	}
	release, err := lifecycleLock(stateDir)
	if err != nil {
		return err
	}
	defer release()
	c, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	if c.Enabled || c.Indexed == nil || !c.Indexed.Activated {
		return errors.New("restore requires a paused, activated indexed profile")
	}
	profile := c.Indexed.Profile
	marker, err := os.OpenFile(filepath.Join(stateDir, "indexed-activation.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer marker.Close()
	info, err = marker.Stat()
	if err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || info.Size() > 65536 {
		return syncstate.ErrIdentityConflict
	}
	data, err := io.ReadAll(io.LimitReader(marker, 65537))
	if err != nil {
		return err
	}
	var activation struct {
		Schema        string `json:"schema"`
		RootID        string `json:"rootId"`
		Phase         string `json:"phase"`
		MinimumWriter int    `json:"minimumWriter"`
	}
	if len(data) > 65536 || json.Unmarshal(data, &activation) != nil || activation.Schema != "pluto.indexed-activation.v1" ||
		activation.RootID != profile.LocalRootID || activation.Phase != "COMPLETE" || activation.MinimumWriter != daemonWriterVersion {
		return syncstate.ErrIdentityConflict
	}
	remote, err := syncproto.ReadBinding(profile.Remote.Binding)
	if err != nil {
		return err
	}
	binding := syncstate.RootBinding{RootID: profile.LocalRootID, MappingID: profile.MappingID, ServerIdentity: remote.ServerIdentity,
		RemoteRootID: remote.RootID, DeviceID: profile.Remote.DeviceID, SourceIdentity: profile.SourceSetID}
	receipt, err := syncstate.RestoreArtifactDirectory(ctx, filepath.Join(stateDir, "indexed"), backupSHA, binding)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(receipt)
}
