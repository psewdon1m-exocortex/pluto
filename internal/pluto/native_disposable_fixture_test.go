//go:build linux

package pluto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This fixture admits only a newly created, host-attested container. The host
// inspects Docker identity, labels and its complete mount set before start, then
// binds this immutable tuple read-only. It grants no product/installer authority.
func requireFreshDisposableNativeFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("STAGE3_C_DISPOSABLE_CONTAINER") == "chat-c-native-193115" {
		t.Fatal("retired disposable container identity is not current ownership")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("container evidence required", err)
	}
	const markerPath = "/run/pluto-disposable-fixture.json"
	file, err := os.Open(markerPath)
	if err != nil {
		t.Fatal("fresh host-attested fixture marker required", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096 {
		t.Fatal("fixture marker is not a bounded regular file", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		t.Fatal("fixture marker read failed or exceeded limit", err)
	}
	var marker struct {
		Schema, Run, Scope, Nonce, ContainerID, Created, Image string
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		t.Fatal("fixture marker shape rejected", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("fixture marker trailing content rejected", err)
	}
	nonce, nonceErr := hex.DecodeString(marker.Nonce)
	id, idErr := hex.DecodeString(marker.ContainerID)
	image, imageErr := hex.DecodeString(strings.TrimPrefix(marker.Image, "sha256:"))
	created, createdErr := time.Parse(time.RFC3339Nano, marker.Created)
	hostname, hostnameErr := os.Hostname()
	if marker.Schema != "pluto.disposable-native-fixture.v1" || !strings.HasPrefix(marker.Run, "release-candidate-") || marker.Run != os.Getenv("PLUTO_NATIVE_FIXTURE_RUN") || nonceErr != nil || len(nonce) != 32 || marker.Nonce != os.Getenv("PLUTO_NATIVE_FIXTURE_NONCE") || marker.Scope != "pluto-native-ci-"+marker.Nonce[:16] || marker.Scope != os.Getenv("PLUTO_NATIVE_FIXTURE_SCOPE") || idErr != nil || len(id) != 32 || hostnameErr != nil || hostname != marker.ContainerID[:12] || imageErr != nil || len(image) != 32 || !strings.HasPrefix(marker.Image, "sha256:") || createdErr != nil || time.Since(created) < 0 || time.Since(created) > 30*time.Minute {
		t.Fatal("fresh container identity, nonce, scope or creation tuple rejected")
	}
	for _, path := range []string{"/workspace", markerPath} {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(path, &fs); err != nil || fs.Flags&syscall.MS_RDONLY == 0 {
			t.Fatal("fixture source and ownership marker must be mounted read-only", path, err)
		}
	}
	t.Log("fresh disposable fixture admitted", marker.ContainerID, marker.Scope, marker.Image)
}
