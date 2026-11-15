package pluto

import (
	"archive/tar"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func noticeFixture(t *testing.T) ([]byte, Artifact, map[string][]byte) {
	t.Helper()
	files := map[string][]byte{}
	entries := []map[string]any{}
	for _, name := range []string{"LICENSE", "LICENSE-3RD-PARTY.md", "LICENSE-SQLITE", "LICENSE-SQLITE_VEC"} {
		b, err := os.ReadFile(filepath.Join("../../packaging/sqlite-v1.60.1", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = b
		entries = append(entries, map[string]any{"name": name, "sha256": runtimeNoticeHashes[name], "size": len(b)})
	}
	modules := []map[string]string{{"path": "modernc.org/sqlite", "version": "v1.60.1", "sum": "h1:fixture"}, {"path": "modernc.org/libc", "version": "v1.77.1", "sum": "h1:fixture"}}
	files["INVENTORY.json"], _ = json.Marshal(map[string]any{"schema": 1, "driver": "modernc.org/sqlite@v1.60.1", "files": entries, "linkedModules": map[string]any{"linux-amd64": modules, "linux-arm64": modules}})
	raw := makeNoticeTar(t, files, "", tar.TypeReg)
	h := sha256.Sum256(raw)
	return raw, Artifact{"https://github.com/example/pluto/releases/download/pluto-v0.1.5/" + runtimeNoticeAsset, hex.EncodeToString(h[:]), int64(len(raw))}, files
}
func makeNoticeTar(t *testing.T, files map[string][]byte, rename string, kind byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	for _, name := range []string{"LICENSE", "LICENSE-3RD-PARTY.md", "LICENSE-SQLITE", "LICENSE-SQLITE_VEC", "INVENTORY.json"} {
		content := files[name]
		actual := name
		if name == "LICENSE" && rename != "" {
			actual = rename
		}
		h := &tar.Header{Name: actual, Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if name == "LICENSE" && kind != tar.TypeReg {
			h.Typeflag = kind
			h.Linkname = "/tmp/escape"
			h.Size = 0
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := w.Write(content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func noticeArtifact(raw []byte) Artifact {
	h := sha256.Sum256(raw)
	return Artifact{SHA256: hex.EncodeToString(h[:]), Size: int64(len(raw))}
}
func TestRuntimeNoticesExactBytesAndSafePaths(t *testing.T) {
	raw, item, want := noticeFixture(t)
	got, err := verifiedRuntimeNotices(raw, item)
	if err != nil {
		t.Fatal(err)
	}
	for name, bytes := range want {
		if !bytesEqual(got[name], bytes) {
			t.Fatal("notice bytes changed", name)
		}
	}
	for _, mutation := range []struct {
		name string
		raw  []byte
		item Artifact
	}{
		{"digest", append(append([]byte{}, raw[:512]...), append([]byte{'x'}, raw[513:]...)...), item},
		{"truncated", raw[:len(raw)-512], noticeArtifact(raw[:len(raw)-512])},
		{"path traversal", makeNoticeTar(t, want, "../escape", tar.TypeReg), Artifact{}},
		{"absolute", makeNoticeTar(t, want, "/escape", tar.TypeReg), Artifact{}},
		{"symlink", makeNoticeTar(t, want, "LICENSE", tar.TypeSymlink), Artifact{}},
		{"hardlink", makeNoticeTar(t, want, "LICENSE", tar.TypeLink), Artifact{}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			a := mutation.item
			if a.Size == 0 {
				a = noticeArtifact(mutation.raw)
			}
			if _, err := verifiedRuntimeNotices(mutation.raw, a); err == nil {
				t.Fatal("accepted unsafe notice asset")
			}
		})
	}
	bad := map[string][]byte{}
	for k, v := range want {
		bad[k] = v
	}
	bad["LICENSE"] = []byte("substituted upstream license")
	altered := makeNoticeTar(t, bad, "", tar.TypeReg)
	if _, err := verifiedRuntimeNotices(altered, noticeArtifact(altered)); err == nil {
		t.Fatal("accepted signed substituted pinned license")
	}
}
func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }
func TestSchemaTwoNoticesAreMandatoryAndSignatureBound(t *testing.T) {
	_, item, _ := noticeFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	kid := sha256.Sum256(der)
	release := Release{Schema: 2, Version: "0.1.5", Artifacts: map[string]Artifact{"linux-amd64": {URL: "https://github.com/example/pluto/releases/download/pluto-v0.1.5/pluto-linux-amd64", SHA256: string(bytes.Repeat([]byte("a"), 64)), Size: 1}, "linux-arm64": {URL: "https://github.com/example/pluto/releases/download/pluto-v0.1.5/pluto-linux-arm64", SHA256: string(bytes.Repeat([]byte("a"), 64)), Size: 1}}, RuntimeNotices: &RuntimeNotices{runtimeNoticeFormat, item}}
	release.RuntimeContract = &RuntimeContract{Schema: runtimeContractSchema, Policy: runtimeContractPolicy, RequiredSince: runtimeContractRequiredSince, Embedded: EmbeddedRuntimeNotices{Format: runtimeNoticeFormat, Command: "licenses --archive", Size: item.Size, SHA256: item.SHA256}}
	verify := func(r Release) (Release, error) {
		raw, _ := json.Marshal(r)
		hash := sha256.Sum256(raw)
		sig, _ := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		envelope, _ := json.Marshal(map[string]string{"schema": "exocortex.release-signature.v1", "algorithm": "RSA-PSS-SHA256", "key_id": hex.EncodeToString(kid[:]), "signature": base64.StdEncoding.EncodeToString(sig)})
		return VerifyRelease(raw, envelope, encoded)
	}
	if _, err := verify(release); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*RuntimeNotices{nil, {"wrong", item}, {runtimeNoticeFormat, Artifact{URL: item.URL, SHA256: item.SHA256, Size: runtimeNoticeMaximum + 1}}, {runtimeNoticeFormat, Artifact{URL: "https://github.com/example/pluto/releases/download/pluto-v0.1.5/../escape", SHA256: item.SHA256, Size: item.Size}}} {
		r := release
		r.RuntimeNotices = n
		if _, err := verify(r); err == nil {
			t.Fatal("accepted missing/invalid runtime notice descriptor")
		}
	}
	legacy := release
	legacy.Schema = 1
	legacy.Version = "0.1.3"
	legacy.RuntimeNotices = nil
	legacy.RuntimeContract = nil
	if _, err := verify(legacy); err != nil {
		t.Fatal("legacy signed manifest compatibility", err)
	}
	legacy.RuntimeNotices = release.RuntimeNotices
	if _, err := verify(legacy); err == nil {
		t.Fatal("legacy manifest silently ignored notices")
	}
}
func writeUpdateFixture(t *testing.T, root string, oldNotices bool) (string, string, string) {
	t.Helper()
	exe, candidate := filepath.Join(root, "pluto"), filepath.Join(root, "candidate")
	for name, value := range map[string]string{exe: "old", candidate: "new", filepath.Join(root, "config.json"): `{"accessToken":"fixture-secret","sources":["/fixture"],"enabled":false}`, filepath.Join(root, "state.json"): "legacy state", filepath.Join(root, "socket-identity"): "same socket"} {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if oldNotices {
		if err := os.Mkdir(noticeDirectory(exe), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(noticeDirectory(exe), "old.txt"), []byte("old notices"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, files := noticeFixture(t)
	staged, err := stageRuntimeNotices(root, files)
	if err != nil {
		t.Fatal(err)
	}
	return exe, candidate, staged
}
func TestNoticeUpdateLegacyAndCurrentInstallCommitRollback(t *testing.T) {
	for _, had := range []bool{false, true} {
		for _, failure := range []string{"", "stop", "start", "health"} {
			t.Run(stringify(had)+failure, func(t *testing.T) {
				root := t.TempDir()
				exe, candidate, staged := writeUpdateFixture(t, root, had)
				identities := map[string][]byte{}
				for _, name := range []string{"config.json", "state.json", "socket-identity"} {
					identities[name], _ = os.ReadFile(filepath.Join(root, name))
				}
				running := true
				startCount := 0
				command := func(action string) error {
					switch action {
					case "stop":
						if failure == "stop" {
							return errors.New("stop failed")
						}
						running = false
					case "start":
						startCount++
						if failure == "start" && startCount == 1 {
							return errors.New("start failed")
						}
						if running {
							t.Fatal("second daemon start")
						}
						running = true
					case "restart":
						running = true
					}
					return nil
				}
				err := installCandidateWithNotices(exe, candidate, staged, command, func() bool { return failure != "health" }, 20*time.Millisecond)
				if failure == "" {
					if err != nil {
						t.Fatal(err)
					}
					assertFile(t, exe, "new")
					for name, want := range runtimeNoticeHashes {
						b, e := os.ReadFile(filepath.Join(noticeDirectory(exe), name))
						h := sha256.Sum256(b)
						if e != nil || hex.EncodeToString(h[:]) != want {
							t.Fatal("installed notices mismatch", name)
						}
					}
				} else {
					if err == nil {
						t.Fatal("failure ignored")
					}
					assertFile(t, exe, "old")
					if had {
						assertFile(t, filepath.Join(noticeDirectory(exe), "old.txt"), "old notices")
					} else {
						if _, e := os.Lstat(noticeDirectory(exe)); !os.IsNotExist(e) {
							t.Fatal("legacy rollback retained new notices")
						}
					}
				}
				if !running {
					t.Fatal("installation left stopped")
				}
				for name, want := range identities {
					b, _ := os.ReadFile(filepath.Join(root, name))
					if !bytes.Equal(b, want) {
						t.Fatal("changed legacy profile/state/socket", name)
					}
				}
				if _, e := os.Lstat(exe + ".update-pending"); !os.IsNotExist(e) {
					t.Fatal("journal remained")
				}
			})
		}
	}
}
func stringify(v bool) string {
	if v {
		return "with-old-notices/"
	}
	return "legacy/"
}
func assertFile(t *testing.T, name, want string) {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil || string(b) != want {
		t.Fatalf("file %s: %s %v", name, b, err)
	}
}
func TestInterruptedNoticeUpdateRecoveryAllReplacementBoundaries(t *testing.T) {
	for _, had := range []bool{false, true} {
		for _, stage := range []int{0, 1, 2, 3, 4} {
			t.Run(stringify(had)+string(rune('0'+stage)), func(t *testing.T) {
				root := t.TempDir()
				exe, candidate, staged := writeUpdateFixture(t, root, had)
				raw, _ := json.Marshal(noticeUpdateIntent{"pluto-replacement-v2", had})
				if err := os.WriteFile(exe+".update-pending", raw, 0600); err != nil {
					t.Fatal(err)
				}
				if stage >= 1 {
					if err := os.Link(exe, exe+".previous"); err != nil {
						t.Fatal(err)
					}
				}
				if stage >= 2 && had {
					if err := os.Rename(noticeDirectory(exe), noticeDirectory(exe)+".previous"); err != nil {
						t.Fatal(err)
					}
				}
				if stage >= 3 {
					if err := os.Rename(staged, noticeDirectory(exe)); err != nil {
						t.Fatal(err)
					}
				}
				if stage >= 4 {
					if err := os.Rename(candidate, exe); err != nil {
						t.Fatal(err)
					}
				}
				if err := recoverInterruptedUpdate(exe, func(string) error { return nil }); err != nil {
					t.Fatal(err)
				}
				assertFile(t, exe, "old")
				if had {
					assertFile(t, filepath.Join(noticeDirectory(exe), "old.txt"), "old notices")
				} else {
					if _, err := os.Stat(noticeDirectory(exe)); !os.IsNotExist(err) {
						t.Fatal("did not restore absent notices")
					}
				}
			})
		}
	}
}
func TestActualProducedReleaseRuntimeNotices(t *testing.T) {
	directory := os.Getenv("PLUTO_RELEASE_FIXTURE_DIR")
	if directory == "" {
		t.Skip("qualified actual release assets provided in audit build container")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "pluto-release.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(filepath.Join(directory, "pluto-release.json.sig.json"))
	key, _ := os.ReadFile(filepath.Join(directory, "release-public.pem"))
	release, err := VerifyRelease(raw, sig, base64.StdEncoding.EncodeToString(key))
	if err != nil || release.Schema != 1 || release.RuntimeContract == nil {
		t.Fatal(err)
	}
	notices, _ := os.ReadFile(filepath.Join(directory, runtimeNoticeAsset))
	if _, err := verifiedRuntimeNotices(notices, release.RuntimeNotices.Artifact); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidNoticeUpdateJournalAndSymlinksPreserveInstallation(t *testing.T) {
	for _, raw := range []string{`{"schema":"pluto-replacement-v2"}`, `{"schema":"pluto-replacement-v2","hadNotices":null}`, `{"schema":"pluto-replacement-v2","hadNotices":true,"extra":1}`, `{"schema":"pluto-replacement-v2","hadNotices":true,"hadNotices":false}`} {
		t.Run(raw, func(t *testing.T) {
			root := t.TempDir()
			exe, _, _ := writeUpdateFixture(t, root, true)
			if err := os.WriteFile(exe+".update-pending", []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			if err := recoverInterruptedUpdate(exe, func(string) error { calls++; return nil }); err == nil {
				t.Fatal("accepted corrupt journal")
			}
			assertFile(t, exe, "old")
			assertFile(t, filepath.Join(noticeDirectory(exe), "old.txt"), "old notices")
			assertFile(t, exe+".update-pending", raw)
			if calls != 0 {
				t.Fatal("interfered with daemon before rejecting invalid journal")
			}
		})
	}
	root := t.TempDir()
	exe, candidate, staged := writeUpdateFixture(t, root, false)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "important"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, noticeDirectory(exe)); err != nil {
		t.Fatal(err)
	}
	if err := installCandidateWithNotices(exe, candidate, staged, func(string) error { t.Fatal("stopped service for unsafe notice path"); return nil }, func() bool { return true }, time.Second); err == nil {
		t.Fatal("accepted notice symlink")
	}
	assertFile(t, exe, "old")
	assertFile(t, filepath.Join(outside, "important"), "preserve")
}
