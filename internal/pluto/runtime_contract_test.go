package pluto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeContractSignedBoundaryAndAmbiguousJSON(t *testing.T) {
	_, item, _ := noticeFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	kid := sha256.Sum256(der)
	base := Release{Schema: 1, Version: "0.1.5", Artifacts: map[string]Artifact{"linux-amd64": {URL: "https://github.com/example/pluto/releases/download/pluto-v0.1.5/pluto-linux-amd64", SHA256: strings.Repeat("a", 64), Size: 1}, "linux-arm64": {URL: "https://github.com/example/pluto/releases/download/pluto-v0.1.5/pluto-linux-arm64", SHA256: strings.Repeat("a", 64), Size: 1}}, RuntimeNotices: &RuntimeNotices{Format: runtimeNoticeFormat, Artifact: item}, RuntimeContract: &RuntimeContract{Schema: runtimeContractSchema, Policy: runtimeContractPolicy, RequiredSince: runtimeContractRequiredSince, Embedded: EmbeddedRuntimeNotices{Format: runtimeNoticeFormat, Command: "licenses --archive", Size: item.Size, SHA256: item.SHA256}}}
	verify := func(raw []byte) error {
		h := sha256.Sum256(raw)
		sig, e := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		if e != nil {
			t.Fatal(e)
		}
		envelope, _ := json.Marshal(map[string]string{"schema": "exocortex.release-signature.v1", "algorithm": "RSA-PSS-SHA256", "key_id": hex.EncodeToString(kid[:]), "signature": base64.StdEncoding.EncodeToString(sig)})
		_, e = VerifyRelease(raw, envelope, public)
		return e
	}
	raw, _ := json.Marshal(base)
	if err := verify(raw); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	_ = json.Unmarshal(raw, &document)
	for _, variant := range []string{"missing", "null", "unknown-policy", "altered-floor", "altered-command", "extra-field", "wrong-hash", "wrong-size", "schema2-missing", "duplicate-root", "duplicate-version", "escaped-key", "case-shadow", "noncanonical-version"} {
		t.Run(variant, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			contract := m["runtimeContract"].(map[string]any)
			embedded := contract["embedded"].(map[string]any)
			switch variant {
			case "missing":
				delete(m, "runtimeContract")
			case "null":
				m["runtimeContract"] = nil
			case "unknown-policy":
				contract["policy"] = "none"
			case "altered-floor":
				contract["requiredSince"] = "0.1.6"
			case "altered-command":
				embedded["command"] = "daemon"
			case "extra-field":
				embedded["extractTo"] = "/usr/local/bin"
			case "wrong-hash":
				embedded["sha256"] = strings.Repeat("b", 64)
			case "wrong-size":
				embedded["size"] = float64(item.Size + 1)
			case "schema2-missing":
				m["schema"] = float64(2)
				delete(m, "runtimeContract")
			case "noncanonical-version":
				m["version"] = "0.01.4"
			}
			altered, _ := json.Marshal(m)
			switch variant {
			case "duplicate-root":
				altered = append([]byte(`{"runtimeContract":null,`), altered[1:]...)
			case "duplicate-version":
				altered = append([]byte(`{"version":"0.1.3",`), altered[1:]...)
			case "escaped-key":
				altered = append([]byte(`{"\u0076ersion":"0.1.3",`), altered[1:]...)
			case "case-shadow":
				altered = append([]byte(`{"RuntimeContract":null,`), altered[1:]...)
			}
			if err := verify(altered); err == nil {
				t.Fatal("accepted re-signed stripped/ambiguous contract")
			}
		})
	}
	legacy := base
	legacy.Version = "0.1.4"
	legacy.RuntimeContract = nil
	legacy.RuntimeNotices = nil
	legacyRaw, _ := json.Marshal(legacy)
	if err := verify(legacyRaw); err != nil {
		t.Fatal("genuine pre-boundary legacy rejected", err)
	}
	for _, field := range []string{"runtimeContract", "runtimeNotices"} {
		var m map[string]any
		_ = json.Unmarshal(legacyRaw, &m)
		m[field] = nil
		b, _ := json.Marshal(m)
		if err := verify(b); err == nil {
			t.Fatal("accepted null legacy runtime field", field)
		}
	}
}

func TestRuntimeArchiveExactReadOnlyAndBounded(t *testing.T) {
	var out bytes.Buffer
	if err := WriteRuntimeLicenses(&out, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), []byte(embeddedRuntimeArchive)) || out.Len() > runtimeNoticeMaximum {
		t.Fatal("archive changed or exceeded limit")
	}
	files, err := verifiedRuntimeNotices(out.Bytes(), noticeArtifact(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for name := range runtimeNoticeHashes {
		want, e := os.ReadFile(filepath.Join("../../packaging/sqlite-v1.60.1", name))
		if e != nil || !bytes.Equal(want, files[name]) {
			t.Fatal("upstream bytes differ", name, e)
		}
	}
	out.Bytes()[512] ^= 1
	var repeated bytes.Buffer
	if err := WriteRuntimeLicenses(&repeated, true); err != nil || !bytes.Equal(repeated.Bytes(), []byte(embeddedRuntimeArchive)) {
		t.Fatal("writer mutated embedded source", err)
	}
	var inventory bytes.Buffer
	if err := WriteRuntimeLicenses(&inventory, false); err != nil || !json.Valid(inventory.Bytes()) || inventory.Len() > runtimeNoticeMaximum {
		t.Fatal("inventory command", err)
	}
	bounded := &boundedCommandOutput{maximum: 10}
	if _, err := bounded.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Write([]byte("678901")); err == nil || bounded.Len() != 5 {
		t.Fatal("unbounded command buffer")
	}
}

func TestCandidateLicenseAndVersionProbesBoundOutputAndCancellation(t *testing.T) {
	archive, item, _ := noticeFixture(t)
	r := Release{RuntimeContract: &RuntimeContract{Embedded: EmbeddedRuntimeNotices{Size: item.Size, SHA256: item.SHA256}}}
	for probe, script := range []string{"#!/bin/sh\nhead -c 2097153 /dev/zero\n", "#!/bin/sh\nprintf substituted\n", "#!/bin/sh\nsleep 30\n"} {
		filename := filepath.Join(t.TempDir(), "candidate")
		if err := os.WriteFile(filename, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		backup := qualifyCandidateCommandBackup(t, filename, probe, r, archive)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		started := time.Now()
		err := verifyCandidateEmbedded(ctx, filename, r, nil)
		cancel()
		if err == nil || time.Since(started) > 2*time.Second {
			t.Fatal("unbounded or accepted invalid archive probe", err, time.Since(started))
		}
		backup.verifyAfter(t)
	}
	filename := filepath.Join(t.TempDir(), "candidate-version")
	if err := os.WriteFile(filename, []byte("#!/bin/sh\nhead -c 1025 /dev/zero\n"), 0700); err != nil {
		t.Fatal(err)
	}
	versionBackup := qualifyCandidateCommandBackup(t, filename, 3, r, archive)
	if _, err := boundedCandidateVersion(context.Background(), filename); err == nil {
		t.Fatal("unbounded version output accepted")
	}
	versionBackup.verifyAfter(t)
}

func TestActualRuntimeBuildInfoRejectsFalseLegacyAndExtractsNotices(t *testing.T) {
	directory := os.Getenv("PLUTO_RELEASE_FIXTURE_DIR")
	if directory == "" {
		t.Skip("actual produced binary is separately qualified in audit release build")
	}
	verifyActualPublishedLegacyRuntime(t)
	raw, e := os.ReadFile(filepath.Join(directory, "pluto-release.json"))
	if e != nil {
		t.Fatal(e)
	}
	var r Release
	if e = json.Unmarshal(raw, &r); e != nil {
		t.Fatal(e)
	}
	archive, e := os.ReadFile(filepath.Join(directory, runtimeNoticeAsset))
	if e != nil {
		t.Fatal(e)
	}
	files, e := verifiedRuntimeNotices(archive, r.RuntimeNotices.Artifact)
	if e != nil {
		t.Fatal(e)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		binary, e := os.ReadFile(filepath.Join(directory, "pluto-linux-"+arch))
		if e != nil {
			t.Fatal(e)
		}
		if e := verifyCandidateRuntime(binary, r, files, "linux-"+arch); e != nil {
			t.Fatal(e)
		}
		legacy := r
		legacy.Version = "0.1.4"
		legacy.RuntimeContract = nil
		legacy.RuntimeNotices = nil
		if e := verifyCandidateRuntime(binary, legacy, nil, "linux-"+arch); e == nil {
			t.Fatal("SQLite candidate waived runtime policy by signed old version")
		}
		if e := verifyCandidateRuntime(binary, r, files, "linux-other"); e == nil {
			t.Fatal("wrong architecture accepted")
		}
	}
	if err := verifyCandidateEmbedded(context.Background(), filepath.Join(directory, "pluto-linux-amd64"), r, archive); err != nil {
		t.Fatal(err)
	}
}
