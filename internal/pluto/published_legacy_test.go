package pluto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func publishedLegacyFixture(t *testing.T) (Release, []byte, []byte, string) {
	t.Helper()
	directory := filepath.Join("..", "..", "testdata", "releases", "pluto-v0.1.4")
	read := func(name, expected string) []byte {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		if hex.EncodeToString(hash[:]) != expected {
			t.Fatal("published baseline fixture fingerprint differs", name)
		}
		return raw
	}
	raw := read("pluto-release.json", "18e45f92b3c2c4570ef9841cdbdd23714aa548a19a75ae0e7b0c0b50f7fe5d40")
	signature := read("pluto-release.json.sig.json", "19f564088650795972505e001e0256b5ef20805f7a696ac0e59e45ec21c00e70")
	key := read("release-public.pem", "2e7e2b857ceb0bf0d2488c5f1ca9c1248b38d759728e549b17545be764508b29")
	public := base64.StdEncoding.EncodeToString(key)
	release, err := VerifyRelease(raw, signature, public)
	if err != nil || release.Version != "0.1.4" || release.RuntimeContract != nil || release.RuntimeNotices != nil {
		t.Fatal("authentic published legacy metadata refused", release, err)
	}
	for architecture, expected := range map[string]struct {
		size int64
		hash string
	}{"linux-amd64": {7172258, "59d12873a01aee77cc7bdf36f1166dc008ea8f846c6909fb70fe5e17c037a9b0"}, "linux-arm64": {6684834, "e56bbe0e2e76571ff66a80f1be145ab2dc23640bc0c7df7a7fa4b81b0ef6ad5d"}} {
		artifact := release.Artifacts[architecture]
		if artifact.Size != expected.size || artifact.SHA256 != expected.hash {
			t.Fatal("actual signed payload fingerprint differs", architecture, artifact)
		}
	}
	return release, raw, signature, public
}

func TestPublishedLegacyMetadataNoNewerDoesNotFetchPayload(t *testing.T) {
	_, raw, signature, public := publishedLegacyFixture(t)
	const repository = "https://github.com/psewdon1m-exocortex/pluto"
	const latest = "https://api.github.com/repos/psewdon1m-exocortex/pluto/releases/latest"
	const prefix = repository + "/releases/download/pluto-v0.1.4/"
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	for _, installed := range []string{"0.1.4", "0.1.5"} {
		requests := []string{}
		http.DefaultTransport = pipelineRoundTripper(func(request *http.Request) (*http.Response, error) {
			url := request.URL.String()
			requests = append(requests, url)
			var body []byte
			switch url {
			case latest:
				body = []byte(`{"tag_name":"pluto-v0.1.4"}`)
			case prefix + "pluto-release.json":
				body = raw
			case prefix + "pluto-release.json.sig.json":
				body = signature
			default:
				return nil, fmt.Errorf("unexpected payload or external request: %s", url)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: request}, nil
		})
		release, err := checkNewerRelease(context.Background(), repository, public, installed)
		if !errors.Is(err, errNoNewerRelease) || release.Version != "0.1.4" {
			t.Fatal("authentic old release did not produce no-newer result", installed, release, err)
		}
		if !reflect.DeepEqual(requests, []string{latest, prefix + "pluto-release.json", prefix + "pluto-release.json.sig.json"}) {
			t.Fatal("no-newer discovery fetched payload or runtime notices", requests)
		}
	}
}

func verifyActualPublishedLegacyRuntime(t *testing.T) {
	t.Helper()
	release, _, _, _ := publishedLegacyFixture(t)
	filename := os.Getenv("PLUTO_LEGACY_FIXTURE_BINARY")
	if filename == "" {
		t.Fatal("actual candidate qualification also requires PLUTO_LEGACY_FIXTURE_BINARY")
	}
	binary, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	artifact := release.Artifacts["linux-amd64"]
	hash := sha256.Sum256(binary)
	if int64(len(binary)) != artifact.Size || hex.EncodeToString(hash[:]) != artifact.SHA256 {
		t.Fatal("legacy binary differs from authentic signed published artifact")
	}
	if err := verifyCandidateRuntime(binary, release, nil, "linux-amd64"); err != nil {
		t.Fatal("genuine stdlib-only published binary refused", err)
	}
}
