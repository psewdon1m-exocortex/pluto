package pluto

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Release struct {
	Schema    int                 `json:"schema"`
	Version   string              `json:"version"`
	Artifacts map[string]Artifact `json:"artifacts"`
}

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func newerVersion(candidate, installed string) bool {
	if !releaseVersion.MatchString(candidate) || !releaseVersion.MatchString(installed) {
		return false
	}
	a, b := strings.Split(candidate, "."), strings.Split(installed, ".")
	for i := range a {
		x, y := strings.TrimLeft(a[i], "0"), strings.TrimLeft(b[i], "0")
		if len(x) != len(y) {
			return len(x) > len(y)
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func VerifyRelease(raw, signature []byte, publicKey string) (Release, error) {
	var release Release
	keyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return release, errors.New("release verification key is invalid")
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return release, errors.New("release verification key is missing")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return release, errors.New("release verification key is invalid")
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() < 3072 {
		return release, errors.New("an RSA verification key of at least 3072 bits is required")
	}
	var envelope struct {
		Schema    string `json:"schema"`
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}
	keyID := sha256.Sum256(block.Bytes)
	if len(signature) > 4096 || json.Unmarshal(signature, &envelope) != nil || envelope.Schema != "exocortex.release-signature.v1" || envelope.Algorithm != "RSA-PSS-SHA256" || envelope.KeyID != hex.EncodeToString(keyID[:]) {
		return release, errors.New("release signature envelope is invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return release, errors.New("release signature is invalid")
	}
	hash := sha256.Sum256(raw)
	if rsa.VerifyPSS(rsaKey, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return release, errors.New("release signature verification failed")
	}
	if len(raw) > 65536 || json.Unmarshal(raw, &release) != nil || release.Schema != 1 || !releaseVersion.MatchString(release.Version) {
		return release, errors.New("release manifest is invalid")
	}
	for _, arch := range []string{"linux-amd64", "linux-arm64"} {
		a, ok := release.Artifacts[arch]
		if !ok || a.Size <= 0 || a.Size > 64<<20 || len(a.SHA256) != 64 {
			return release, errors.New("release artifact is invalid")
		}
		if _, err := hex.DecodeString(a.SHA256); err != nil {
			return release, errors.New("release checksum is invalid")
		}
		if !trustedReleaseURL(a.URL) {
			return release, errors.New("release artifact URL is invalid")
		}
	}
	return release, nil
}
func trustedReleaseURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Host == "github.com" && strings.Contains(u.Path, "/releases/download/")
}
func releaseClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("release redirect is invalid")
		}
		host := req.URL.Hostname()
		if host != "github.com" && host != "release-assets.githubusercontent.com" && host != "objects.githubusercontent.com" {
			return errors.New("release redirect host is invalid")
		}
		return nil
	}}
}
func fetchRelease(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("release server is unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("release request rejected (HTTP %d)", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("release exceeds download limit")
	}
	return raw, nil
}
func CheckRelease(ctx context.Context, repository, publicKey string) (Release, error) {
	var release Release
	u, err := url.Parse(repository)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(strings.Split(strings.Trim(u.Path, "/"), "/")) != 2 {
		return release, errors.New("configure a GitHub release repository in Kernel first")
	}
	client := releaseClient()
	var latest struct {
		Tag string `json:"tag_name"`
	}
	raw, err := fetchRelease(ctx, client, "https://api.github.com/repos"+strings.TrimRight(u.Path, "/")+"/releases/latest", 65536)
	if err != nil {
		return release, err
	}
	if json.Unmarshal(raw, &latest) != nil || !strings.HasPrefix(latest.Tag, "pluto-v") || !releaseVersion.MatchString(strings.TrimPrefix(latest.Tag, "pluto-v")) {
		return release, errors.New("latest release tag is invalid")
	}
	prefix := strings.TrimRight(repository, "/") + "/releases/download/" + latest.Tag + "/"
	raw, err = fetchRelease(ctx, client, prefix+"pluto-release.json", 65536)
	if err != nil {
		return release, err
	}
	signature, err := fetchRelease(ctx, client, prefix+"pluto-release.json.sig.json", 4096)
	if err != nil {
		return release, err
	}
	release, err = VerifyRelease(raw, signature, publicKey)
	if err != nil {
		return release, err
	}
	if latest.Tag != "pluto-v"+release.Version {
		return release, errors.New("release tag and manifest differ")
	}
	for _, a := range release.Artifacts {
		if !strings.HasPrefix(a.URL, prefix) {
			return release, errors.New("release artifact belongs to a different repository or version")
		}
	}
	return release, nil
}

func Update(ctx context.Context, repository, publicKey, socket string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("install updates with sudo pluto tui or sudo pluto update")
	}
	lock, err := os.OpenFile("/run/pluto-update.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil { return err }
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil { return errors.New("another update is running") }
	systemctl := func(action string) error {
		// Rollback must remain possible even when the invoking TUI is cancelled.
		commandCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return exec.CommandContext(commandCtx, "systemctl", action, "pluto.service").Run()
	}
	if err := recoverInterruptedUpdate("/usr/local/bin/pluto", systemctl); err != nil { return err }
	release, err := CheckRelease(ctx, repository, publicKey)
	if err != nil {
		return err
	}
	a, ok := release.Artifacts["linux-"+runtime.GOARCH]
	if !ok {
		return errors.New("this Linux architecture is unsupported")
	}
	binary, err := fetchRelease(ctx, releaseClient(), a.URL, a.Size)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(binary)
	if int64(len(binary)) != a.Size || hex.EncodeToString(hash[:]) != a.SHA256 {
		return errors.New("release binary checksum verification failed")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil || executable != "/usr/local/bin/pluto" {
		return errors.New("self-update requires a bootstrap installation at /usr/local/bin/pluto")
	}
	versionCtx, versionCancel := context.WithTimeout(ctx, 5*time.Second)
	installed, err := exec.CommandContext(versionCtx, executable, "--version").Output()
	versionCancel()
	if err != nil || !newerVersion(release.Version, strings.TrimSpace(string(installed))) {
		return errors.New("no newer verified Pluto release is available")
	}
	candidate, err := os.CreateTemp(filepath.Dir(executable), ".pluto-update-*")
	if err != nil {
		return err
	}
	candidatePath := candidate.Name()
	defer os.Remove(candidatePath)
	_, err = candidate.Write(binary)
	if err == nil {
		err = candidate.Chmod(0755)
	}
	if err == nil {
		err = candidate.Sync()
	}
	candidate.Close()
	if err != nil {
		return err
	}
	versionCtx, versionCancel = context.WithTimeout(ctx, 5*time.Second)
	out, err := exec.CommandContext(versionCtx, candidatePath, "--version").Output()
	versionCancel()
	if err != nil || strings.TrimSpace(string(out)) != release.Version {
		return errors.New("release binary failed its version check")
	}
	local := Remote{LocalClient(socket), "http://localhost", ""}
	if err = local.json(ctx, "POST", "/control", Control{Action: "quiesce"}, nil); err != nil {
		return err
	}
	return installCandidate(executable, candidatePath, systemctl, func() bool {
		var status Status
		healthCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return local.request(healthCtx, "GET", "/status", nil, -1, nil, &status) == nil && status.Version == release.Version
	}, 15*time.Second)
}

func syncParent(filename string) error {
	directory, err := os.Open(filepath.Dir(filename))
	if err != nil { return err }
	defer directory.Close()
	return directory.Sync()
}

// The installed path is never removed: the previous executable is hard-linked,
// and replacement uses one atomic rename. The journal survives until health proof.
func recoverInterruptedUpdate(executable string, systemctl func(string) error) error {
	journal := executable + ".update-pending"
	raw, err := os.ReadFile(journal)
	if errors.Is(err, os.ErrNotExist) { return nil }
	if err != nil { return err }
	if string(raw) != "pluto-replacement-v1\n" { return errors.New("invalid update journal; operator reconciliation required") }
	backup := executable + ".previous"
	if _, err := os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
		// An interruption before backup creation leaves the installed binary intact.
		if _, err = os.Stat(executable); err != nil { return err }
		if err = systemctl("start"); err != nil { return errors.New("installed binary is intact but service restart failed") }
	} else {
		if err != nil { return err }
		if err = systemctl("stop"); err != nil { return errors.New("interrupted update recovery requires service stop") }
		if err = os.Rename(backup, executable); err != nil { return err }
		if err = syncParent(executable); err != nil { return err }
		if err = systemctl("start"); err != nil { return errors.New("previous binary restored but service restart failed") }
	}
	if err = os.Remove(journal); err != nil { return err }
	return syncParent(executable)
}

func installCandidate(executable, candidatePath string, systemctl func(string) error, healthy func() bool, timeout time.Duration) error {
	backup, journal := executable+".previous", executable+".update-pending"
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) { return errors.New("previous binary requires reconciliation before another update") }
	intent, err := os.OpenFile(journal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { return err }
	_, err = intent.WriteString("pluto-replacement-v1\n")
	if err == nil { err = intent.Sync() }
	intent.Close()
	if err == nil { err = syncParent(executable) }
	if err != nil { return err }
	if err := systemctl("stop"); err != nil {
		_ = systemctl("restart")
		_ = os.Remove(journal)
		_ = syncParent(executable)
		return errors.New("Pluto could not be stopped for update")
	}
	if err := os.Link(executable, backup); err != nil {
		_ = systemctl("start")
		_ = os.Remove(journal)
		_ = syncParent(executable)
		return err
	}
	if err := syncParent(executable); err != nil { return err }
	rollback := func() error { return recoverInterruptedUpdate(executable, systemctl) }
	if err := os.Rename(candidatePath, executable); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}
	if err := syncParent(executable); err != nil { return err }
	if err := systemctl("start"); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return errors.New("new Pluto failed to start; previous binary restored")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if healthy() {
			// Removing the intent first commits health proof. A leftover backup is
			// harmless and requires explicit reconciliation, never silent overwrite.
			if err := os.Remove(journal); err != nil { return err }
			if err := syncParent(executable); err != nil { return err }
			if err := os.Remove(backup); err != nil { return err }
			return syncParent(executable)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := rollback(); err != nil {
		return err
	}
	return errors.New("updated Pluto did not become healthy; previous binary restored")
}
