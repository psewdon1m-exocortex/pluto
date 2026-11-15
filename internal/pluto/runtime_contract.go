package pluto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// The first new SQLite-bearing release is 0.1.5. The published 0.1.4 CLI is
// stdlib-only; authenticated discovery of that legacy release remains supported.
const runtimeContractRequiredSince = "0.1.5"
const runtimeContractSchema = "pluto-runtime-contract.v1"
const runtimeContractPolicy = "sqlite-runtime-notices.v1"

// Full upstream notice bytes and actual linked dependency inventory are embedded
// in every CLI. Release qualification refuses a stale source archive.
//
//go:embed runtime-notices.tar
var embeddedRuntimeArchive string

type RuntimeContract struct {
	Schema        string                 `json:"schema"`
	Policy        string                 `json:"policy"`
	RequiredSince string                 `json:"requiredSince"`
	Embedded      EmbeddedRuntimeNotices `json:"embedded"`
}
type EmbeddedRuntimeNotices struct {
	Format  string `json:"format"`
	Command string `json:"command"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

func requiresRuntimeContract(version string) bool {
	return version == runtimeContractRequiredSince || newerVersion(version, runtimeContractRequiredSince)
}

// Reject duplicate keys at every depth, including version/schema. Otherwise a
// signed ambiguous JSON document could be interpreted as different policies.
func uniqueReleaseJSON(raw []byte) error {
	if len(raw) > 65536 {
		return errors.New("release metadata exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("release JSON nesting exceeds limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return errors.New("duplicate or invalid release JSON key")
					}
					seen[name] = true
					// encoding/json matches struct fields case-insensitively. Reject
					// alternate spellings so differently cased keys cannot shadow the
					// canonical policy that the other verifiers interpret literally.
					for _, canonical := range []string{"schema", "version", "artifacts", "url", "sha256", "size", "runtimeNotices", "format", "artifact", "runtimeContract", "policy", "requiredSince", "embedded", "command", "algorithm", "key_id", "signature"} {
						if name != canonical && strings.EqualFold(name, canonical) {
							return errors.New("noncanonical release JSON field")
						}
					}
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errors.New("invalid release JSON object")
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errors.New("invalid release JSON array")
				}
			default:
				return errors.New("invalid release JSON delimiter")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("release JSON trailing content")
	}
	return nil
}

func validateRuntimeContract(raw []byte, r Release) error {
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil {
		return errors.New("runtime contract is invalid")
	}
	_, present := document["runtimeContract"]
	if r.RuntimeContract == nil {
		if present {
			return errors.New("runtime contract cannot be null")
		}
		if _, noticesPresent := document["runtimeNotices"]; r.Schema == 1 && noticesPresent {
			return errors.New("legacy runtime notices are not permitted")
		}
		if requiresRuntimeContract(r.Version) {
			return errors.New("release requires the embedded runtime contract")
		}
		return nil
	}
	var contract RuntimeContract
	d := json.NewDecoder(bytes.NewReader(document["runtimeContract"]))
	d.DisallowUnknownFields()
	if err := d.Decode(&contract); err != nil {
		return errors.New("runtime contract shape is invalid")
	}
	if !requiresRuntimeContract(r.Version) || contract.Schema != runtimeContractSchema || contract.Policy != runtimeContractPolicy || contract.RequiredSince != runtimeContractRequiredSince || contract.Embedded.Format != runtimeNoticeFormat || contract.Embedded.Command != "licenses --archive" || r.RuntimeNotices == nil || contract.Embedded.Size != r.RuntimeNotices.Artifact.Size || contract.Embedded.SHA256 != r.RuntimeNotices.Artifact.SHA256 {
		return errors.New("runtime contract policy or notice identity is invalid")
	}
	return nil
}

// Explicit read-only license access: no configuration/state/daemon or filesystem
// writes. --version never calls this command.
func WriteRuntimeLicenses(out io.Writer, archive bool) error {
	raw := []byte(embeddedRuntimeArchive)
	h := sha256.Sum256(raw)
	files, err := verifiedRuntimeNotices(raw, Artifact{Size: int64(len(raw)), SHA256: hex.EncodeToString(h[:])})
	if err != nil {
		return err
	}
	if archive {
		_, err = out.Write(raw)
	} else {
		_, err = out.Write(files["INVENTORY.json"])
	}
	return err
}

type linkedNoticeModule struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}

// Binary build info is independent evidence: a signer cannot waive notice policy
// merely by calling a newly linked SQLite binary a pre-boundary legacy version.
func verifyCandidateRuntime(binary []byte, r Release, files map[string][]byte, architecture string) error {
	info, err := buildinfo.Read(bytes.NewReader(binary))
	if err != nil {
		return errors.New("release candidate is not a readable Go binary")
	}
	actual := map[string]linkedNoticeModule{}
	linkedSQLite := false
	for _, dep := range info.Deps {
		linkedSQLite = linkedSQLite || dep.Path == "modernc.org/sqlite"
		if dep.Replace != nil {
			return errors.New("release candidate uses an unqualified module replacement")
		}
		actual[dep.Path] = linkedNoticeModule{dep.Path, dep.Version, dep.Sum}
	}
	if r.RuntimeContract == nil {
		if linkedSQLite {
			return errors.New("SQLite-linked candidate requires the embedded runtime contract")
		}
		return nil
	}
	if !linkedSQLite || info.GoVersion != "go1.26.10" || files == nil {
		return errors.New("release runtime build or notice inventory is missing")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || "linux-"+settings["GOARCH"] != architecture || settings["CGO_ENABLED"] != "0" {
		return errors.New("release runtime architecture or CGO policy differs")
	}
	var inventory struct {
		LinkedModules map[string][]linkedNoticeModule `json:"linkedModules"`
	}
	if json.Unmarshal(files["INVENTORY.json"], &inventory) != nil {
		return errors.New("release runtime inventory is invalid")
	}
	expected := inventory.LinkedModules[architecture]
	if len(actual) != len(expected) {
		return errors.New("release runtime dependency inventory differs")
	}
	for _, dep := range expected {
		if actual[dep.Path] != dep {
			return fmt.Errorf("release runtime dependency differs: %s", dep.Path)
		}
	}
	return nil
}

type boundedCommandOutput struct {
	buffer     bytes.Buffer
	maximum    int
	onExceeded func()
}

func (b *boundedCommandOutput) Write(p []byte) (int, error) {
	if len(p) > b.maximum-b.Len() {
		if b.onExceeded != nil {
			b.onExceeded()
		}
		return 0, errors.New("candidate command output exceeds limit")
	}
	return b.buffer.Write(p)
}
func (b *boundedCommandOutput) Len() int      { return b.buffer.Len() }
func (b *boundedCommandOutput) Bytes() []byte { return b.buffer.Bytes() }

func boundedReadOnlyCommand(ctx context.Context, executable string, args ...string) (*exec.Cmd, context.CancelFunc) {
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	command := exec.CommandContext(commandCtx, executable, args...)
	// Pluto runs on Linux; kill only the private candidate command group, including
	// children holding output pipes open. No daemon/process lookup is involved.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = time.Second
	return command, cancel
}

func verifyCandidateEmbedded(ctx context.Context, candidate string, r Release, external []byte) error {
	if r.RuntimeContract == nil {
		return nil
	}
	command, cancel := boundedReadOnlyCommand(ctx, candidate, "licenses", "--archive")
	defer cancel()
	output := &boundedCommandOutput{maximum: runtimeNoticeMaximum, onExceeded: cancel}
	stderr := &boundedCommandOutput{maximum: 4096, onExceeded: cancel}
	command.Stdout, command.Stderr = output, stderr
	if err := command.Run(); err != nil {
		return errors.New("release embedded notice command failed or exceeded limits")
	}
	embedded := r.RuntimeContract.Embedded
	h := sha256.Sum256(output.Bytes())
	if int64(output.Len()) != embedded.Size || hex.EncodeToString(h[:]) != embedded.SHA256 || !bytes.Equal(output.Bytes(), external) {
		return errors.New("release embedded and external notices differ")
	}
	return nil
}

func boundedCandidateVersion(ctx context.Context, executable string) ([]byte, error) {
	command, cancel := boundedReadOnlyCommand(ctx, executable, "--version")
	defer cancel()
	out, stderr := &boundedCommandOutput{maximum: 1024, onExceeded: cancel}, &boundedCommandOutput{maximum: 4096, onExceeded: cancel}
	command.Stdout, command.Stderr = out, stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("candidate version command failed or exceeded limits")
	}
	return out.Bytes(), nil
}
