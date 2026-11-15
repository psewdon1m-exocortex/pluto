// Audit-only implementation source. No init side effects. Not qualified yet.
package nativefixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const MaxPacket = 65536
const MaxRPC = 100000
const MaxArtifact = 128 << 20

type Artifact struct {
	Path, SHA256 string
	Bytes        int64
}
type Case struct {
	Actions          map[string]int64 // exact reviewed maximum milliseconds; no default
	Faults           map[string]Fault
	MaxFixtures      int
	CopyMs           int64
	CopyMaxBytes     int64
	CopyDestinations map[string]string
}
type Fault struct {
	Site, BackupPath, BackupSHA string
	CheckpointRoot              string
	BarrierRequired             bool
}
type Manifest struct {
	Schema, Run, Scope, Nonce          string
	ContainerID, Hostname              string
	Namespaces                         [3]string
	ExpiresUnixMs                      int64
	Socket, RetainedRoot, EvidenceRoot string
	Owner, GoTest                      Artifact
	GoArgs                             []string
	Artifacts                          map[string]Artifact // current, historical-r1e/r1f, copy
	Cases                              map[string]Case     // exact complete t.Name, including every subtest
	Environment                        []string            // exact reviewed public minimum; TLS path is per fixture
	OutputPrefixBytes                  int64
}

type Request struct {
	Schema, Scope, Nonce, Operation                                                                 string
	Sequence                                                                                        uint64
	Case, Fixture, Role, Action, Profile, Digest, Actor, Config, State, CopySource, CopyDestination string
	DeadlineUnixMs                                                                                  int64
	Failed                                                                                          bool
	BarrierObserved                                                                                 bool
}
type Actual struct {
	PID                        int
	Observed, Exited, Signaled bool
	ExitCode, Signal           int
	RawStatus                  uint32
}
type Result struct {
	ID, Fixture, Base, Evidence                                     string
	Actual                                                          Actual
	Stdout, Stderr, Combined                                        []byte `json:"-"` // loaded from exact retained prefix files after join
	CombinedMode                                                    bool
	StdoutPrefixBytes, StderrPrefixBytes                            int64
	StdoutPrefixSHA, StderrPrefixSHA                                string
	LifecycleError, DomainError                                     string
	IntentProven, StrongTupleObserved, NumericDurable, DrainsJoined bool
	DeadlineExpired, JoinWatchdogExpired                            bool
	Truncated                                                       bool
}
type Response struct {
	Sequence uint64
	Error    string
	Result   Result
}

func SHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func validSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
func strictJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaxPacket {
		return errors.New("bounded JSON required")
	}
	if e := uniqueJSON(raw); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func() error
	value = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		delimiter, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate/invalid JSON key")
				}
				seen[s] = true
				if e = value(); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := value(); e != nil {
					return e
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := value(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func cleanAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n\\")
}
func beneath(root, p string) bool {
	return cleanAbsolute(root) && cleanAbsolute(p) && strings.HasPrefix(p, root+"/")
}
func safeName(s string) bool {
	return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n\\") && !strings.Contains(s, "..")
}

// Pin is supplied by the independently reviewed outer invocation, not by Go's RPC.
func DecodeManifest(raw []byte, pin string, nowMs int64) (Manifest, error) {
	var m Manifest
	if !validSHA(pin) || SHA(raw) != pin {
		return m, errors.New("Root-pinned manifest bytes required")
	}
	if err := strictJSON(raw, &m); err != nil {
		return m, err
	}
	if m.Schema != "nativefixture.owner.v2" || !safeName(m.Scope) || !safeName(m.Run) || len(m.Nonce) != 32 || !validSHA(m.Nonce+m.Nonce) || m.ExpiresUnixMs <= nowMs {
		return m, errors.New("Root owner scope/nonce/freshness")
	}
	if !validSHA(m.ContainerID) || m.Hostname != m.ContainerID[:12] || m.Namespaces[0] == "" || m.Namespaces[1] == "" || m.Namespaces[2] == "" {
		return m, errors.New("Root actual created container/hostname/namespace binding required")
	}
	if !cleanAbsolute(m.Socket) || len(m.Socket) > 100 || !cleanAbsolute(m.RetainedRoot) || !strings.HasPrefix(m.RetainedRoot, "/retained/endurance-") || !cleanAbsolute(m.EvidenceRoot) || !beneath(m.RetainedRoot, m.EvidenceRoot) {
		return m, errors.New("fixed fresh retained/evidence/socket namespace")
	}
	if len(m.Cases) == 0 || len(m.Cases) > 128 || len(m.GoArgs) == 0 || len(m.GoArgs) > 32 || m.OutputPrefixBytes < 1024 || m.OutputPrefixBytes > 16<<20 {
		return m, errors.New("finite Root case/output/argv bounds")
	}
	for _, a := range append([]Artifact{m.Owner, m.GoTest}, artifactValues(m.Artifacts)...) {
		if !cleanAbsolute(a.Path) || path.Dir(a.Path) != "/" || a.Bytes <= 0 || a.Bytes > MaxArtifact || !validSHA(a.SHA256) {
			return m, errors.New("Root-staged root-level exact artifacts required")
		}
	}
	if _, ok := m.Artifacts["current"]; !ok {
		return m, errors.New("current CLI descriptor missing")
	}
	for name, c := range m.Cases {
		if !safeName(name) || c.MaxFixtures < 1 || c.MaxFixtures > 4 {
			return m, errors.New("exact case/fixture bound")
		}
		for action, ms := range c.Actions {
			if !allowedAction(action) || ms <= 0 || ms > 3600000 {
				return m, errors.New("explicit action deadline required")
			}
		}
		for site, f := range c.Faults {
			if site != FaultSite(name) || f.Site != site || !f.BarrierRequired || !validSHA(f.BackupSHA) || !cleanAbsolute(f.BackupPath) || path.Dir(f.BackupPath) != "/" {
				return m, errors.New("exact Root fault/barrier/immutable backup receipt")
			}
			if f.CheckpointRoot != "" && (site != "adoption-prepared-changes-entry" || !cleanAbsolute(f.CheckpointRoot) || path.Dir(f.CheckpointRoot) != "/" || f.CheckpointRoot == f.BackupPath || f.CheckpointRoot == m.RetainedRoot) {
				return m, errors.New("separate Root-admitted PREPARED checkpoint directory required")
			}
		}
	}
	if len(m.Environment) == 0 || len(m.Environment) > 32 {
		return m, errors.New("finite public environment")
	}
	seen := map[string]bool{}
	for _, e := range m.Environment {
		k, _, ok := strings.Cut(e, "=")
		if !ok || seen[k] || k == "SSL_CERT_FILE" || k == "LD_PRELOAD" || k == "LD_LIBRARY_PATH" || strings.ContainsAny(e, "\x00\r\n") {
			return m, errors.New("exact nonconflicting reviewed env")
		}
		seen[k] = true
	}
	return m, nil
}
func FaultSite(testName string) string {
	switch testName {
	case "TestCompletionNativeBulkReadbackPauseRestartNoCopies":
		return "bulk-lost-committed-ack"
	case "TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal":
		return "proxy-sealed-original"
	case "TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent":
		return "route-loss-after-commit"
	case "TestStage3C01OrdinaryDaemonRestartBackupSemantics":
		return "c01-sealed-pending-original"
	case "TestStage3C12NativeReviewedPolicyScopesAndRestart":
		return "adoption-prepared-changes-entry"
	}
	return ""
}
func artifactValues(m map[string]Artifact) []Artifact {
	v := []Artifact{}
	for _, a := range m {
		v = append(v, a)
	}
	return v
}
func allowedAction(s string) bool {
	switch s {
	case "daemon", "status", "pause", "resume", "inspect", "checkpoint", "backup", "diagnostics", "migrate-plan", "adopt", "policy-plan", "policy-apply", "namespace-plan", "namespace-apply", "copy-indexed", "batch-current", "historical-r1e", "historical-r1f", "remount-current":
		return true
	}
	return false
}

// ReplayLedger allows concurrent RPC arrival order, but never duplicate tokens.
// No actor id, PID or fd supplied by a caller can become spawn/signal authority.
type ReplayLedger struct{ Seen map[uint64]bool }

func (l *ReplayLedger) Admit(m Manifest, r Request, pid, expectedPID int) error {
	if r.Schema != "nativefixture.rpc.v2" || r.Scope != m.Scope || r.Nonce != m.Nonce || pid <= 0 || pid != expectedPID {
		return errors.New("SCM sender/scope/nonce refused")
	}
	if r.Sequence == 0 || r.Sequence > MaxRPC {
		return errors.New("finite request sequence")
	}
	if l.Seen == nil {
		l.Seen = map[uint64]bool{}
	}
	if l.Seen[r.Sequence] {
		return errors.New("replayed request")
	}
	l.Seen[r.Sequence] = true
	return nil
}

func commandArgs(action, config, state, socket, profile, digest string) ([]string, error) {
	if !allowedAction(action) {
		return nil, errors.New("fixed action required")
	}
	a := []string{action, "--config", config, "--state", state}
	if action == "copy-indexed" {
		return a, nil
	}
	a = append(a, "--socket", socket)
	switch action {
	case "migrate-plan", "adopt", "policy-plan", "policy-apply", "namespace-plan", "namespace-apply":
		if profile == "" {
			return nil, errors.New("exact profile required")
		}
		a = append(a, "--profile", profile)
	}
	switch action {
	case "adopt", "policy-apply", "namespace-apply":
		if !validSHA(digest) {
			return nil, errors.New("exact plan digest")
		}
		a = append(a, "--plan-digest", digest)
	}
	return a, nil
}

func lifecycleError(a Actual, deadline, watchdog bool, numeric, drains, outputOK bool) string {
	if !a.Observed || a.Exited == a.Signaled || a.Exited && (a.ExitCode < 0 || a.ExitCode > 255) || a.Signaled && (a.Signal < 1 || a.ExitCode != -1) {
		return "ACTUAL_WAIT_UNKNOWN_OR_INVALID"
	}
	if !numeric {
		return "ACTUAL_NUMERIC_RECEIPT_NOT_DURABLE"
	}
	if !drains {
		return "DRAINS_NOT_JOINED"
	}
	if deadline || watchdog {
		return "DEADLINE_FAIL_ACTUAL_OUTCOME_RETAINED"
	}
	if !outputOK {
		return "OUTPUT_PREFIX_OR_IO_FAILURE"
	}
	return ""
}
func domainError(a Actual) string {
	if a.Exited && a.ExitCode == 0 {
		return ""
	}
	if a.Signaled {
		return fmt.Sprintf("signal %d raw=%d", a.Signal, a.RawStatus)
	}
	return fmt.Sprintf("exit %d", a.ExitCode)
}
