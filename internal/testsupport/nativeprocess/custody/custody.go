// Package nativecustody contains pure parsing and admission decisions only.
// No function opens a file, starts a process, waits, or sends a signal.
package nativecustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxStat = 8192
const MaxCmdline = 8192
const MaxStatus = 16384
const MaxManifest = 65536
const MaxCandidate = 64 << 20

type Birth struct {
	PID, PPID int
	Ticks     uint64
	State     byte
}

type Profile struct {
	UID, GID     [4]uint32
	Groups       []uint32
	Caps         [5]uint64 // Inh, Prm, Eff, Bnd, Amb; all five are mandatory.
	NNP, Seccomp uint32
}

type Tuple struct {
	Birth, Parent  Birth
	PIDFDTarget    int
	Exe, ExeSHA256 string
	Argv           []string
	Profile        Profile
}

type Handle struct {
	OwnStartPID int
	AtomicPIDFD bool
	FD          int
}

type Artifact struct {
	LogicalPath, SHA256 string
	Bytes               int64
}

type FileView struct {
	Path             string
	Device, Inode    uint64
	UID, GID         uint32
	Mode             uint32
	Regular, Symlink bool
	Bytes            int64
	SHA256           string
}

type Namespace struct {
	Path               string
	Device, Inode      uint64
	UID, GID, Mode     uint32
	Directory, Symlink bool
}

func bounded(raw []byte, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum || bytes.IndexByte(raw, 0) >= 0 || !utf8.Valid(raw) {
		return errors.New("bounded non-NUL UTF8 input required")
	}
	return nil
}

func decimal(s string, bits int) (uint64, error) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("unsigned decimal required")
	}
	return strconv.ParseUint(s, 10, bits)
}

// ParseStat uses the last ')' because a comm may contain spaces and ')'.
func ParseStat(raw []byte) (Birth, error) {
	var result Birth
	if err := bounded(raw, MaxStat); err != nil {
		return result, err
	}
	text := strings.TrimSuffix(string(raw), "\n")
	open, close := strings.Index(text, " ("), strings.LastIndex(text, ") ")
	if open < 1 || close <= open+2 {
		return result, errors.New("stat comm delimiters")
	}
	pid, err := decimal(text[:open], 31)
	if err != nil || pid == 0 {
		return result, errors.New("stat positive PID")
	}
	fields := strings.Fields(text[close+2:])
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.ContainsRune("RSDZTWtXIP", rune(fields[0][0])) {
		return result, errors.New("stat mandatory fields/state")
	}
	ppid, err := decimal(fields[1], 31)
	if err != nil {
		return result, errors.New("stat PPID")
	}
	ticks, err := decimal(fields[19], 64) // state=field3, starttime=field22.
	if err != nil || ticks == 0 {
		return result, errors.New("stat positive startticks")
	}
	return Birth{PID: int(pid), PPID: int(ppid), Ticks: ticks, State: fields[0][0]}, nil
}

func ParseCmdline(raw []byte) ([]string, error) {
	if len(raw) < 2 || len(raw) > MaxCmdline || raw[len(raw)-1] != 0 {
		return nil, errors.New("bounded terminated cmdline")
	}
	parts := bytes.Split(raw[:len(raw)-1], []byte{0})
	if len(parts) > 32 {
		return nil, errors.New("cmdline argument limit")
	}
	result := make([]string, len(parts))
	for index, part := range parts {
		if len(part) == 0 || !utf8.Valid(part) {
			return nil, errors.New("nonempty UTF8 argument")
		}
		result[index] = string(part)
	}
	return result, nil
}

func ParseStatus(raw []byte) (Profile, error) {
	var result Profile
	if err := bounded(raw, MaxStatus); err != nil {
		return result, err
	}
	required := map[string]bool{"Uid": true, "Gid": true, "Groups": true, "CapInh": true, "CapPrm": true, "CapEff": true, "CapBnd": true, "CapAmb": true, "NoNewPrivs": true, "Seccomp": true}
	seen := map[string]bool{}
	caps := map[string]int{"CapInh": 0, "CapPrm": 1, "CapEff": 2, "CapBnd": 3, "CapAmb": 4}
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || !required[name] {
			continue
		}
		if seen[name] {
			return result, fmt.Errorf("duplicate status %s", name)
		}
		seen[name] = true
		fields := strings.Fields(value)
		switch name {
		case "Uid", "Gid":
			if len(fields) != 4 {
				return result, errors.New("four UID/GID fields")
			}
			for index, field := range fields {
				number, err := decimal(field, 32)
				if err != nil {
					return result, err
				}
				if name == "Uid" {
					result.UID[index] = uint32(number)
				} else {
					result.GID[index] = uint32(number)
				}
			}
		case "Groups":
			if len(fields) > 64 {
				return result, errors.New("group limit")
			}
			result.Groups = []uint32{}
			groups := map[uint32]bool{}
			for _, field := range fields {
				number, err := decimal(field, 32)
				if err != nil {
					return result, err
				}
				group := uint32(number)
				if groups[group] {
					return result, errors.New("duplicate group")
				}
				groups[group] = true
				result.Groups = append(result.Groups, group)
			}
		case "NoNewPrivs", "Seccomp":
			if len(fields) != 1 {
				return result, errors.New("singleton status scalar")
			}
			number, err := decimal(fields[0], 32)
			if err != nil || name == "NoNewPrivs" && number > 1 || name == "Seccomp" && number > 2 {
				return result, errors.New("status scalar range")
			}
			if name == "NoNewPrivs" {
				result.NNP = uint32(number)
			} else {
				result.Seccomp = uint32(number)
			}
		default:
			if len(fields) != 1 || len(fields[0]) != 16 || strings.IndexFunc(fields[0], func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') }) >= 0 {
				return result, errors.New("capability hex64")
			}
			number, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				return result, err
			}
			result.Caps[caps[name]] = number
		}
	}
	if len(seen) != len(required) {
		return result, errors.New("missing mandatory profile fields")
	}
	return result, nil
}

// ParsePIDFDTarget rejects reaped/dead pidfds (Pid:-1) and ambiguous input.
func ParsePIDFDTarget(raw []byte) (int, error) {
	if err := bounded(raw, 4096); err != nil {
		return 0, err
	}
	found, pid := false, 0
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name != "Pid" {
			continue
		}
		if found {
			return 0, errors.New("duplicate pidfd Pid")
		}
		found = true
		fields := strings.Fields(value)
		if len(fields) != 1 {
			return 0, errors.New("pidfd singleton Pid")
		}
		number, err := decimal(fields[0], 31)
		if err != nil || number == 0 {
			return 0, errors.New("pidfd not a live target")
		}
		pid = int(number)
	}
	if !found {
		return 0, errors.New("missing pidfd Pid")
	}
	return pid, nil
}

func validSHA(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// AdmitManifest first authenticates exact Root-pinned public report bytes.
// Unused report metadata is ignored only AFTER that exact digest comparison.
func AdmitManifest(raw []byte, pinnedSHA string) (Artifact, error) {
	var result Artifact
	if len(raw) == 0 || len(raw) > MaxManifest || !validSHA(pinnedSHA) {
		return result, errors.New("Root manifest pin/bound required")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != pinnedSHA {
		return result, errors.New("Root manifest byte mismatch")
	}
	var report struct {
		Schema   int    `json:"schema_version"`
		Status   string `json:"status"`
		Version  string `json:"version"`
		Compiler string `json:"compiler"`
		Binaries []struct {
			Architecture string `json:"architecture"`
			Path         string `json:"path"`
			Bytes        int64  `json:"bytes"`
			SHA256       string `json:"sha256"`
		} `json:"runtime_binaries"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&report); err != nil {
		return result, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, errors.New("manifest trailing data")
	}
	if report.Schema != 1 || report.Status != "PASS_UNSIGNED_LOCAL_TRUST_COMPOSITION_ONLY" || report.Version != "0.1.5" || report.Compiler != "go1.26.10" {
		return result, errors.New("exact Root candidate contract")
	}
	found := false
	for _, binary := range report.Binaries {
		if binary.Architecture != "linux-amd64" {
			continue
		}
		if found || binary.Bytes <= 0 || binary.Bytes > MaxCandidate || !validSHA(binary.SHA256) || binary.Path != "raw/pluto-production-trust-artifacts-minimal-a01/pluto-linux-amd64" {
			return result, errors.New("ambiguous/invalid Root artifact")
		}
		found = true
		result = Artifact{LogicalPath: binary.Path, Bytes: binary.Bytes, SHA256: binary.SHA256}
	}
	if !found {
		return result, errors.New("missing Root artifact")
	}
	return result, nil
}

func CheckArtifact(expected Artifact, before, after FileView, namespace, namespaceAfter Namespace) error {
	if expected.LogicalPath != "raw/pluto-production-trust-artifacts-minimal-a01/pluto-linux-amd64" || expected.Bytes <= 0 || expected.Bytes > MaxCandidate || !validSHA(expected.SHA256) {
		return errors.New("Root descriptor missing")
	}
	if before != after {
		return errors.New("candidate changed during read")
	}
	if !before.Regular || before.Symlink || before.Device == 0 || before.Inode == 0 || before.UID != 0 || before.GID != 0 || before.Mode != 0555 || before.Bytes != expected.Bytes || before.SHA256 != expected.SHA256 {
		return errors.New("regular bounded readonly candidate identity")
	}
	base := path.Base(before.Path)
	nonce := strings.TrimSuffix(strings.TrimPrefix(base, "exocortex-cnative-"), ".cli")
	if path.Clean(before.Path) != before.Path || path.Dir(before.Path) != "/" || base != "exocortex-cnative-"+nonce+".cli" || len(nonce) != 16 || strings.IndexFunc(nonce, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) >= 0 {
		return errors.New("fixed root-level staged candidate required")
	}
	if namespace != namespaceAfter {
		return errors.New("root namespace changed during read")
	}
	if namespace.Path != "/" || !namespace.Directory || namespace.Symlink || namespace.Device == 0 || namespace.Inode == 0 || namespace.UID != 0 || namespace.GID != 0 || namespace.Mode != 0755 {
		return errors.New("readonly root namespace custody")
	}
	return nil
}

func live(birth Birth) bool {
	return birth.PID > 0 && birth.Ticks > 0 && strings.ContainsRune("RSDTWtIP", rune(birth.State))
}
func sameBirth(a, b Birth) bool {
	return a.PID == b.PID && a.PPID == b.PPID && a.Ticks == b.Ticks && live(a) && live(b)
}

func RequireRuntimeProfile(profile Profile) error {
	if profile.UID != [4]uint32{10001, 10001, 10001, 10001} || profile.GID != [4]uint32{10001, 10001, 10001, 10001} || len(profile.Groups) != 0 || profile.Caps != [5]uint64{} || profile.NNP != 1 || profile.Seccomp != 2 {
		return errors.New("Root-admitted nonadmin cap0 NNP1 profile required")
	}
	return nil
}

func CheckTuple(expected, actual, confirm Tuple, handle Handle) error {
	if !handle.AtomicPIDFD || handle.FD < 0 || handle.OwnStartPID != expected.Birth.PID {
		return errors.New("atomic SAME Start pidfd required; no PID-only fallback")
	}
	if err := RequireRuntimeProfile(expected.Profile); err != nil {
		return err
	}
	if !live(expected.Birth) || !live(expected.Parent) || expected.Birth.PPID != expected.Parent.PID || !validSHA(expected.ExeSHA256) || expected.Exe == "" || len(expected.Argv) == 0 || expected.Argv[0] != expected.Exe {
		return errors.New("incomplete own birth/artifact expectation")
	}
	for _, tuple := range []Tuple{actual, confirm} {
		if !sameBirth(expected.Birth, tuple.Birth) || !sameBirth(expected.Parent, tuple.Parent) || tuple.PIDFDTarget != handle.OwnStartPID {
			return errors.New("PID/birth/parent/pidfd changed")
		}
		if tuple.Exe != expected.Exe || tuple.ExeSHA256 != expected.ExeSHA256 || !reflect.DeepEqual(tuple.Argv, expected.Argv) || !reflect.DeepEqual(tuple.Profile, expected.Profile) {
			return errors.New("exe/argv/profile mismatch")
		}
	}
	return nil
}

type Policy struct {
	CrashRequested, Watchdog bool
	Test                     string
	Signal                   int
}

func SignalAllowed(expected, actual, confirm Tuple, handle Handle, policy Policy) error {
	if err := CheckTuple(expected, actual, confirm, handle); err != nil {
		return err
	}
	if policy.Watchdog {
		return errors.New("watchdog FAIL+ordinary join, no later signal")
	}
	if !policy.CrashRequested {
		if policy.Signal != 15 {
			return errors.New("ordinary stop only SIGTERM")
		}
		return nil
	}
	allowed := map[string]bool{
		"TestCompletionNativeBulkReadbackPauseRestartNoCopies":            true,
		"TestCompletionDaemonProxyReopenRetainsDeletedSourceOriginal":     true,
		"TestCompletionDaemonRestartsAfterOwnedRouteLossWithoutFileEvent": true,
		"TestStage3C01OrdinaryDaemonRestartBackupSemantics":               true,
	}
	if policy.Signal != 9 || !allowed[policy.Test] {
		return errors.New("explicit reviewed crash site only")
	}
	return nil
}

type WaitResult struct {
	Observed, Exited, Signaled bool
	ExitCode, Signal           int
	RawStatus                  uint32
}

// JoinDisposition never permits diagnostics before an actual outcome receipt is
// committed by the integration adapter. A late0 cannot erase the watchdog FAIL.
func JoinDisposition(result WaitResult, receiptCommitted, watchdog, crash, custodyAdmitted bool) (string, error) {
	if !result.Observed || result.Exited == result.Signaled || result.Exited && (result.ExitCode < 0 || result.ExitCode > 255) || result.Signaled && result.Signal <= 0 {
		return "", errors.New("actual normal exit or signal outcome required")
	}
	if !receiptCommitted {
		return "", errors.New("actual Wait receipt must be durable before diagnostic metadata")
	}
	if !custodyAdmitted {
		return "FAIL_CUSTODY_WITH_ACTUAL_OUTCOME", nil
	}
	if watchdog {
		return "FAIL_WATCHDOG_WITH_ACTUAL_OUTCOME", nil
	}
	if crash {
		if result.Signaled && result.Signal == 9 {
			return "INTENTIONAL_CRASH_JOINED", nil
		}
		return "FAIL_REQUESTED_CRASH_NOT_OBSERVED", nil
	}
	if result.Exited && result.ExitCode == 0 {
		return "NATURAL_JOINED0", nil
	}
	return "FAIL_ORDINARY_EXIT_WITH_ACTUAL_OUTCOME", nil
}
