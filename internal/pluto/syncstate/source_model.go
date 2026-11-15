package syncstate

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// This optional local-only module cannot authorize a planner or server effect.
const (
	SourceSchemaVersion = 3
	MaxSources          = 128
	MaxSourcePage       = 128
	MaxSourcePageBytes  = 4 * 1024 * 1024
	MaxSourceDepth      = 128
)

var (
	ErrSourceIncomplete = errors.New("local source scan is incomplete")
	ErrSourceQuota      = errors.New("local source state admission budget exhausted")
	ErrSourceAmbiguous  = errors.New("different source objects map to the same backup destination")
	ErrCaptureChanged   = errors.New("source changed during guarded capture")
)

type SourceLimits struct{ DatabaseBytes, WALBytes, BackupBytes, FreeDiskBytes int64 }

func DefaultSourceLimits() SourceLimits { return SourceLimits{4 << 30, 64 << 20, 4 << 30, 1 << 30} }

type SourceSpec struct{ ID, SelectedPath, WorkingDirectory string }
type SourceSet struct {
	ID, ConfigDigest, OwnerID, AttachedRootID string
	Revision, GapGeneration, OwnerSequence    int64
}
type SourceObject struct {
	FileIdentity, LinkGuard, BootIdentity, MountID string
	MountKnown                                     bool
}
type SourceBinding struct {
	SourceSpec
	Destination, PhysicalPath string
	Revision                  int64
	Active                    bool
	Object, PendingObject     SourceObject
	Incarnation               int64
	IncarnationStatus         string
}
type SourceWitness struct {
	SetID, OwnerID                         string
	Revision, GapGeneration, OwnerSequence int64
}
type Scan struct {
	ID, SourceID, Status, Reason string
	Witness                      SourceWitness
	Pages                        int64
}
type FrontierClaim struct {
	ScanID, Token, PhysicalPath, Destination string
	WorkID, Page                             int64
	Depth                                    int
	Witness                                  SourceWitness
}
type SourceDescriptor struct {
	Destination, PhysicalPath, Kind, Presence, FileIdentity string
	SizeBytes, MTimeNS, CTimeNS, ExpectedGeneration         int64
}
type SourceEntry struct {
	SourceDescriptor
	SetID, SourceID, SourceRootPath                    string
	Generation, VerificationRequest, SourceIncarnation int64
	SourceObject                                       SourceObject
	Ambiguous                                          bool
}
type ScanPage struct {
	Entries          []SourceDescriptor
	Children         []SourceDescriptor
	EOF              bool
	IncompleteReason string
}
type VerificationWork struct {
	Entry   SourceEntry
	Request int64
}

// SnapshotEvidence is historical evidence of sealed bytes at an exact capture.
// It is deliberately not a LocalCutProof/ContinuousJournal/ReconciledRoot.
type SnapshotEvidence struct {
	SetID, SourceID, Destination, SnapshotID, SHA256, GuardDigest      string
	Witness                                                            SourceWitness
	EntryGeneration, VerificationRequest, SizeBytes, SourceIncarnation int64
}

func sourceDestination(p string) string { return strings.TrimLeft(filepath.ToSlash(p), "/") }
func validSourcePath(p string) bool {
	return p != "" && len(p) <= 4096 && utf8.ValidString(p) && !strings.ContainsRune(p, 0)
}
func validDestination(p string) bool {
	if !validSourcePath(p) || strings.HasPrefix(p, "/") {
		return false
	}
	parts := strings.Split(p, "/")
	if len(parts) > MaxSourceDepth {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func checkSourceDescriptor(d SourceDescriptor) error {
	if !validDestination(d.Destination) || !validSourcePath(d.PhysicalPath) || !filepath.IsAbs(d.PhysicalPath) || len(d.FileIdentity) > 4096 || d.ExpectedGeneration < 0 || d.ExpectedGeneration >= int64(^uint64(0)>>1) || d.SizeBytes < 0 {
		return errors.New("source descriptor bounds invalid")
	}
	if d.Kind != "file" && d.Kind != "folder" {
		return errors.New("source type invalid")
	}
	if d.Presence != "PRESENT" && d.Presence != "UNKNOWN" {
		return errors.New("source absence requires a complete reconciliation, never a missing stat")
	}
	return nil
}
