package syncstate

import "errors"

// Local lifecycle only. Operation status/idempotency remain in operations.
const (
	ArtifactSchemaVersion = 4
	ArtifactDirectoryName = "sync-artifacts-v1"
	MaxArtifactRecords    = 4096
	ArtifactReserved      = "RESERVED"
	ArtifactCapturing     = "CAPTURING"
	ArtifactSealed        = "SEALED"
	ArtifactDisposing     = "DISPOSING"
	ArtifactGone          = "GONE"
)

var (
	ErrArtifactUnreconciled = errors.New("local artifacts need explicit reconciliation before work")
	ErrArtifactInUse        = errors.New("artifact users must join before disposal or store close")
	ErrArtifactRetained     = errors.New("pending immutable operation retains its artifact")
)

type ArtifactRecord struct {
	ID, Name, Phase, FileIdentity, SHA256, SnapshotID, OperationID string
	ExpectedBytes, SizeBytes                                       int64
}

// Complete=false is not an absence proof. Charge is conservative on refusal.
type ArtifactReport struct {
	ScopeID, OwnerID, Directory                  string
	Records, Files, ReservedBytes, ObservedBytes int64
	RecoveryOperations                           int64
	QuarantinedEmptyFiles                        int64
	Complete, Admitted                           bool
	Problems                                     []string
}

type ArtifactLimits struct {
	Records        int
	PlaintextBytes int64
}

func DefaultArtifactLimits() ArtifactLimits { return ArtifactLimits{MaxArtifactRecords, MaxFileBytes} }
