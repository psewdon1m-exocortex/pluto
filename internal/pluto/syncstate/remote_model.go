package syncstate

import (
	"errors"
	"pluto/internal/syncproto"
)

const RemoteSchemaVersion = 5
const MaxRemotePage = syncproto.MaxItems

var ErrRemoteUnqualified = errors.New("remote cut has no qualified server authority")
var ErrRemoteIncomplete = errors.New("remote snapshot preparation is incomplete")

type RemoteBinding = syncproto.Binding

// RemoteWitness is a CAS token for imported candidate state. It is deliberately
// not a server handshake, source continuity proof or permission to send bytes.
type RemoteWitness struct {
	RootID                                          string
	TrustGeneration, Generation, Revision, Position int64
	Binding                                         RemoteBinding
	Cursor                                          string
	Valid                                           bool
}

type RemoteCandidate struct {
	RemoteWitness
	SnapshotID                   string
	LastFeedHash, LastFeedCursor string
	LastFeedFrom                 int64
	HTTPRebootstrap              *HTTPRebootstrapCheckpoint `json:",omitempty"`
}

type SnapshotPreparation struct {
	RootID                                          string
	Generation, PreviousGeneration, TrustGeneration int64
	Snapshot                                        syncproto.Snapshot
	AfterNodeID                                     *string
	Cursor                                          string
	Complete                                        bool
	ExpiresMS                                       int64
}

// RemoteAuthority has no exported constructor. A future qualified adapter must
// mint this only after the actual server READY/feed/all-writer/conditional/status
// and fence handshake. Raw JSON shape validation cannot create this evidence.
type RemoteAuthority struct {
	witness                  RemoteWitness
	qualifiedAtMS, expiresMS int64
	transport                *CapturedHTTPIdentity
}

type CapturedDecision struct {
	Kind, Reason, OperationID string
	Witness                   CapturedWitness
	Remote                    *RemoteEntry
}

// Witness binds every state value read in one transaction. Future execution
// requires revalidation, even for advisory KEEP_REMOTE/RECOVER outcomes.
type CapturedWitness struct {
	RootID, EntryID, StateDigest string
	Source                       SnapshotEvidence
	Remote                       RemoteWitness
}
