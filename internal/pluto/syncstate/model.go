// Package syncstate provides an inactive durable-state foundation for Pluto.
// It does not discover changes, invoke the network, or authorize fast-path skips.
package syncstate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	SchemaVersion           = 2
	MaxBatch                = 1000
	MaxFileBytes      int64 = 256 * 1024 * 1024
	MaxActiveVersions       = 10
	TrustRequired           = "RECONCILIATION_REQUIRED"
)

var (
	ErrStaleGeneration   = errors.New("sync state generation changed")
	ErrUnsupportedSchema = errors.New("sync state schema is unsupported")
	ErrStateInUse        = errors.New("sync state has another writer")
	ErrIdentityConflict  = errors.New("sync state identity conflicts")
	ErrInvalidReceipt    = errors.New("sync publication receipt does not match the durable operation")
)

type RootBinding struct {
	RootID, MappingID, ServerIdentity, RemoteRootID, DeviceID, SourceIdentity string
}

type Root struct {
	RootBinding
	TrustGeneration, ActiveRemoteGeneration int64
	Trust, NameCodec                        string
	MaxFileBytes                            int64
	MaxActiveVersions                       int
	AllowsDelete, EngineReady               bool
}

type Observation struct {
	RootID, EntryID, ParentID, Name, NameKey, Kind, FileIdentity, Presence, SHA256 string
	ExpectedGeneration, Generation, SizeBytes, MTimeNS, HashGeneration             int64
}

type Baseline struct {
	PublishedMTimeNS                                                             int64 `json:",omitempty"`
	RootID, EntryID, NodeID, Epoch, Version, SHA256, Kind, Presence, OperationID string
	ParentID, Name, NameKey, FileIdentity                                        string
	LocalGeneration, TrustGeneration, SizeBytes, LastSeq                         int64
	RemoteBinding                                                                *RemoteBinding    `json:",omitempty"`
	RemoteParentID                                                               string            `json:",omitempty"`
	ContentVersionID                                                             string            `json:",omitempty"`
	CaptureProof                                                                 *SnapshotEvidence `json:",omitempty"`
}

type RemoteEntry struct {
	RootID, NodeID, ParentID, Name, Kind, Epoch, Version, SHA256, Presence, OperationID string
	Generation, SizeBytes, LastSeq                                                      int64
	Availability                                                                        string         `json:",omitempty"`
	ContentVersionID                                                                    string         `json:",omitempty"`
	RemoteBinding                                                                       *RemoteBinding `json:",omitempty"`
}

type Dirty struct {
	RootID, EntryID, Reasons      string
	ObservedGeneration, RemoteSeq int64
}

type Cursor struct {
	RootID, Stream, Epoch string
	Position              int64
	Valid                 bool
}

type EntryState struct {
	Local  Observation
	Base   *Baseline // nil is UNKNOWN, never a fresh remote observation.
	Remote *RemoteEntry
	Dirty  *Dirty
}

type Intent struct {
	OperationID, RootID, EntryID, Kind, ExpectedEpoch, ExpectedVersion, ExpectedNodeID string
	ParentID, Name, NameKey, FileIdentity                                              string
	LocalGeneration, TrustGeneration, SizeBytes                                        int64
	ExpectedAbsent                                                                     bool
	Dependencies                                                                       []string
	Captured                                                                           *CapturedOperationBinding `json:",omitempty"`
	FolderHTTP                                                                         *FolderHTTPOperation      `json:",omitempty"`
	Mutation                                                                           *MutationBinding          `json:",omitempty"`
	Stream                                                                             *StreamBinding            `json:",omitempty"`
}

type Operation struct {
	Intent
	Stage, SHA256, SnapshotID, IntentFingerprint, SealedFingerprint string
	HTTPBinding                                                     *HTTPUploadBinding `json:",omitempty"`
}

type Receipt struct {
	OperationID, RootID, EntryID, NodeID, Epoch, Version, SHA256, SealedFingerprint string
	LocalGeneration, SizeBytes, Seq                                                 int64
	Published, ContentVerified                                                      bool
	CapturedResult                                                                  *CapturedPublicationEvidence `json:",omitempty"`
}

func NewOperationID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(bytes[:])
	return hexID[:8] + "-" + hexID[8:12] + "-" + hexID[12:16] + "-" + hexID[16:20] + "-" + hexID[20:], nil
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func validHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func fingerprint(value any) string {
	raw, _ := json.Marshal(value)
	return hashBytes(raw)
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func checkBinding(root RootBinding) error {
	for _, value := range []string{root.RootID, root.MappingID, root.ServerIdentity, root.RemoteRootID, root.DeviceID, root.SourceIdentity} {
		if !validID(value) {
			return errors.New("root binding requires bounded opaque identities")
		}
	}
	return nil
}

func checkObservation(entry Observation) error {
	if !validID(entry.RootID) || !validID(entry.EntryID) || (entry.ParentID != "" && !validID(entry.ParentID)) || entry.ParentID == entry.EntryID {
		return errors.New("local entry identity invalid")
	}
	if !utf8.ValidString(entry.Name) || entry.Name == "" || len(entry.Name) > 4096 || strings.ContainsAny(entry.Name, "/\x00") || entry.Name == "." || entry.Name == ".." || entry.NameKey == "" || len(entry.NameKey) > 4096 {
		return errors.New("local entry name invalid")
	}
	if entry.Kind != "file" && entry.Kind != "folder" {
		return errors.New("local entry kind invalid")
	}
	if entry.Presence != "PRESENT" && entry.Presence != "ABSENT" && entry.Presence != "UNKNOWN" {
		return errors.New("local observation presence invalid")
	}
	if len(entry.FileIdentity) > 4096 || entry.ExpectedGeneration < 0 || entry.ExpectedGeneration == int64(^uint64(0)>>1) || entry.SizeBytes < 0 || (entry.SHA256 != "" && !validHash(entry.SHA256)) {
		return errors.New("local observation bounds invalid")
	}
	if entry.SHA256 != "" && entry.HashGeneration != entry.ExpectedGeneration+1 {
		return errors.New("content hash does not describe this local generation")
	}
	return nil
}

func checkRemote(entry RemoteEntry) error {
	if !validID(entry.RootID) || !validID(entry.NodeID) || !validID(entry.Epoch) || !validID(entry.Version) || entry.Generation < 1 || entry.LastSeq < 1 || entry.SizeBytes < 0 {
		return errors.New("remote entry identity/bounds invalid")
	}
	if entry.Kind != "file" && entry.Kind != "folder" {
		return errors.New("remote entry kind invalid")
	}
	if !utf8.ValidString(entry.Name) || entry.Name == "" || len(entry.Name) > 4096 || strings.ContainsAny(entry.Name, "/\x00") || entry.Name == "." || entry.Name == ".." || (entry.ParentID != "" && !validID(entry.ParentID)) || (entry.OperationID != "" && !validID(entry.OperationID)) {
		return errors.New("remote entry name/identity invalid")
	}
	if entry.Presence != "PRESENT" && entry.Presence != "ABSENT" {
		return errors.New("remote entry must state observed presence")
	}
	if entry.Kind == "file" && entry.Presence == "PRESENT" && !validHash(entry.SHA256) {
		return errors.New("remote file checksum invalid")
	}
	return nil
}

func checkBatch(size int) error {
	if size < 0 || size > MaxBatch {
		return fmt.Errorf("state batches are limited to %d rows", MaxBatch)
	}
	return nil
}
