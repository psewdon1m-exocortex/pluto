package syncstate

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
)

// This is a local regression fixture, not release or historical evidence.
// Only the source mount observation changes; the retained intent stays exact.
func retainedRemountStreamFixture(t *testing.T) (*IsolatedHTTPSession, Operation, *p02V2Server, []byte, SourceWitness, SourceBinding) {
	t.Helper()
	s, op, server, data := p02V2TransportFixture(t)
	root, err := s.r.store.Root(testContext, op.RootID)
	if err != nil {
		t.Fatal(err)
	}
	set, err := s.r.sources.Set(testContext, root.SourceIdentity)
	if err != nil {
		t.Fatal(err)
	}
	set, err = s.r.sources.BindSourceSet(testContext, set.ID, hashBytes([]byte("retained-remount-config")), set.Revision, []SourceSpec{{ID: "remount-source", SelectedPath: op.Stream.Source.SourceRootPath}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.r.sources.BeginSourceOwner(testContext, set.ID, set.Revision, id)
	if err != nil {
		t.Fatal(err)
	}
	w, err = s.r.sources.RequalifyOwnerMounts(testContext, w, []string{"remount-source"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.r.sources.Binding(testContext, w.SetID, "remount-source")
	if err != nil {
		t.Fatal(err)
	}
	old := b
	old.Object.MountID = "900000001"
	writeRemountBinding(t, s.r.sources, w, old)
	op.Stream.Source.SetID = set.ID
	op.Stream.Source.SourceID = b.ID
	op.Stream.Source.SourceObject = old.Object
	op.Stream.Source.SourceIncarnation = old.Incarnation
	op.Stream.Source.Kind = "file"
	op.Stream.Source.Presence = "PRESENT"
	op.Stream.Witness = w
	op.IntentFingerprint = fingerprint(op.Intent)
	if _, err = s.r.store.db.Exec("UPDATE operations SET intent_json=?,intent_fingerprint=? WHERE operation_id=?", string(mustJSON(op.Intent)), op.IntentFingerprint, op.OperationID); err != nil {
		t.Fatal(err)
	}
	w = freshRemountOwner(t, s.r.sources, w)
	w, err = s.r.sources.RequalifyOwnerMounts(testContext, w, []string{b.ID})
	if err != nil {
		t.Fatal(err)
	}
	b, err = s.r.sources.Binding(testContext, w.SetID, b.ID)
	if err != nil || !mountOnlyReobservation(old.Object, b.Object) || b.Incarnation != old.Incarnation+1 {
		t.Fatal(b, err)
	}
	server.op = op
	return s, op, server, data, w, b
}

func TestStreamRemountOriginalV2ResumesAcceptedMountWithoutReplacingIntent(t *testing.T) {
	s, op, server, data, _, _ := retainedRemountStreamFixture(t)
	before, err := s.r.store.Operation(testContext, op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := s.updateStreamV2Progress(testContext, op, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.streamV2Source(testContext, op, p, p02V2Acquire)
	if err != nil || got != hashBytes(data) {
		t.Fatalf("accepted mount-only observation cannot resume original: hash=%s err=%v", got, err)
	}
	after, err := s.r.store.Operation(testContext, op.OperationID)
	if err != nil || string(mustJSON(before.Intent)) != string(mustJSON(after.Intent)) || before.IntentFingerprint != after.IntentFingerprint || before.OperationID != after.OperationID {
		t.Fatal("immutable original changed", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.parts) != 4 || server.maximum != 2 || server.active != 0 {
		t.Fatal("bounded complete original stream", len(server.parts), server.maximum, server.active)
	}
	info, err := os.Stat(op.Stream.Source.PhysicalPath)
	if err != nil || !streamSourceMatches(op.Stream.Source, info) {
		t.Fatal("original source changed", err)
	}
}

func TestStreamRemountOriginalV2RejectsUnqualifiedSourceOrOwner(t *testing.T) {
	for _, kind := range []string{"unaccepted", "unknown", "boot", "inode", "link", "mount-unknown", "revision", "owner", "gap", "inactive", "root", "incarnation", "pending", "changed-file", "same-bytes-new-ctime"} {
		t.Run(kind, func(t *testing.T) {
			s, op, server, data, w, b := retainedRemountStreamFixture(t)
			switch kind {
			case "unaccepted":
				b.Object = op.Stream.Source.SourceObject
			case "unknown":
				b.IncarnationStatus = "UNKNOWN"
				b.PendingObject = b.Object
			case "boot":
				op.Stream.Source.SourceObject.BootIdentity = "other-boot"
			case "inode":
				op.Stream.Source.SourceObject.FileIdentity = "other-inode"
			case "link":
				op.Stream.Source.SourceObject.LinkGuard = "other-link"
			case "mount-unknown":
				op.Stream.Source.SourceObject.MountKnown = false
			case "revision":
				if _, err := s.r.store.db.Exec("UPDATE source_sets SET revision=revision+1 WHERE set_id=?", w.SetID); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if _, err := s.r.store.db.Exec("UPDATE source_sets SET owner_id='another-owner' WHERE set_id=?", w.SetID); err != nil {
					t.Fatal(err)
				}
			case "gap":
				if _, err := s.r.store.db.Exec("UPDATE source_sets SET gap_generation=gap_generation+1 WHERE set_id=?", w.SetID); err != nil {
					t.Fatal(err)
				}
			case "inactive":
				if _, err := s.r.store.db.Exec("UPDATE source_bindings SET active=0 WHERE set_id=? AND source_id=?", w.SetID, b.ID); err != nil {
					t.Fatal(err)
				}
			case "root":
				if _, err := s.r.store.db.Exec("UPDATE source_sets SET attached_root_id=NULL WHERE set_id=?", w.SetID); err != nil {
					t.Fatal(err)
				}
			case "incarnation":
				b.Incarnation = op.Stream.Source.SourceIncarnation
			case "pending":
				b.PendingObject = b.Object
			case "changed-file":
				if err := os.WriteFile(op.Stream.Source.PhysicalPath, []byte("new generation"), 0600); err != nil {
					t.Fatal(err)
				}
			case "same-bytes-new-ctime":
				if err := os.WriteFile(op.Stream.Source.PhysicalPath, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "inactive" {
				writeRemountBinding(t, s.r.sources, w, b)
			}
			op.IntentFingerprint = fingerprint(op.Intent)
			if _, err := s.r.store.db.Exec("UPDATE operations SET intent_json=?,intent_fingerprint=? WHERE operation_id=?", string(mustJSON(op.Intent)), op.IntentFingerprint, op.OperationID); err != nil {
				t.Fatal(err)
			}
			p, _, err := s.updateStreamV2Progress(testContext, op, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.streamV2Source(testContext, op, p, p02V2Acquire); !errors.Is(err, ErrCaptureChanged) {
				t.Fatalf("unqualified %s read admitted: %v", kind, err)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.parts) != 0 || server.active != 0 {
				t.Fatal("rejected source sent new content", len(server.parts), server.active)
			}
		})
	}
}

type streamRemountRoundTrip func(*http.Request) (*http.Response, error)

func (f streamRemountRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStreamRemountOriginalV2RevalidatesOwnerAfterJoinedRead(t *testing.T) {
	s, op, server, _, w, _ := retainedRemountStreamFixture(t)
	var once sync.Once
	s.client.Transport = streamRemountRoundTrip(func(request *http.Request) (*http.Response, error) {
		response, err := server.RoundTrip(request)
		if strings.HasSuffix(request.URL.Path, "/chunk") {
			once.Do(func() {
				if _, e := s.r.store.db.Exec("UPDATE source_sets SET gap_generation=gap_generation+1 WHERE set_id=?", w.SetID); e != nil {
					t.Error(e)
				}
			})
		}
		return response, err
	})
	p, _, err := s.updateStreamV2Progress(testContext, op, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.streamV2Source(testContext, op, p, p02V2Acquire); !errors.Is(err, ErrCaptureChanged) {
		t.Fatal("source owner changed during read", err)
	}
	after, err := s.r.store.Operation(testContext, op.OperationID)
	if err != nil || after.SHA256 != "" || after.Stage != "SUBMITTED" || after.IntentFingerprint != op.IntentFingerprint {
		t.Fatal("rejected read sealed or changed original", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.active != 0 || server.maximum != 2 || len(server.sealHashes) != 0 {
		t.Fatal("accepted IO not joined or unqualified seal", server.active, server.maximum, server.sealHashes)
	}
}
