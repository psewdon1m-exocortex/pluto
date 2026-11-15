package syncstate

import (
	"pluto/internal/syncproto"
	"testing"
)

// A publication can journal its file first and then update ancestor sizes.
// Its receipt covers the whole transaction; the file's last event is earlier.
func TestCapturedRepeatAfterPublicationWithAncestorEvents(t *testing.T) {
	for _, scenario := range []string{"complete", "partial-cut", "changed-version", "changed-content"} {
		t.Run(scenario, func(t *testing.T) {
			r, w, v, entry, candidate, op := createCapturedOperationFixture(t)
			if err := r.store.artifacts.BindOperation(testContext, op.SnapshotID, op.OperationID); err != nil {
				t.Fatal(err)
			}
			if err := r.SubmittedCaptured(testContext, w, v, fixtureRemoteAuthority(candidate), op.OperationID, remoteNow); err != nil {
				t.Fatal(err)
			}
			pub := publicationFixture(op)
			pub.FirstSeq = candidate.Position + 1
			pub.Receipt.Seq = candidate.Position + 2
			pub.Description.LastSeq = pub.Receipt.Seq
			if err := r.AckCaptured(testContext, pub); err != nil {
				t.Fatal(err)
			}
			leaf := fileRemote(pub.Description.NodeID, pub.Description.ParentID, op.Name, "one")
			leaf.Version = pub.Description.Version
			leaf.ContentVersionID = &pub.Description.ContentVersionID
			items := []syncproto.FeedItem{{Descriptor: leaf, Seq: remoteDecimal(pub.FirstSeq), Kind: "upsert", OperationID: op.OperationID}}
			if scenario != "partial-cut" {
				parent := folderRemote(candidate.Binding.RootID, "", "root")
				parent.SizeBytes = "3"
				parent.Version = remoteVersion(20)
				items = append(items, syncproto.FeedItem{Descriptor: parent, Seq: remoteDecimal(pub.Receipt.Seq), Kind: "upsert", OperationID: op.OperationID})
			}
			current, err := r.ImportFeed(testContext, candidate.RemoteWitness, wireFeed(candidate.RemoteWitness, items, "after-publication"))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "changed-version" || scenario == "changed-content" {
				leaf.Version = remoteVersion(21)
				if scenario == "changed-content" {
					sha := hashBytes([]byte("two"))
					leaf.ContentSHA256 = &sha
				}
				current, err = r.ImportFeed(testContext, current.RemoteWitness, wireFeed(current.RemoteWitness, []syncproto.FeedItem{{Descriptor: leaf, Seq: remoteDecimal(current.Position + 1), Kind: "upsert", OperationID: "external-change"}}, "after-external"))
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := r.store.Operation(testContext, op.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := r.DecideCaptured(testContext, w, "root", entry, v, fixtureRemoteAuthority(current), remoteNow)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "complete" {
				if decision.Kind != "NOOP_CAPTURED" {
					t.Fatalf("complete publication cut should agree: %+v", decision)
				}
				if err := r.AdoptCaptured(testContext, w, v, fixtureRemoteAuthority(current), decision, remoteNow); err != nil {
					t.Fatal(err)
				}
			} else if decision.Kind != "CONFLICT" && decision.Kind != "RECONCILE" {
				t.Fatalf("incomplete or changed authority permitted agreement: %+v", decision)
			}
			after, err := r.store.Operation(testContext, op.OperationID)
			if err != nil || fingerprint(before) != fingerprint(after) {
				t.Fatal("historical operation changed", err)
			}
		})
	}
}
