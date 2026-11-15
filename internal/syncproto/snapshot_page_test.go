package syncproto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSnapshotPageSharedRawVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/snapshot-pages.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Snapshot json.RawMessage `json:"snapshot"`
		Cases    []struct {
			Name        string
			AfterNodeID *string `json:"afterNodeId"`
			InputHex    string
			Accepted    bool
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadSnapshot(corpus.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range corpus.Cases {
		t.Run(row.Name, func(t *testing.T) {
			input, err := hex.DecodeString(row.InputHex)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ReadSnapshotEntries(input, snapshot, row.AfterNodeID)
			if (err == nil) != row.Accepted {
				t.Fatalf("shared page acceptance=%v expected=%v error=%v", err == nil, row.Accepted, err)
			}
		})
	}
}

func TestSnapshotPageIgnoredNumericFieldsUseReceivedBudget(t *testing.T) {
	raw, err := os.ReadFile("testdata/snapshot-pages.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Snapshot json.RawMessage
		Cases    []struct {
			Name        string
			AfterNodeID *string `json:"afterNodeId"`
			InputHex    string
		}
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadSnapshot(corpus.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range corpus.Cases {
		if row.Name != "nonempty terminal page" {
			continue
		}
		input, err := hex.DecodeString(row.InputHex)
		if err != nil {
			t.Fatal(err)
		}
		input = []byte(string(input[:len(input)-1]) + ",\"future\":[" + strings.TrimSuffix(strings.Repeat("1e4,", 710000), ",") + "]}")
		if len(input) >= MaxBytes {
			t.Fatal("fixture exceeds raw budget")
		}
		page, err := ReadSnapshotEntries(input, snapshot, row.AfterNodeID)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 2 || page.Items[0].SizeBytes != "9007199254740993" {
			t.Fatal("exact page changed")
		}
		return
	}
	t.Fatal("fixture absent")
}

func TestSnapshotPageRejectsUnqualifiedContextAndRawBudget(t *testing.T) {
	raw, err := os.ReadFile("testdata/snapshot-pages.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Snapshot json.RawMessage
		Cases    []struct{ InputHex string }
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadSnapshot(corpus.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	input, err := hex.DecodeString(corpus.Cases[0].InputHex)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.LeaseSeconds = 0
	if _, err = ReadSnapshotEntries(input, snapshot, nil); err == nil {
		t.Fatal("unqualified lease context accepted")
	}
	snapshot, err = ReadSnapshot(corpus.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadSnapshotEntries(make([]byte, MaxBytes+1), snapshot, nil); err != ErrLimit {
		t.Fatal("raw page budget not enforced", err)
	}
}
