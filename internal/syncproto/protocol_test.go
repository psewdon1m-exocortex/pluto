package syncproto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedContractBoundaries(t *testing.T) {
	corpusPath := os.Getenv("SYNC_WIRE_CORPUS_PATH")
	if corpusPath == "" {
		corpusPath = "testdata/boundaries.v1.json"
	}
	raw, e := os.ReadFile(corpusPath)
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Binding map[string]any `json:"binding"`
		After   string         `json:"after"`
		Cases   []struct {
			Kind, Name, InputHex string
			Accepted             bool
		} `json:"cases"`
	}
	if e = json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	b, e := ReadBinding(c.Binding)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range c.Cases {
		t.Run(v.Name, func(t *testing.T) {
			input, e := hex.DecodeString(v.InputHex)
			if e != nil {
				t.Fatal(e)
			}
			x, e := Parse(input)
			if e == nil {
				switch v.Kind {
				case "integer64":
					_, e = Integer64(x)
				case "descriptor":
					_, e = ReadDescriptor(x)
				case "expected":
					e = ReadExpected(input)
				case "snapshot":
					_, e = ReadSnapshot(input)
				case "feed":
					_, e = ReadFeed(input, b, c.After)
				case "parse":
				default:
					t.Fatal("unknown corpus operation")
				}
			}
			if (e == nil) != v.Accepted {
				t.Fatalf("TS/Go mismatch accepted=%v error=%v input=%s", v.Accepted, e, input)
			}
		})
	}
}
func TestRawPageBudget(t *testing.T) {
	if _, e := Parse(make([]byte, MaxBytes+1)); e != ErrLimit {
		t.Fatal(e)
	}
}
