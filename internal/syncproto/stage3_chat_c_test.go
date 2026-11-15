package syncproto

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestStage3C05SharedCodecVectors(t *testing.T) {
	corpusPath := os.Getenv("SYNC_NAME_CODEC_CORPUS_PATH")
	if corpusPath == "" {
		corpusPath = "testdata/name-codec-v1.json"
	}
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 28 {
		t.Fatal("missing contract vectors")
	}
	for i, raw := range file.Vectors {
		t.Run(fmt.Sprintf("vector-%02d", i), func(t *testing.T) {
			var v struct {
				Name, Codec, Key string
				Accepted         bool
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			// Strict wire parsing rejects lone surrogate escapes before Go's JSON
			// decoder could replace them with U+FFFD and lose the evidence.
			if _, err := Parse(raw); err != nil {
				if v.Accepted {
					t.Fatal(err)
				}
				return
			}
			key, err := NameKey(v.Name, v.Codec)
			if (err == nil) != v.Accepted || v.Accepted && key != v.Key {
				t.Fatalf("name=%q key=%q accepted=%v error=%v", v.Name, key, v.Accepted, err)
			}
		})
	}
}
func TestStage3C05BoundariesAndCase(t *testing.T) {
	for _, name := range []string{"\xff", ".", "..", "a/b", "a\\b", "x\x00y", strings.Repeat("x", 256), "e\u0301", "COM1.md", "lpt³.md"} {
		if _, err := NameKey(name, "portable_v1"); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"COMLPT1.md", "LPTCOM1.md", "comlpt¹.md", strings.Repeat("😀", 255), "Агентность, локус контроля, инициативность.md"} {
		if _, err := NameKey(name, "portable_v1"); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	a, _ := NameKey("A.txt", "portable_v1")
	b, _ := NameKey("a.txt", "portable_v1")
	if a != b {
		t.Fatal("ASCII collision lost")
	}
	a, _ = NameKey("Ж.txt", "portable_v1")
	b, _ = NameKey("ж.txt", "portable_v1")
	if a == b {
		t.Fatal("Unicode folded beyond contract")
	}
	if key, err := NameKey("e\u0301.", "legacy"); err != nil || key != "e\u0301." {
		t.Fatal("legacy spelling changed", key, err)
	}
}
