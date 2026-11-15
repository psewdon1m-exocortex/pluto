package syncproto

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// An independent arbitrary-precision oracle checks canonical exact counters;
// they must never pass through JSON floating point or accept numeric tokens.
func TestExactCounterBoundariesGenerated(t *testing.T) {
	canonical := regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	maximum := new(big.Int).SetUint64(9223372036854775807)
	seed := uint64(0x6a09e667f3bcc909)
	for i := 0; i < 5000; i++ {
		seed = seed*6364136223846793005 + 1442695040888963407
		value := strconv.FormatUint(seed, 10)
		switch i % 7 {
		case 1:
			value = "0" + value
		case 2:
			value = "-" + value
		case 3:
			value += ".0"
		case 4:
			value += "e0"
		case 5:
			value = " " + value
		}
		n, valid := new(big.Int).SetString(value, 10)
		accepted := canonical.MatchString(value) && valid && n.Sign() >= 0 && n.Cmp(maximum) <= 0
		actual, err := Integer64(value)
		if (err == nil) != accepted || accepted && actual != n.Int64() {
			t.Fatalf("counter %q accepted=%v got=%d err=%v", value, accepted, actual, err)
		}
	}
	if _, err := Integer64(json.Number("1")); err == nil {
		t.Fatal("numeric tokens cannot supply exact counter strings")
	}
}

func TestIncomingBudgetCountsReceivedRepresentation(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]json.RawMessage
	if err = json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	var bindingObject map[string]any
	if err = json.Unmarshal(golden["binding"], &bindingObject); err != nil {
		t.Fatal(err)
	}
	binding, err := ReadBinding(bindingObject)
	if err != nil {
		t.Fatal(err)
	}
	page := append([]byte(nil), bytes.TrimSpace(golden["feed"])...)
	if len(page) == 0 || page[len(page)-1] != '}' {
		t.Fatal("qualified feed fixture missing")
	}
	// The forward field is within the received 4 MiB budget, although decoding
	// and reserializing 1e4 as 10000 would produce a larger representation.
	page = append(page[:len(page)-1], []byte(`,"future":[`)...)
	page = append(page, bytes.Repeat([]byte("1e4,"), 710000)...)
	page[len(page)-1] = ']'
	page = append(page, '}')
	if len(page) > MaxBytes {
		t.Fatal("incoming fixture exceeds its intended budget")
	}
	feedValue, err := Parse(golden["feed"])
	if err != nil {
		t.Fatal(err)
	}
	feedObject := feedValue.(map[string]any)
	after := feedObject["from_exclusive"].(string)
	if _, err = ReadFeed(page, binding, after); err != nil {
		t.Fatal("received representation rejected", err)
	}
	if _, err = Parse(bytes.Repeat([]byte(" "), MaxBytes+1)); err != ErrLimit {
		t.Fatal("raw byte limit must apply before decoding", err)
	}
}
