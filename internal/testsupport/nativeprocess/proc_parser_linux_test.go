//go:build linux

package nativefixture

import (
	"strings"
	"testing"
)

func TestPgrpSessionParsingIsDataOnly(t *testing.T) {
	makeStat := func(group, session string) []byte {
		return []byte("4101 (odd ) comm) S 4001 " + group + " " + session + " " + strings.Repeat("0 ", 15) + "12345 0\n")
	}
	g, s, e := parseGroupSession(makeStat("4101", "3999"))
	if e != nil || g != 4101 || s != 3999 {
		t.Fatal(g, s, e)
	}
	for _, bad := range []string{"0", "-1", "+4101", "2147483648", "x"} {
		if _, _, e := parseGroupSession(makeStat(bad, "3999")); e == nil {
			t.Fatal("bad pgrp", bad)
		}
		if _, _, e := parseGroupSession(makeStat("4101", bad)); e == nil {
			t.Fatal("bad session", bad)
		}
	}
}
