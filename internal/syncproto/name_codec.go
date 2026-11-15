package syncproto

import (
	"golang.org/x/text/unicode/norm"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NameKey implements K1 r1 exactly. It never normalizes or escapes an on-disk
// name. A non-NFC source needs an explicit operator migration, not a rename.
func NameKey(name, codec string) (string, error) {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 255 || len(name) > 1020 {
		return "", ErrContract
	}
	for _, r := range name {
		if r == '/' || r == '\\' || unicode.IsControl(r) || r >= 0xd800 && r <= 0xdfff {
			return "", ErrContract
		}
	}
	if codec == "legacy" {
		return name, nil
	}
	if codec != "portable_v1" || !norm.NFC.IsNormalString(name) || strings.ContainsAny(name, "<>:\"|?*") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return "", ErrContract
	}
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.ToUpper(stem)
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" {
		return "", ErrContract
	}
	if strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT") {
		// Both device prefixes are exactly three ASCII bytes. Remove only
		// the matched prefix: COMLPT1 is a regular filename, not LPT1.
		suffix := stem[3:]
		if utf8.RuneCountInString(suffix) == 1 && strings.Contains("123456789¹²³", suffix) {
			return "", ErrContract
		}
	}
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, name), nil
}
