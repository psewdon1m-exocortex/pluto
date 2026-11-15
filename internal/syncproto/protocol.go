// Package syncproto is an inactive candidate wire reader. Validation never
// grants source completeness, current-root authority, or baseline adoption.
package syncproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxBytes = 4 * 1024 * 1024
const MaxItems = 500
const Protocol = "neptune-sync/1"
const DescriptorSchema = "saturn.current-namespace.v1"

var ErrJSON = errors.New("invalid_json")
var ErrContract = errors.New("invalid_contract")
var ErrLimit = errors.New("page_limit")
var ErrGap = errors.New("feed_gap")
var ErrBinding = errors.New("binding_mismatch")

type Binding struct{ Protocol, DescriptorSchema, ServerIdentity, RootID, ServerEpoch, PolicyVersion, BindingVersion string }
type Descriptor struct {
	NodeID                          string
	ParentID                        *string
	Name, Type, SizeBytes           string
	ContentSHA256, ContentVersionID *string
	Version, Availability           string
}
type FeedItem struct {
	Descriptor
	Seq, Kind, OperationID, BeforeVersion string
}
type Feed struct {
	Binding
	FromExclusive, ToInclusive string
	Items                      []FeedItem
	NextCursor                 string
	HasMore                    bool
}
type Snapshot struct {
	Binding
	SnapshotID, CutSeq, EntriesCursor, ChangesCursor string
	LeaseSeconds, AbsoluteLifetimeSeconds            int64
}

func Integer64(v any) (int64, error) {
	s, ok := v.(string)
	if !ok || len(s) == 0 || len(s) > 19 || len(s) > 1 && s[0] == '0' {
		return 0, ErrContract
	}
	for _, b := range []byte(s) {
		if b < '0' || b > '9' {
			return 0, ErrContract
		}
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil {
		return 0, ErrContract
	}
	return n, nil
}
func opaque(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
func uuid(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, b := range []byte(s) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return false
			}
		} else if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
func text(m map[string]any, k string) (string, error) {
	s, ok := m[k].(string)
	if !ok {
		return "", ErrContract
	}
	return s, nil
}
func nullable(m map[string]any, k string) (*string, error) {
	v, ok := m[k]
	if !ok {
		return nil, ErrContract
	}
	if v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, ErrContract
	}
	return &s, nil
}
func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrContract
	}
	return m, nil
}

// encoding/json accepts invalid UTF-8 and replaces isolated escaped UTF-16
// surrogates. Reject both before decoding, including ignored forward fields.
func strictStrings(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		i++
		for ; i < len(b) && b[i] != '"'; i++ {
			if b[i] != '\\' {
				continue
			}
			i++
			if i >= len(b) {
				return false
			}
			if b[i] != 'u' {
				continue
			}
			if i+4 >= len(b) {
				return false
			}
			n, e := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
			if e != nil {
				return false
			}
			i += 4
			if n >= 0xd800 && n <= 0xdbff {
				if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
					return false
				}
				low, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
				if e != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			} else if n >= 0xdc00 && n <= 0xdfff {
				return false
			}
		}
	}
	return true
}
func Parse(raw []byte) (any, error) {
	if len(raw) > MaxBytes {
		return nil, ErrLimit
	}
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		raw = raw[3:]
	}
	if !strictStrings(raw) {
		return nil, ErrJSON
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 32 {
			return nil, ErrJSON
		}
		t, e := d.Token()
		if e != nil {
			return nil, ErrJSON
		}
		switch t {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, ErrJSON
				}
				s, ok := k.(string)
				if !ok {
					return nil, ErrJSON
				}
				if _, exists := m[s]; exists {
					return nil, ErrJSON
				}
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			t, e = d.Token()
			if e != nil || t != json.Delim('}') {
				return nil, ErrJSON
			}
			return m, nil
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			t, e = d.Token()
			if e != nil || t != json.Delim(']') {
				return nil, ErrJSON
			}
			return a, nil
		default:
			if _, isDelim := t.(json.Delim); isDelim {
				return nil, ErrJSON
			}
			return t, nil
		}
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrJSON
	}
	return v, nil
}
func ReadBinding(m map[string]any) (Binding, error) {
	var b Binding
	fields := []struct {
		k string
		p *string
	}{{"protocol", &b.Protocol}, {"descriptor_schema", &b.DescriptorSchema}, {"server_identity", &b.ServerIdentity}, {"root_id", &b.RootID}, {"server_epoch", &b.ServerEpoch}, {"policy_version", &b.PolicyVersion}, {"binding_version", &b.BindingVersion}}
	for _, f := range fields {
		s, e := text(m, f.k)
		if e != nil {
			return b, e
		}
		*f.p = s
	}
	if b.Protocol != Protocol || b.DescriptorSchema != DescriptorSchema || !uuid(b.BindingVersion) {
		return b, ErrContract
	}
	for _, s := range []string{b.ServerIdentity, b.RootID, b.ServerEpoch, b.PolicyVersion} {
		if !opaque(s, 128) {
			return b, ErrContract
		}
	}
	return b, nil
}
func ReadDescriptor(v any) (Descriptor, error) {
	var d Descriptor
	m, e := object(v)
	if e != nil {
		return d, e
	}
	fields := []struct {
		k string
		p *string
	}{{"node_id", &d.NodeID}, {"name", &d.Name}, {"type", &d.Type}, {"size_bytes", &d.SizeBytes}, {"version", &d.Version}, {"availability", &d.Availability}}
	for _, f := range fields {
		s, e := text(m, f.k)
		if e != nil {
			return d, e
		}
		*f.p = s
	}
	if !opaque(d.NodeID, 128) || !uuid(d.Version) || len(d.Name) == 0 || len(d.Name) > 1020 || strings.ContainsAny(d.Name, "\x00/\\") || !utf8.ValidString(d.Name) {
		return d, ErrContract
	}
	if _, e = Integer64(d.SizeBytes); e != nil {
		return d, e
	}
	d.ParentID, e = nullable(m, "parent_id")
	if e != nil {
		return d, e
	}
	if d.ParentID != nil && (!opaque(*d.ParentID, 128) || *d.ParentID == d.NodeID) {
		return d, ErrContract
	}
	d.ContentSHA256, e = nullable(m, "content_sha256")
	if e != nil {
		return d, e
	}
	d.ContentVersionID, e = nullable(m, "content_version_id")
	if e != nil {
		return d, e
	}
	if d.ContentSHA256 != nil {
		if len(*d.ContentSHA256) != 64 {
			return d, ErrContract
		}
		for _, b := range []byte(*d.ContentSHA256) {
			if !(b >= 'a' && b <= 'f' || b >= '0' && b <= '9') {
				return d, ErrContract
			}
		}
	}
	if d.ContentVersionID != nil && !opaque(*d.ContentVersionID, 128) {
		return d, ErrContract
	}
	if d.Type != "file" && d.Type != "folder" || d.Availability != "AVAILABLE" && d.Availability != "UNAVAILABLE" && d.Availability != "UNKNOWN" {
		return d, ErrContract
	}
	if d.Type == "folder" && (d.ContentSHA256 != nil || d.ContentVersionID != nil) || d.Type == "file" && d.Availability == "AVAILABLE" && (d.ContentSHA256 == nil || d.ContentVersionID == nil) {
		return d, ErrContract
	}
	return d, nil
}
func expected(v any) error {
	m, e := object(v)
	if e != nil {
		return e
	}
	kind, e := text(m, "kind")
	if e != nil {
		return e
	}
	if kind == "absent" && len(m) == 1 {
		return nil
	}
	if kind != "version" || len(m) != 3 {
		return ErrContract
	}
	n, e := text(m, "node_id")
	if e != nil || !opaque(n, 128) {
		return ErrContract
	}
	ver, e := text(m, "version")
	if e != nil || !uuid(ver) {
		return ErrContract
	}
	return nil
}
func ReadExpected(raw []byte) error {
	v, e := Parse(raw)
	if e != nil {
		return e
	}
	return expected(v)
}
func ReadFeed(raw []byte, previous Binding, after string) (Feed, error) {
	var f Feed
	v, e := Parse(raw)
	if e != nil {
		return f, e
	}
	m, e := object(v)
	if e != nil {
		return f, e
	}
	f.Binding, e = ReadBinding(m)
	if e != nil {
		return f, e
	}
	if f.Binding != previous {
		return f, ErrBinding
	}
	f.FromExclusive, e = text(m, "from_exclusive")
	if e != nil {
		return f, e
	}
	from, e := Integer64(f.FromExclusive)
	if e != nil {
		return f, e
	}
	old, e := Integer64(after)
	if e != nil {
		return f, e
	}
	f.ToInclusive, e = text(m, "to_inclusive")
	if e != nil {
		return f, e
	}
	to, e := Integer64(f.ToInclusive)
	if e != nil {
		return f, e
	}
	if from != old || to < from {
		return f, ErrGap
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) > MaxItems {
		return f, ErrLimit
	}
	seq := from
	for _, v := range items {
		d, e := ReadDescriptor(v)
		if e != nil {
			return f, e
		}
		m, _ := object(v)
		item := FeedItem{Descriptor: d}
		item.Seq, e = text(m, "seq")
		if e != nil {
			return f, e
		}
		n, e := Integer64(item.Seq)
		if e != nil {
			return f, e
		}
		if seq == 9223372036854775807 || n != seq+1 {
			return f, ErrGap
		}
		seq = n
		item.Kind, e = text(m, "kind")
		if e != nil || item.Kind != "upsert" && item.Kind != "tombstone" {
			return f, ErrContract
		}
		item.OperationID, e = text(m, "operation_id")
		if e != nil || !opaque(item.OperationID, 128) {
			return f, ErrContract
		}
		if item.Kind == "tombstone" {
			item.BeforeVersion, e = text(m, "before_version")
			if e != nil || !uuid(item.BeforeVersion) || item.BeforeVersion == item.Version {
				return f, ErrContract
			}
		}
		f.Items = append(f.Items, item)
	}
	if seq != to {
		return f, ErrGap
	}
	f.NextCursor, e = text(m, "next_cursor")
	if e != nil || !opaque(f.NextCursor, 4096) {
		return f, ErrContract
	}
	f.HasMore, ok = m["has_more"].(bool)
	if !ok {
		return f, ErrContract
	}
	if f.HasMore && len(f.Items) == 0 {
		return f, ErrGap
	}
	return f, nil
}
func ReadSnapshot(raw []byte) (Snapshot, error) {
	var s Snapshot
	v, e := Parse(raw)
	if e != nil {
		return s, e
	}
	m, e := object(v)
	if e != nil {
		return s, e
	}
	s.Binding, e = ReadBinding(m)
	if e != nil {
		return s, e
	}
	state, e := text(m, "state")
	if e != nil || state != "READY" {
		return s, ErrContract
	}
	s.SnapshotID, e = text(m, "snapshot_id")
	if e != nil || !opaque(s.SnapshotID, 128) {
		return s, ErrContract
	}
	s.CutSeq, e = text(m, "cut_seq")
	if e != nil {
		return s, e
	}
	if _, e = Integer64(s.CutSeq); e != nil {
		return s, e
	}
	s.EntriesCursor, e = text(m, "entries_cursor")
	if e != nil || !opaque(s.EntriesCursor, 4096) {
		return s, ErrContract
	}
	s.ChangesCursor, e = text(m, "changes_cursor")
	if e != nil || !opaque(s.ChangesCursor, 4096) {
		return s, ErrContract
	}
	for _, f := range []struct {
		k string
		p *int64
	}{{"lease_seconds", &s.LeaseSeconds}, {"absolute_lifetime_seconds", &s.AbsoluteLifetimeSeconds}} {
		n, ok := m[f.k].(json.Number)
		if !ok {
			return s, ErrContract
		}
		value, numberError := n.Float64()
		if numberError != nil || value < 1 || value > 86400 || value != float64(int64(value)) {
			return s, ErrContract
		}
		*f.p = int64(value)
	}
	if s.LeaseSeconds > s.AbsoluteLifetimeSeconds {
		return s, ErrContract
	}
	return s, nil
}
