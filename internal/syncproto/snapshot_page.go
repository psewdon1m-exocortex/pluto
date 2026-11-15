package syncproto

import "errors"

var ErrSnapshotMismatch = errors.New("snapshot_mismatch")
var ErrSnapshotPageGap = errors.New("snapshot_page_gap")

// SnapshotEntries is an inactive shape. It is not server readiness, local
// completeness, current presence, or baseline adoption authority.
type SnapshotEntries struct {
	Binding
	SnapshotID, CutSeq      string
	AfterNodeID, LastNodeID *string
	Items                   []Descriptor
	NextCursor              string
	HasMore                 bool
}

func equalNullable(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func ReadSnapshotEntries(raw []byte, snapshot Snapshot, after *string) (SnapshotEntries, error) {
	var page SnapshotEntries
	if !opaque(snapshot.EntriesCursor, 4096) || !opaque(snapshot.ChangesCursor, 4096) || snapshot.LeaseSeconds < 1 || snapshot.AbsoluteLifetimeSeconds > 86400 || snapshot.LeaseSeconds > snapshot.AbsoluteLifetimeSeconds {
		return page, ErrContract
	}
	v, err := Parse(raw)
	if err != nil {
		return page, err
	}
	m, err := object(v)
	if err != nil {
		return page, err
	}
	page.Binding, err = ReadBinding(m)
	if err != nil {
		return page, err
	}
	if page.Binding != snapshot.Binding {
		return page, ErrBinding
	}
	page.SnapshotID, err = text(m, "snapshot_id")
	if err != nil || !opaque(page.SnapshotID, 128) {
		return page, ErrContract
	}
	page.CutSeq, err = text(m, "cut_seq")
	if err != nil {
		return page, err
	}
	if _, err = Integer64(page.CutSeq); err != nil {
		return page, err
	}
	if page.SnapshotID != snapshot.SnapshotID || page.CutSeq != snapshot.CutSeq {
		return page, ErrSnapshotMismatch
	}
	if after != nil && !opaque(*after, 128) {
		return page, ErrContract
	}
	page.AfterNodeID, err = nullable(m, "after_node_id")
	if err != nil || page.AfterNodeID != nil && !opaque(*page.AfterNodeID, 128) {
		return page, ErrContract
	}
	page.LastNodeID, err = nullable(m, "last_node_id")
	if err != nil || page.LastNodeID != nil && !opaque(*page.LastNodeID, 128) {
		return page, ErrContract
	}
	if !equalNullable(page.AfterNodeID, after) {
		return page, ErrSnapshotPageGap
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) > MaxItems {
		return page, ErrLimit
	}
	page.Items = make([]Descriptor, 0, len(items))
	last := after
	for _, item := range items {
		d, err := ReadDescriptor(item)
		if err != nil {
			return page, err
		}
		if last != nil && d.NodeID <= *last {
			return page, ErrSnapshotPageGap
		}
		page.Items = append(page.Items, d)
		id := d.NodeID
		last = &id
	}
	if !equalNullable(page.LastNodeID, last) {
		return page, ErrSnapshotPageGap
	}
	page.NextCursor, err = text(m, "next_cursor")
	if err != nil || !opaque(page.NextCursor, 4096) {
		return page, ErrContract
	}
	page.HasMore, ok = m["has_more"].(bool)
	if !ok {
		return page, ErrContract
	}
	if page.HasMore && len(page.Items) == 0 {
		return page, ErrSnapshotPageGap
	}
	return page, nil
}
