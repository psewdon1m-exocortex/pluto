package syncstate

import "context"

// Missing historical memberships are not source absence or server-delete proof.
// At most128 configured memberships are examined for a pending exact entry.
func (s *Sources) seenInCurrentScans(ctx context.Context, w SourceWitness, destination string, scans map[string]bool) (bool, error) {
	if len(scans) > MaxSources {
		return false, ErrSourceQuota
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.checkWitness(ctx, s.store.db, w); err != nil {
		return false, err
	}
	rows, err := s.store.db.QueryContext(ctx, "SELECT seen_scan_id FROM source_membership WHERE set_id=? AND destination=? ORDER BY source_id LIMIT ?", w.SetID, destination, MaxSources+1)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	count := 0
	seen := false
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return false, err
		}
		count++
		if count > MaxSources {
			return false, ErrSourceQuota
		}
		seen = seen || scans[id]
	}
	return seen, rows.Err()
}
