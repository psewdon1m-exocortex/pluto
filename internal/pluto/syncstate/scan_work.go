package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

func readScan(ctx context.Context, q queryer, id string) (Scan, error) {
	var scan Scan
	err := q.QueryRowContext(ctx, "SELECT scan_id,source_id,set_id,revision,owner_id,owner_sequence,gap_generation,status,reason,pages FROM source_scans WHERE scan_id=?", id).Scan(&scan.ID, &scan.SourceID, &scan.Witness.SetID, &scan.Witness.Revision, &scan.Witness.OwnerID, &scan.Witness.OwnerSequence, &scan.Witness.GapGeneration, &scan.Status, &scan.Reason, &scan.Pages)
	return scan, err
}
func (s *Sources) Scan(ctx context.Context, id string) (Scan, error) {
	return readScan(ctx, s.store.db, id)
}
func (s *Sources) BeginScan(ctx context.Context, w SourceWitness, sourceID, scanID string) (Scan, error) {
	if !validID(scanID) {
		return Scan{}, ErrIdentityConflict
	}
	var scan Scan
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		b, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1 AND revision=?", w.SetID, sourceID, w.Revision)
		if err != nil {
			return err
		}
		var active int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM source_scans WHERE set_id=? AND source_id=? AND status='DISCOVERING'", w.SetID, sourceID).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return ErrStateInUse
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO source_scans(scan_id,set_id,source_id,revision,owner_id,owner_sequence,gap_generation,status) VALUES(?,?,?,?,?,?,?,'DISCOVERING')", scanID, w.SetID, sourceID, w.Revision, w.OwnerID, w.OwnerSequence, w.GapGeneration); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO source_frontier(scan_id,work_id,physical_path,destination,depth) VALUES(?,1,?,?,0)", scanID, b.PhysicalPath, b.Destination); err != nil {
			return err
		}
		scan, err = readScan(ctx, tx, scanID)
		return err
	})
	return scan, err
}
func (s *Sources) ClaimScanFrontier(ctx context.Context, w SourceWitness, scanID string) (FrontierClaim, error) {
	var c FrontierClaim
	err := s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		scan, err := readScan(ctx, tx, scanID)
		if err != nil {
			return err
		}
		if scan.Witness != w || scan.Status != "DISCOVERING" {
			return ErrStaleGeneration
		}
		c.ScanID = scanID
		c.Witness = w
		if err = tx.QueryRowContext(ctx, "SELECT work_id,physical_path,destination,depth,page FROM source_frontier WHERE scan_id=? AND claim_token='' ORDER BY work_id LIMIT 1", scanID).Scan(&c.WorkID, &c.PhysicalPath, &c.Destination, &c.Depth, &c.Page); err != nil {
			return err
		}
		c.Token, err = NewOperationID()
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE source_frontier SET claim_token=? WHERE scan_id=? AND work_id=? AND claim_token=''", c.Token, scanID, c.WorkID)
		return err
	})
	return c, err
}
func (s *Sources) checkClaim(ctx context.Context, q queryer, c FrontierClaim) error {
	if _, err := s.checkWitness(ctx, q, c.Witness); err != nil {
		return err
	}
	scan, err := readScan(ctx, q, c.ScanID)
	if err != nil {
		return err
	}
	if scan.Witness != c.Witness || scan.Status != "DISCOVERING" {
		return ErrStaleGeneration
	}
	var token, p, key string
	var page int64
	var depth int
	if err = q.QueryRowContext(ctx, "SELECT claim_token,page,physical_path,destination,depth FROM source_frontier WHERE scan_id=? AND work_id=?", c.ScanID, c.WorkID).Scan(&token, &page, &p, &key, &depth); err != nil {
		return err
	}
	if token == "" || token != c.Token || page != c.Page || p != c.PhysicalPath || key != c.Destination || depth != c.Depth {
		return ErrStaleGeneration
	}
	return nil
}

// CommitScanPage never persists a ReadDir cookie. A crashed/incomplete directory
// is reread from its beginning by a new scan; exact keys coalesce durable work.
// The claim/page CAS, descriptors, children and EOF pop commit in one transaction.
func (s *Sources) CommitScanPage(ctx context.Context, c FrontierClaim, page ScanPage) (FrontierClaim, error) {
	if len(page.Entries) > MaxSourcePage || len(page.Children) > MaxSourcePage || len(page.IncompleteReason) > 512 {
		return c, ErrSourceQuota
	}
	raw, _ := json.Marshal(page)
	if len(raw) > MaxSourcePageBytes {
		return c, ErrSourceQuota
	}
	for _, d := range append(append([]SourceDescriptor{}, page.Entries...), page.Children...) {
		if err := checkSourceDescriptor(d); err != nil {
			return c, err
		}
		if d.Destination == c.Destination && d.PhysicalPath != c.PhysicalPath {
			return c, ErrIdentityConflict
		}
		if d.Destination != c.Destination && (!strings.HasPrefix(d.Destination, c.Destination+"/") || filepath.Dir(d.PhysicalPath) != c.PhysicalPath || strings.TrimPrefix(d.Destination, c.Destination+"/") != filepath.Base(d.PhysicalPath)) {
			return c, ErrIdentityConflict
		}
	}
	for _, d := range page.Children {
		if d.Kind != "folder" || d.Presence != "PRESENT" || d.Destination == c.Destination || c.Depth >= MaxSourceDepth {
			return c, ErrSourceQuota
		}
	}
	next := c
	err := s.change(ctx, int64(len(raw))*12+(1<<20), func(tx *sql.Tx) error {
		if err := s.checkClaim(ctx, tx, c); err != nil {
			return err
		}
		scan, err := readScan(ctx, tx, c.ScanID)
		if err != nil {
			return err
		}
		binding, err := readJSON[SourceBinding](ctx, tx, "SELECT descriptor_json FROM source_bindings WHERE set_id=? AND source_id=? AND active=1", c.Witness.SetID, scan.SourceID)
		if err != nil {
			return err
		}
		for _, d := range page.Entries {
			if err := s.recordScanDescriptor(ctx, tx, c, binding, d); err != nil {
				return err
			}
		}
		var maxID int64
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(work_id),0) FROM source_frontier WHERE scan_id=?", c.ScanID).Scan(&maxID); err != nil {
			return err
		}
		for _, d := range page.Children {
			maxID++
			if _, err := tx.ExecContext(ctx, "INSERT INTO source_frontier(scan_id,work_id,physical_path,destination,depth) VALUES(?,?,?,?,?) ON CONFLICT(scan_id,destination) DO NOTHING", c.ScanID, maxID, d.PhysicalPath, d.Destination, c.Depth+1); err != nil {
				return err
			}
		}
		if page.IncompleteReason != "" {
			if _, err := tx.ExecContext(ctx, "UPDATE source_scans SET status='INCOMPLETE',reason=? WHERE scan_id=?", page.IncompleteReason, c.ScanID); err != nil {
				return err
			}
		}
		if page.EOF {
			if _, err := tx.ExecContext(ctx, "DELETE FROM source_frontier WHERE scan_id=? AND work_id=?", c.ScanID, c.WorkID); err != nil {
				return err
			}
			next.Token = ""
		} else {
			if _, err := tx.ExecContext(ctx, "UPDATE source_frontier SET page=page+1 WHERE scan_id=? AND work_id=?", c.ScanID, c.WorkID); err != nil {
				return err
			}
			next.Page++
		}
		_, err = tx.ExecContext(ctx, "UPDATE source_scans SET pages=pages+1 WHERE scan_id=?", c.ScanID)
		return err
	})
	return next, err
}
func (s *Sources) recordScanDescriptor(ctx context.Context, tx *sql.Tx, c FrontierClaim, binding SourceBinding, d SourceDescriptor) error {
	old, err := readSourceEntry(ctx, tx, c.Witness.SetID, d.Destination)
	entry := SourceEntry{SourceDescriptor: d, SetID: c.Witness.SetID, SourceID: binding.ID, SourceRootPath: binding.PhysicalPath, SourceObject: binding.Object, SourceIncarnation: binding.Incarnation, Generation: 1, VerificationRequest: 1}
	if errors.Is(err, sql.ErrNoRows) {
		if d.ExpectedGeneration != 0 {
			return ErrStaleGeneration
		}
	} else if err != nil {
		return err
	} else {
		if old.Generation != d.ExpectedGeneration {
			return ErrStaleGeneration
		}
		entry.Generation = old.Generation
		entry.VerificationRequest = old.VerificationRequest + 1
		entry.Ambiguous = old.Ambiguous
		// A hardlink does not make two differently selected physical paths one
		// binding. A shared destination remains ambiguous even for the same inode.
		if old.PhysicalPath != d.PhysicalPath {
			entry.Ambiguous = true
		}
		oldData := old.SourceDescriptor
		oldData.ExpectedGeneration = d.ExpectedGeneration
		if fingerprint(oldData) != fingerprint(d) || old.SourceObject != binding.Object || old.SourceIncarnation != binding.Incarnation {
			entry.Generation++
		}
	}
	body, _ := json.Marshal(entry)
	if _, err = tx.ExecContext(ctx, "INSERT INTO source_entries(set_id,destination,generation,verification_request,ambiguous,descriptor_json) VALUES(?,?,?,?,?,?) ON CONFLICT(set_id,destination) DO UPDATE SET generation=excluded.generation,verification_request=excluded.verification_request,ambiguous=excluded.ambiguous,descriptor_json=excluded.descriptor_json", entry.SetID, d.Destination, entry.Generation, entry.VerificationRequest, entry.Ambiguous, string(body)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO source_membership(set_id,source_id,destination,seen_scan_id) VALUES(?,?,?,?) ON CONFLICT(set_id,source_id,destination) DO UPDATE SET seen_scan_id=excluded.seen_scan_id", entry.SetID, binding.ID, d.Destination, c.ScanID); err != nil {
		return err
	}
	if d.Kind == "file" {
		_, err = tx.ExecContext(ctx, "INSERT INTO source_verification(set_id,destination,request) VALUES(?,?,?) ON CONFLICT(set_id,destination) DO UPDATE SET request=excluded.request", entry.SetID, d.Destination, entry.VerificationRequest)
	}
	return err
}
func (s *Sources) CompleteScanScope(ctx context.Context, w SourceWitness, scanID string) error {
	return s.change(ctx, 1<<20, func(tx *sql.Tx) error {
		if _, err := s.checkWitness(ctx, tx, w); err != nil {
			return err
		}
		scan, err := readScan(ctx, tx, scanID)
		if err != nil {
			return err
		}
		if scan.Witness != w {
			return ErrStaleGeneration
		}
		if scan.Status == "COMPLETE" {
			return nil
		}
		if scan.Status != "DISCOVERING" {
			return ErrSourceIncomplete
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM source_frontier WHERE scan_id=? LIMIT 1)", scanID).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return ErrSourceIncomplete
		}
		// Completion is traversal evidence only. Missing old memberships are retained
		// for future explicit no-delete reconciliation, never inferred server absence.
		_, err = tx.ExecContext(ctx, "UPDATE source_scans SET status='COMPLETE' WHERE scan_id=?", scanID)
		return err
	})
}
func (s *Sources) VerificationPage(ctx context.Context, w SourceWitness, after string, limit int) ([]VerificationWork, error) {
	return s.verificationPage(ctx, w, "", after, limit)
}

// VerificationPageForScan dispatches only exact members observed by this scan.
// Old retained work must not race a later current observation of the same file.
func (s *Sources) VerificationPageForScan(ctx context.Context, w SourceWitness, scanID, after string, limit int) ([]VerificationWork, error) {
	if !validID(scanID) {
		return nil, ErrIdentityConflict
	}
	return s.verificationPage(ctx, w, scanID, after, limit)
}

func (s *Sources) verificationPage(ctx context.Context, w SourceWitness, scanID, after string, limit int) ([]VerificationWork, error) {
	if limit < 1 || limit > MaxSourcePage {
		return nil, ErrSourceQuota
	}
	var out []VerificationWork
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = s.checkWitness(ctx, tx, w); err != nil {
		return nil, err
	}
	query := "SELECT e.descriptor_json,e.generation,e.verification_request,e.ambiguous,v.request FROM source_verification v JOIN source_entries e USING(set_id,destination) WHERE v.set_id=? AND v.destination>? ORDER BY v.destination LIMIT ?"
	args := []any{w.SetID, after, limit}
	if scanID != "" {
		scan, err := readScan(ctx, tx, scanID)
		if err != nil {
			return nil, err
		}
		if scan.Witness != w || scan.Status != "DISCOVERING" && scan.Status != "COMPLETE" {
			return nil, ErrStaleGeneration
		}
		// A no-op scan still drains after every frontier page. Avoid repeatedly
		// walking its entire membership when no verification work remains. Keep
		// this check after owner/scan validation and in the same read snapshot as
		// the normal page query, so it cannot waive an incarnation or hide work.
		var pending bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM source_verification WHERE set_id=?)", w.SetID).Scan(&pending); err != nil {
			return nil, err
		}
		if !pending {
			return nil, tx.Commit()
		}
		var version int
		if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return nil, err
		}
		index := ""
		if version == HTTPBindingSchemaVersion || (version == smallBatchSchemaVersion || version == daemonSchemaVersion) {
			index = " INDEXED BY source_current_scan_entries"
		}
		query = "SELECT e.descriptor_json,e.generation,e.verification_request,e.ambiguous,v.request FROM source_membership m" + index + " JOIN source_verification v ON v.set_id=m.set_id AND v.destination=m.destination JOIN source_entries e ON e.set_id=m.set_id AND e.destination=m.destination WHERE m.seen_scan_id=? AND m.destination>? AND m.set_id=? AND m.source_id=? ORDER BY m.destination LIMIT ?"
		args = []any{scanID, after, w.SetID, scan.SourceID, limit}
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bytes := 0
	for rows.Next() {
		var raw string
		var work VerificationWork
		var g, r int64
		var ambiguous bool
		if err = rows.Scan(&raw, &g, &r, &ambiguous, &work.Request); err != nil {
			return nil, err
		}
		bytes += len(raw)
		if bytes > MaxSourcePageBytes {
			return nil, ErrSourceQuota
		}
		if err = json.Unmarshal([]byte(raw), &work.Entry); err != nil {
			return nil, err
		}
		work.Entry.Generation = g
		work.Entry.VerificationRequest = r
		work.Entry.Ambiguous = ambiguous
		out = append(out, work)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
