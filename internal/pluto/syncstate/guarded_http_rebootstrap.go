package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mime"
	"sort"
	"strings"
	"time"

	"pluto/internal/syncproto"
)

const httpBootstrapPreparing = "PREPARING"
const httpBootstrapAwaitFeed = "AWAITING_FEED"
const httpBootstrapRetiringImport = "RETIRING_EXPIRED_IMPORT"

var ErrHTTPRebootstrapLimit = errors.New("isolated remote continuity recovery budget exhausted")

// This read-snapshot checkpoint shares the existing candidate row. It is not a
// publication intent, a backend qualification or a local source continuity proof.
type HTTPRebootstrapCheckpoint struct {
	RetiringGeneration, RetiringExpiresMS           int64 `json:",omitempty"`
	Schema, Reason, SnapshotID, TransportPin, Phase string
	RetiredSnapshotIDs                              string `json:",omitempty"`
	Original                                        RemoteWitness
}

type guardedHTTPFailure struct {
	status       int
	code, path   string
	binding      RemoteBinding
	transportPin string
	retryAfter   time.Duration
}

func (e *guardedHTTPFailure) Error() string {
	if e.code == "" {
		return fmt.Sprintf("isolated sync HTTP status %d", e.status)
	}
	return fmt.Sprintf("isolated sync HTTP status %d (%s)", e.status, e.code)
}

func httpTransportPin(identity CapturedHTTPIdentity, binding RemoteBinding, allowed map[string]bool, token string) string {
	addresses := make([]string, 0, len(allowed))
	for address := range allowed {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return fingerprint(struct {
		Identity  CapturedHTTPIdentity
		Binding   RemoteBinding
		Addresses []string
		TokenHash string
	}{identity, binding, addresses, hashBytes([]byte(token))})
}

func (s *IsolatedHTTPSession) httpFailure(status int, path, contentType string, raw []byte) error {
	failure := &guardedHTTPFailure{status: status, path: path, binding: s.binding, transportPin: s.transportPin}
	media, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(media, "application/json") || parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") || len(raw) > 16384 {
		return errors.Join(failure, syncproto.ErrContract)
	}
	value, err := syncproto.Parse(raw)
	if err != nil {
		return errors.Join(failure, err)
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) < 1 || len(object) > 2 {
		return errors.Join(failure, syncproto.ErrContract)
	}
	if len(object) == 2 {
		delay, ok := object["retry_after_ms"]
		if !ok {
			return errors.Join(failure, syncproto.ErrContract)
		}
		if number, ok := delay.(json.Number); ok {
			delay = number.String()
		}
		n, e := syncproto.Integer64(delay)
		if e != nil || n < 0 || n > 86400000 {
			return errors.Join(failure, syncproto.ErrContract)
		}
		failure.retryAfter = time.Duration(n) * time.Millisecond
	}
	code, ok := object["code"].(string)
	if !ok || len(code) < 1 || len(code) > 128 {
		return errors.Join(failure, syncproto.ErrContract)
	}
	for _, char := range code {
		if (char < 'a' || char > 'z') && char != '_' {
			return errors.Join(failure, syncproto.ErrContract)
		}
	}
	failure.code = code
	return failure
}

func (s *IsolatedHTTPSession) eligibleRebootstrapFailure(err error) bool {
	var failure *guardedHTTPFailure
	// The server janitor removes expired token registrations. A later read of
	// the exact persisted feed cursor then returns invalid_cursor rather than
	// cursor_expired. Both require a new qualified observation, never a new
	// publication identity or permission to use stale authority.
	return errors.As(err, &failure) && failure.path == "changes" && failure.binding == s.binding && failure.transportPin == s.transportPin && (failure.status == 410 && failure.code == "cursor_expired" || failure.status == 409 && failure.code == "journal_gap" || failure.status == 400 && failure.code == "invalid_cursor")
}

func validHTTPCheckpoint(c RemoteCandidate, pin string) bool {
	p := c.HTTPRebootstrap
	if p == nil || p.Schema != "pluto.http-continuity-rebootstrap/v1" || p.Reason != "cursor_expired" && p.Reason != "journal_gap" && p.Reason != "invalid_cursor" || !httpUUID(p.SnapshotID) || !validHash(pin) || p.TransportPin != pin || !p.Original.Valid || p.Original.RootID != c.RootID || p.Original.Binding != c.Binding || p.Original.TrustGeneration != c.TrustGeneration || p.Original.TrustGeneration < 1 || p.Original.Generation < 1 || p.Original.Revision < 1 || p.Original.Revision >= math.MaxInt64-1 || p.Original.Generation == math.MaxInt64 || p.Original.Position < 0 || len(p.Original.Cursor) < 1 || len(p.Original.Cursor) > 4096 {
		return false
	}
	if p.RetiredSnapshotIDs != "" {
		ids := strings.Split(p.RetiredSnapshotIDs, ",")
		if len(ids) > 16 {
			return false
		}
		seen := map[string]bool{p.SnapshotID: true}
		for _, id := range ids {
			if !httpUUID(id) || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	if raw, err := httpJSON(p); err != nil || len(raw) > 16384 {
		return false
	}
	if p.Phase == httpBootstrapPreparing || p.Phase == httpBootstrapRetiringImport {
		expected := p.Original
		expected.Valid = false
		expected.Revision++
		fields := p.RetiringGeneration == 0 && p.RetiringExpiresMS == 0
		if p.Phase == httpBootstrapRetiringImport {
			fields = c.Generation < math.MaxInt64 && p.RetiringGeneration == c.Generation+1 && p.RetiringExpiresMS > 0
		}
		return fields && c.RemoteWitness == expected && c.SnapshotID != p.SnapshotID
	}
	return p.RetiringGeneration == 0 && p.RetiringExpiresMS == 0 && p.Phase == httpBootstrapAwaitFeed && !c.Valid && c.Generation == p.Original.Generation+1 && c.Revision >= p.Original.Revision+2 && c.Position >= p.Original.Position && c.SnapshotID == p.SnapshotID
}

// beginHTTPRebootstrap is reachable only from the private, connection-bound
// typed failure. Generic backend invalidation continues to require a new binding.
func (s *IsolatedHTTPSession) beginHTTPRebootstrap(ctx context.Context, expected RemoteCandidate, cause error) (RemoteCandidate, error) {
	var result RemoteCandidate
	if !s.eligibleRebootstrapFailure(cause) || !expected.Valid || expected.Binding != s.binding || expected.HTTPRebootstrap != nil {
		return result, ErrRemoteUnqualified
	}
	var failure *guardedHTTPFailure
	errors.As(cause, &failure)
	id, err := NewOperationID()
	if err != nil {
		return result, err
	}
	err = s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		current, err := readCandidate(ctx, tx, s.root)
		if err != nil {
			return err
		}
		root, err := readRoot(ctx, tx, s.root)
		if err != nil {
			return err
		}
		if current.RemoteWitness != expected.RemoteWitness || current.HTTPRebootstrap != nil || current.SnapshotID != expected.SnapshotID || root.ActiveRemoteGeneration != expected.Generation || root.TrustGeneration != expected.TrustGeneration || root.DeviceID != s.identity.DeviceID || root.RemoteRootID != s.binding.RootID || root.ServerIdentity != s.binding.ServerIdentity || current.Revision >= math.MaxInt64-1 || current.Generation == math.MaxInt64 {
			return ErrStaleGeneration
		}
		var prepared int
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM remote_preparations WHERE root_id=?)", s.root).Scan(&prepared); err != nil {
			return err
		}
		if prepared != 0 {
			return ErrRemoteIncomplete
		}
		if err = s.validateRetainedHTTPIdentity(ctx, tx); err != nil {
			return err
		}
		current.HTTPRebootstrap = &HTTPRebootstrapCheckpoint{Schema: "pluto.http-continuity-rebootstrap/v1", Reason: failure.code, SnapshotID: id, TransportPin: s.transportPin, Phase: httpBootstrapPreparing, Original: expected.RemoteWitness}
		current.Valid = false
		current.Revision++
		if !validHTTPCheckpoint(current, s.transportPin) {
			return ErrIdentityConflict
		}
		if err = saveCandidate(ctx, tx, current); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE journal_cursors SET valid=0 WHERE root_id=? AND stream='remote'", s.root); err != nil {
			return err
		}
		result = current
		return s.r.point("http_rebootstrap.before_commit")
	})
	if err == nil {
		err = s.r.point("http_rebootstrap.after_commit")
	}
	return result, err
}

// Existing pending originals constrain the first recovery on an older candidate
// which predates this optional checkpoint. Indexed keyset pages, not ACK history,
// are read in the same CAS transaction; admission refuses excessive pending debt.
func (s *IsolatedHTTPSession) validateRetainedHTTPIdentity(ctx context.Context, tx *sql.Tx) error {
	after := ""
	for page := 0; page < 32; page++ {
		rows, err := tx.QueryContext(ctx, `SELECT operation_id,CASE WHEN length(CAST(intent_json AS BLOB))<=? THEN intent_json ELSE '' END FROM operations WHERE root_id=? AND operation_id>? AND stage<>'CLIENT_ACKED' ORDER BY operation_id LIMIT 128`, MaxSourcePageBytes, s.root, after)
		if err != nil {
			return err
		}
		count, bytes := 0, 0
		for rows.Next() {
			var raw string
			if err = rows.Scan(&after, &raw); err != nil {
				rows.Close()
				return err
			}
			count++
			bytes += len(raw)
			if raw == "" || bytes > MaxSourcePageBytes {
				rows.Close()
				return ErrSourceQuota
			}
			var intent Intent
			if err = json.Unmarshal([]byte(raw), &intent); err != nil {
				rows.Close()
				return err
			}
			var identity *CapturedHTTPIdentity
			if intent.Captured != nil {
				identity = intent.Captured.Transport
			}
			if intent.FolderHTTP != nil {
				identity = &intent.FolderHTTP.Identity
			}
			if identity != nil {
				original := *identity
				binding := original.InputBinding
				original.InputBinding = RemoteBinding{}
				original.RequestPath = ""
				if original != s.identity || binding != s.binding {
					rows.Close()
					return ErrIdentityConflict
				}
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if count < 128 {
			return nil
		}
	}
	// Exactly 32 full pages is the supported 4096-original boundary. Probe
	// only for another indexed key; no extra intent bytes are admitted here.
	var more bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM operations WHERE root_id=? AND operation_id>? AND stage<>'CLIENT_ACKED' LIMIT 1)`, s.root, after).Scan(&more); err != nil {
		return err
	}
	if more {
		return ErrSourceQuota
	}
	return nil
}

// Called under the session mutex. One new or resumed flow per session bounds
// an immediately-expired replacement; restart reuses the committed snapshot UUID.
func (s *IsolatedHTTPSession) rebootstrap(ctx context.Context, current RemoteCandidate, cause error) error {
	if s.rebootstrapRuns >= 1 {
		s.continuityBlocked = true
		return ErrHTTPRebootstrapLimit
	}
	s.rebootstrapRuns++
	s.freshAt = time.Time{}
	var err error
	if current.HTTPRebootstrap == nil {
		current, err = s.beginHTTPRebootstrap(ctx, current, cause)
		if err != nil {
			return err
		}
	}
	if !validHTTPCheckpoint(current, s.transportPin) || current.Binding != s.binding {
		return ErrRemoteUnqualified
	}
	if current.HTTPRebootstrap.Phase == httpBootstrapAwaitFeed {
		return s.refresh(ctx)
	}
	if current.HTTPRebootstrap.Phase == httpBootstrapRetiringImport {
		current, err = s.finishExpiredImportRetirement(ctx, current)
		if err != nil {
			return err
		}
	}
	checkpoint := *current.HTTPRebootstrap
	p, err := s.r.Preparation(ctx, s.root)
	if err == nil && time.Now().UnixMilli() >= p.ExpiresMS {
		current, err = s.beginExpiredImportRetirement(ctx, current, p, time.Now())
		if err != nil {
			return err
		}
		if err = s.r.point("http_rebootstrap.expired_import_marked"); err != nil {
			return err
		}
		current, err = s.finishExpiredImportRetirement(ctx, current)
		if err != nil {
			return err
		}
		checkpoint = *current.HTTPRebootstrap
		err = sql.ErrNoRows
	}
	if errors.Is(err, sql.ErrNoRows) {
		for attempt := 0; attempt < 2; attempt++ {
			p, err = s.startRebootstrapSnapshot(ctx, current, checkpoint)
			if !s.expiredRecoveryStart(err) {
				break
			}
			if attempt != 0 {
				s.continuityBlocked = true
				return ErrHTTPRebootstrapLimit
			}
			current, err = s.retireExpiredRecoveryStart(ctx, current, err)
			if err != nil {
				return err
			}
			checkpoint = *current.HTTPRebootstrap
		}
	} else if err == nil {
		if p.Snapshot.SnapshotID != checkpoint.SnapshotID || p.Snapshot.Binding != s.binding || p.TrustGeneration != current.TrustGeneration || p.PreviousGeneration != current.Generation || time.Now().UnixMilli() >= p.ExpiresMS {
			return ErrIdentityConflict
		}
	}
	if err != nil {
		return err
	}
	for page := 0; !p.Complete && page < 8192; page++ {
		raw, err := s.post(ctx, "entries", map[string]any{"binding": bindingHTTP(s.binding), "cursor": p.Cursor})
		if err != nil {
			return err
		}
		p, err = s.r.ImportSnapshotPage(ctx, s.root, p.Cursor, raw, time.Now())
		if err != nil {
			return err
		}
	}
	if !p.Complete {
		return ErrSourceQuota
	}
	if _, err = s.r.PublishSnapshot(ctx, s.root, p, time.Now()); err != nil {
		return err
	}
	return s.refresh(ctx)
}

func (s *IsolatedHTTPSession) expiredRecoveryStart(err error) bool {
	var failure *guardedHTTPFailure
	if !errors.As(err, &failure) || failure.status != 410 || failure.code != "cursor_expired" || failure.binding != s.binding || failure.transportPin != s.transportPin {
		return false
	}
	// All three calls prepare the same durable read UUID. Retirement still
	// refuses any imported preparation or changed original witness below.
	return failure.path == "snapshots/start" || failure.path == "snapshots/step" || failure.path == "snapshots/ready"
}

// Only a server-confirmed expired read UUID can be retired. This never changes
// publication originals, B, the original witness or partially imported pages.
// A lost response, changed binding or already prepared import must retain its
// original identity. One replacement per session and sixteen per checkpoint
// bound a perpetually expiring server without admitting stale authority.
func (s *IsolatedHTTPSession) retireExpiredRecoveryStart(ctx context.Context, expected RemoteCandidate, cause error) (RemoteCandidate, error) {
	var result RemoteCandidate
	if !s.expiredRecoveryStart(cause) || !validHTTPCheckpoint(expected, s.transportPin) || expected.HTTPRebootstrap.Phase != httpBootstrapPreparing {
		return result, ErrRemoteUnqualified
	}
	id, err := NewOperationID()
	if err != nil {
		return result, err
	}
	err = s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		current, err := readCandidate(ctx, tx, s.root)
		if err != nil {
			return err
		}
		root, err := readRoot(ctx, tx, s.root)
		if err != nil {
			return err
		}
		if current.RemoteWitness != expected.RemoteWitness || current.HTTPRebootstrap == nil || *current.HTTPRebootstrap != *expected.HTTPRebootstrap || current.SnapshotID != expected.SnapshotID || !validHTTPCheckpoint(current, s.transportPin) || root.ActiveRemoteGeneration != current.Generation || root.TrustGeneration != current.TrustGeneration || root.DeviceID != s.identity.DeviceID || root.RemoteRootID != s.binding.RootID || root.ServerIdentity != s.binding.ServerIdentity {
			return ErrStaleGeneration
		}
		var prepared int
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM remote_preparations WHERE root_id=?)", s.root).Scan(&prepared); err != nil {
			return err
		}
		if prepared != 0 {
			return ErrRemoteIncomplete
		}
		if err = s.validateRetainedHTTPIdentity(ctx, tx); err != nil {
			return err
		}
		p := *current.HTTPRebootstrap
		if p.RetiredSnapshotIDs != "" && len(strings.Split(p.RetiredSnapshotIDs, ",")) >= 16 {
			return ErrHTTPRebootstrapLimit
		}
		if p.RetiredSnapshotIDs != "" {
			p.RetiredSnapshotIDs += ","
		}
		p.RetiredSnapshotIDs += p.SnapshotID
		p.SnapshotID = id
		current.HTTPRebootstrap = &p
		if !validHTTPCheckpoint(current, s.transportPin) {
			return ErrIdentityConflict
		}
		if err = saveCandidate(ctx, tx, current); err != nil {
			return err
		}
		result = current
		return s.r.point("http_rebootstrap.retire_expired_before_commit")
	})
	return result, err
}

func (s *IsolatedHTTPSession) startRebootstrapSnapshot(ctx context.Context, c RemoteCandidate, checkpoint HTTPRebootstrapCheckpoint) (SnapshotPreparation, error) {
	var zero SnapshotPreparation
	body := map[string]any{"binding": bindingHTTP(s.binding), "snapshot_id": checkpoint.SnapshotID}
	progress, err := s.post(ctx, "snapshots/start", body)
	if err != nil {
		return zero, err
	}
	for step := 0; step < 16384; step++ {
		value, err := syncproto.Parse(progress)
		if err != nil {
			return zero, err
		}
		m, err := strictHTTPObject(value, "snapshotId", "state", "startSeq", "appliedSeq", "cutSeq", "entries", "documentBytes")
		if err != nil || m["snapshotId"] != checkpoint.SnapshotID {
			return zero, ErrIdentityConflict
		}
		for _, key := range []string{"startSeq", "appliedSeq", "entries", "documentBytes"} {
			if _, err := syncproto.Integer64(m[key]); err != nil {
				return zero, err
			}
		}
		if m["state"] == "READY" {
			break
		}
		if m["state"] != "BASE" && m["state"] != "OVERLAY" {
			return zero, ErrRemoteUnqualified
		}
		progress, err = s.post(ctx, "snapshots/step", body)
		if err != nil {
			return zero, err
		}
		if step == 16383 {
			return zero, ErrSourceQuota
		}
	}
	raw, err := s.post(ctx, "snapshots/ready", body)
	if err != nil {
		return zero, err
	}
	snapshot, err := syncproto.ReadSnapshot(raw)
	if err != nil || snapshot.Binding != s.binding || snapshot.SnapshotID != checkpoint.SnapshotID {
		return zero, ErrIdentityConflict
	}
	cut, err := syncproto.Integer64(snapshot.CutSeq)
	if err != nil || cut < checkpoint.Original.Position {
		return zero, ErrIdentityConflict
	}
	return s.r.prepareSnapshot(ctx, s.root, c.TrustGeneration, raw, time.Now(), &checkpoint)
}

func (s *IsolatedHTTPSession) finishRebootstrap(ctx context.Context, expected RemoteCandidate) error {
	if expected.HTTPRebootstrap == nil {
		return nil
	}
	if !validHTTPCheckpoint(expected, s.transportPin) || expected.HTTPRebootstrap.Phase != httpBootstrapAwaitFeed {
		return ErrRemoteUnqualified
	}
	return s.r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		current, err := readCandidate(ctx, tx, s.root)
		if err != nil {
			return err
		}
		root, err := readRoot(ctx, tx, s.root)
		if err != nil || current.RemoteWitness != expected.RemoteWitness || current.HTTPRebootstrap == nil || *current.HTTPRebootstrap != *expected.HTTPRebootstrap || root.ActiveRemoteGeneration != current.Generation || root.TrustGeneration != current.TrustGeneration || !validHTTPCheckpoint(current, s.transportPin) {
			return ErrStaleGeneration
		}
		anchor, err := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", s.root, current.Generation, s.binding.RootID)
		if err != nil || anchor.ParentID != "" || anchor.Kind != "folder" || anchor.Presence != "PRESENT" || anchor.Availability != "AVAILABLE" || anchor.RemoteBinding == nil || *anchor.RemoteBinding != s.binding {
			return ErrRemoteUnqualified
		}
		current.HTTPRebootstrap = nil
		current.Valid = true
		if current.Revision == math.MaxInt64 {
			return ErrStaleGeneration
		}
		current.Revision++
		if err = saveCandidate(ctx, tx, current); err != nil {
			return err
		}
		return s.r.point("http_rebootstrap.before_qualified")
	})
}
