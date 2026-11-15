package syncstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func (a *Artifacts) open(record ArtifactRecord) (*os.File, error) {
	if record.Name != record.ID+".snapshot" || !artifactUUID(record.ID) {
		return nil, ErrIdentityConflict
	}
	fd, err := unix.Openat(int(a.directory.Fd()), record.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(a.path, record.Name))
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Size() < 0 || info.Size() > record.ExpectedBytes || record.FileIdentity == "" || artifactIdentity(info) != record.FileIdentity {
		f.Close()
		return nil, ErrIdentityConflict
	}
	return f, nil
}
func artifactUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range []byte(id) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func artifactIdentity(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return decimal(st.Dev) + ":" + decimal(st.Ino)
}
func decimal(value uint64) string { return strconv.FormatUint(value, 10) }

type artifactCapture struct {
	SnapshotEvidence
	SourceFileIdentity string
}

// Snapshot UUID reference closes crash-between-Seal-and-Bind. It never guesses
// by digest, repairs an intent, or creates a replacement network identity.
func artifactOperation(ctx context.Context, q queryer, r ArtifactRecord) (Operation, error) {
	var id, next string
	err := q.QueryRowContext(ctx, "SELECT operation_id FROM operations WHERE snapshot_id=? AND snapshot_id<>'' ORDER BY operation_id LIMIT 1", r.ID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		if r.OperationID != "" {
			return Operation{}, ErrInvalidReceipt
		}
		return Operation{}, sql.ErrNoRows
	}
	if err != nil {
		return Operation{}, err
	}
	err = q.QueryRowContext(ctx, "SELECT operation_id FROM operations WHERE snapshot_id=? AND snapshot_id<>'' AND operation_id>? ORDER BY operation_id LIMIT 1", r.ID, id).Scan(&next)
	if err == nil {
		return Operation{}, ErrIdentityConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Operation{}, err
	}
	if r.OperationID != "" && r.OperationID != id {
		return Operation{}, ErrIdentityConflict
	}
	var bounded int
	if err = q.QueryRowContext(ctx, "SELECT length(intent_json)<=? FROM operations WHERE operation_id=?", MaxSourcePageBytes, id).Scan(&bounded); err != nil {
		return Operation{}, err
	}
	if bounded != 1 {
		return Operation{}, ErrSourceQuota
	}
	op, err := readOperation(ctx, q, id)
	if err != nil {
		return Operation{}, err
	}
	var raw string
	var capture artifactCapture
	if err = q.QueryRowContext(ctx, "SELECT CASE WHEN length(capture_json)<=16384 THEN capture_json ELSE '' END FROM local_artifacts WHERE artifact_id=?", r.ID).Scan(&raw); err != nil {
		return Operation{}, err
	}
	root, err := readRoot(ctx, q, op.RootID)
	if err != nil {
		return Operation{}, err
	}
	if json.Unmarshal([]byte(raw), &capture) != nil || capture.SetID == "" || capture.Witness.SetID != capture.SetID || capture.SnapshotID != r.ID || capture.SHA256 != r.SHA256 || capture.SizeBytes != r.SizeBytes || !validHash(capture.GuardDigest) || root.SourceIdentity != capture.SetID || op.Captured == nil && (capture.Destination != op.EntryID || capture.EntryGeneration != op.LocalGeneration) || op.Captured != nil && !capturedArtifactMatches(op, capture) || capture.SourceFileIdentity == "" || capture.SourceFileIdentity != op.FileIdentity || op.OperationID != id || op.Stage == "PLANNED" || op.SnapshotID != r.ID || op.SHA256 != r.SHA256 || op.SizeBytes != r.SizeBytes || op.IntentFingerprint != fingerprint(op.Intent) || op.SealedFingerprint != fingerprint(struct{ IntentFingerprint, SHA256 string }{op.IntentFingerprint, op.SHA256}) {
		return Operation{}, ErrIdentityConflict
	}
	return op, nil
}

// A bounded namespace check after our own directory mutation prevents a
// concurrent unknown insertion from being hidden by the new directory ctime.
// It checks registered identity/size, not a claim that content never changes.
func (a *Artifacts) checkNamespace(ctx context.Context) error {
	fd, err := unix.Openat(int(a.directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), a.path)
	defer dir.Close()
	count := 0
	for {
		entries, readErr := dir.ReadDir(MaxSourcePage)
		for _, entry := range entries {
			count++
			if count > a.limits.Records {
				return ErrArtifactUnreconciled
			}
			var id string
			if err = a.store.db.QueryRowContext(ctx, "SELECT CASE WHEN length(artifact_id)=36 THEN artifact_id ELSE '' END FROM local_artifacts WHERE filename=?", entry.Name()).Scan(&id); err != nil {
				return errors.Join(ErrArtifactUnreconciled, err)
			}
			r, err := readArtifact(ctx, a.store.db, id)
			if err != nil {
				return err
			}
			if r.Phase == ArtifactGone || r.Phase == ArtifactReserved || r.Phase == ArtifactDisposing {
				return ErrArtifactUnreconciled
			}
			f, err := a.open(r)
			if err != nil {
				return errors.Join(ErrArtifactUnreconciled, err)
			}
			if err = f.Close(); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
func (a *Artifacts) verify(ctx context.Context, r ArtifactRecord, reader func(context.Context) (func(), error)) error {
	f, err := a.open(r)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0400 || info.Size() != r.SizeBytes || r.SizeBytes != r.ExpectedBytes || !validHash(r.SHA256) || r.SnapshotID != r.ID {
		return ErrInvalidReceipt
	}
	if reader == nil {
		return ErrIdentityConflict
	}
	release, err := reader(ctx)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.CopyBuffer(h, captureContextReader{ctx, io.LimitReader(f, r.ExpectedBytes+1)}, make([]byte, 65536))
	release()
	after, statErr := f.Stat()
	if copyErr != nil || statErr != nil {
		return errors.Join(copyErr, statErr)
	}
	if n != r.SizeBytes || hex.EncodeToString(h.Sum(nil)) != r.SHA256 || !os.SameFile(info, after) || info.ModTime() != after.ModTime() || statCTime(info) != statCTime(after) {
		return ErrInvalidReceipt
	}
	current, err := a.open(r)
	if err != nil {
		return err
	}
	defer current.Close()
	fresh, err := current.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, fresh) {
		return ErrIdentityConflict
	}
	if _, err := artifactOperation(ctx, a.store.db, r); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

// Reconcile never deletes or adopts unknown bytes. Admission requires a complete
// bounded scan; an interrupted/over-cap scan is deliberately not absence proof.
func (a *Artifacts) Reconcile(ctx context.Context, reader func(context.Context) (func(), error)) (report ArtifactReport, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	report = ArtifactReport{ScopeID: a.scope, OwnerID: a.owner, Directory: a.path, QuarantinedEmptyFiles: a.quarantinedEmpty}
	a.ready = false
	if len(a.live) != 0 {
		return report, ErrArtifactInUse
	}
	if err = a.validate(ctx, a.store.db); err != nil {
		return report, err
	}
	count, charge, e := a.aggregate(ctx, a.store.db)
	if e != nil {
		return report, e
	}
	report.Records = count
	report.ReservedBytes = charge
	problem := func(message string) {
		if len(report.Problems) < 20 {
			report.Problems = append(report.Problems, message)
		}
	}
	if count > int64(a.limits.Records) || charge > a.limits.PlaintextBytes {
		problem("registry admission limits exceeded")
		return report, ErrArtifactUnreconciled
	}
	after := ""
	for {
		rows, e := a.store.db.QueryContext(ctx, "SELECT CASE WHEN length(artifact_id)=36 THEN artifact_id ELSE '' END FROM local_artifacts WHERE artifact_id>? ORDER BY artifact_id LIMIT ?", after, MaxSourcePage)
		if e != nil {
			return report, e
		}
		ids := make([]string, 0, MaxSourcePage)
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		e = errors.Join(e, rows.Err(), rows.Close())
		if e != nil {
			return report, e
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			if e = ctx.Err(); e != nil {
				return report, e
			}
			if !artifactUUID(id) {
				problem("invalid bounded row key")
				return report, ErrArtifactUnreconciled
			}
			r, e := readArtifact(ctx, a.store.db, id)
			if e != nil {
				return report, e
			}
			after = id
			if !artifactUUID(r.ID) || r.Name != r.ID+".snapshot" {
				problem("invalid row identity: " + id)
				continue
			}
			if r.Phase == ArtifactGone {
				continue
			}
			if r.Phase != ArtifactSealed {
				problem("incomplete lifecycle: " + id + " " + r.Phase)
				continue
			}
			if e = a.verify(ctx, r, reader); e != nil {
				problem("unverified sealed artifact: " + id + " " + e.Error())
			}
			if op, e := artifactOperation(ctx, a.store.db, r); e == nil && op.Stage != "CLIENT_ACKED" {
				report.RecoveryOperations++
			}
		}
	}
	fd, e := unix.Openat(int(a.directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return report, e
	}
	dir := os.NewFile(uintptr(fd), a.path)
	defer dir.Close()
	for {
		entries, readErr := dir.ReadDir(MaxSourcePage)
		for _, entry := range entries {
			if e = ctx.Err(); e != nil {
				return report, e
			}
			report.Files++
			if report.Files > int64(a.limits.Records) {
				problem("directory record budget exceeded; scan incomplete")
				return report, ErrArtifactUnreconciled
			}
			name := entry.Name()
			var id, phase string
			e = a.store.db.QueryRowContext(ctx, "SELECT artifact_id,phase FROM local_artifacts WHERE filename=?", name).Scan(&id, &phase)
			if e != nil || phase == ArtifactGone {
				problem("unknown retained object: " + name)
			}
			// No following of symlink/foreign directory; unknown bytes block even
			// when size cannot be measured. Totals are diagnostic, never admission.
			info, statErr := entry.Info()
			if statErr != nil {
				problem("cannot inspect: " + name)
				continue
			}
			if info.Size() >= 0 && info.Size() <= MaxFileBytes-report.ObservedBytes {
				report.ObservedBytes += info.Size()
			} else {
				report.ObservedBytes = MaxFileBytes
				problem("observed plaintext exceeds limit")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return report, readErr
		}
	}
	if err = a.validate(ctx, a.store.db); err != nil {
		return report, err
	}
	report.Complete = true
	if len(report.Problems) > 0 {
		return report, ErrArtifactUnreconciled
	}
	info, e := a.directory.Stat()
	if e != nil {
		return report, e
	}
	a.directoryGeneration = statCTime(info)
	a.ready = true
	a.reader = reader
	report.Admitted = true
	return report, nil
}

// SealSnapshot accepts only the private verified capture, not a caller's claimed
// digest. It records local bytes, never a root cut or publication authorization.
func (r *ArtifactReservation) SealSnapshot(ctx context.Context, v *VerifiedSnapshot) error {
	if v == nil {
		return ErrInvalidReceipt
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	a := r.registry
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.closed || a.live[r.id] != r || v.filename != filepath.Join(a.path, r.id+".snapshot") || v.evidence.SnapshotID != r.id {
		return ErrIdentityConflict
	}
	if r.writable == nil {
		return ErrIdentityConflict
	}
	if _, err := r.writable.Stat(); !errors.Is(err, os.ErrClosed) {
		return ErrArtifactInUse
	}
	if err := v.integrity(ctx); err != nil {
		return err
	}
	current, err := readArtifact(ctx, a.store.db, r.id)
	if err != nil {
		return err
	}
	file, err := a.open(current)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if info.Mode().Perm() != 0400 || !os.SameFile(info, v.sealed) {
		return ErrIdentityConflict
	}
	if err = a.directory.Sync(); err != nil {
		return err
	}
	raw, err := json.Marshal(artifactCapture{v.evidence, v.sourceIdentity})
	if err != nil || len(raw) > 16384 {
		return errors.Join(ErrSourceQuota, err)
	}
	err = a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if err := a.validate(ctx, tx); err != nil {
			return err
		}
		old, err := readArtifact(ctx, tx, r.id)
		if err != nil {
			return err
		}
		if old.Phase != ArtifactCapturing || old.ExpectedBytes != v.evidence.SizeBytes || old.FileIdentity != artifactIdentity(v.sealed) {
			return ErrIdentityConflict
		}
		_, err = tx.ExecContext(ctx, "UPDATE local_artifacts SET phase=?,size_bytes=?,sha256=?,snapshot_id=?,capture_json=? WHERE artifact_id=?", ArtifactSealed, v.evidence.SizeBytes, v.evidence.SHA256, v.evidence.SnapshotID, string(raw), r.id)
		return err
	})
	if err == nil && a.crashPoint != nil {
		a.crashPoint("sealed")
	}
	return err
}

func (a *Artifacts) BindOperation(ctx context.Context, id, operationID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	record, err := readArtifact(ctx, a.store.db, id)
	if err != nil {
		return err
	}
	if !a.ready {
		return ErrArtifactUnreconciled
	}
	if err = a.verify(ctx, record, a.reader); err != nil {
		return err
	}
	return a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if err := a.validate(ctx, tx); err != nil {
			return err
		}
		r, err := readArtifact(ctx, tx, id)
		if err != nil {
			return err
		}
		op, err := readOperation(ctx, tx, operationID)
		if err != nil {
			return err
		}
		if r.Phase != ArtifactSealed || r.OperationID != "" && r.OperationID != operationID || op.Stage == "PLANNED" || op.SHA256 != r.SHA256 || op.SizeBytes != r.SizeBytes || op.SnapshotID != r.ID || !validHash(op.SealedFingerprint) {
			return ErrIdentityConflict
		}
		var raw string
		var capture artifactCapture
		if err = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(capture_json)<=16384 THEN capture_json ELSE '' END FROM local_artifacts WHERE artifact_id=?", id).Scan(&raw); err != nil {
			return err
		}
		if json.Unmarshal([]byte(raw), &capture) != nil || capture.SetID == "" || capture.Witness.SetID != capture.SetID || capture.SnapshotID != r.ID || capture.SHA256 != r.SHA256 {
			return ErrInvalidReceipt
		}
		if op.Captured != nil {
			// Historical association survives a later source/local generation. It
			// cannot authorize first Send, which rechecks the original witness.
			bound, err := artifactOperation(ctx, tx, r)
			if err != nil || bound.OperationID != operationID || !capturedArtifactMatches(op, capture) {
				return errors.Join(ErrIdentityConflict, err)
			}
			_, err = tx.ExecContext(ctx, "UPDATE local_artifacts SET operation_id=? WHERE artifact_id=?", operationID, id)
			return err
		}
		set, err := a.sources.checkWitness(ctx, tx, capture.Witness)
		if err != nil {
			return err
		}
		root, err := readRoot(ctx, tx, op.RootID)
		if err != nil {
			return err
		}
		entry, err := readSourceEntry(ctx, tx, capture.SetID, capture.Destination)
		if err != nil {
			return err
		}
		// This foundation uses exact destination entry keys. A future importer
		// with another local key scheme needs an explicit qualified mapping; no
		// same-hash/inode guess can associate captures with a different intent.
		if set.AttachedRootID != op.RootID || root.SourceIdentity != capture.SetID || op.EntryID != capture.Destination || op.LocalGeneration != capture.EntryGeneration || entry.Generation != capture.EntryGeneration || entry.VerificationRequest != capture.VerificationRequest || entry.SourceID != capture.SourceID || entry.SourceIncarnation != capture.SourceIncarnation || entry.FileIdentity != op.FileIdentity || capture.SourceFileIdentity != op.FileIdentity || entry.Ambiguous {
			return ErrIdentityConflict
		}
		_, err = tx.ExecContext(ctx, "UPDATE local_artifacts SET operation_id=? WHERE artifact_id=?", operationID, id)
		return err
	})
}

// RecoveryOperation exposes only the already durable identity/status. The caller
// must recover that operation; registry reconciliation does not retry the network.
func (a *Artifacts) RecoveryOperation(ctx context.Context, id string) (Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(ctx, a.store.db); err != nil {
		return Operation{}, err
	}
	r, err := readArtifact(ctx, a.store.db, id)
	if err != nil {
		return Operation{}, err
	}
	return artifactOperation(ctx, a.store.db, r)
}

func acknowledgedArtifact(ctx context.Context, q queryer, r ArtifactRecord) error {
	op, err := artifactOperation(ctx, q, r)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if op.Stage != "CLIENT_ACKED" {
		return ErrArtifactRetained
	}
	var receipt Receipt
	var raw string
	if err = q.QueryRowContext(ctx, "SELECT CASE WHEN length(receipt_json)<=16384 THEN receipt_json ELSE '' END FROM operations WHERE operation_id=?", op.OperationID).Scan(&raw); err != nil {
		return err
	}
	if json.Unmarshal([]byte(raw), &receipt) != nil || !receipt.Published || !receipt.ContentVerified || receipt.OperationID != op.OperationID || receipt.RootID != op.RootID || receipt.EntryID != op.EntryID || receipt.LocalGeneration != op.LocalGeneration || receipt.SizeBytes != r.SizeBytes || receipt.SHA256 != r.SHA256 || receipt.SealedFingerprint != op.SealedFingerprint || op.SHA256 != r.SHA256 || op.SnapshotID != r.ID || op.SizeBytes != r.SizeBytes || !validID(receipt.NodeID) || !validID(receipt.Epoch) || !validID(receipt.Version) || receipt.Seq < 1 {
		return ErrInvalidReceipt
	}
	if op.Captured != nil && !validCapturedReceipt(op, receipt) {
		return ErrInvalidReceipt
	}
	return nil
}
func (a *Artifacts) Dispose(ctx context.Context, id string) error { return a.dispose(ctx, id, nil) }
func (a *Artifacts) dispose(ctx context.Context, id string, owner *ArtifactReservation) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// The exact reservation remembers joined, durable disposal. Another worker
	// may already have pruned its GONE accounting row before the owner's final
	// budget release repeats Dispose. Missing rows for unknown owners still fail.
	if owner != nil && owner.disposed {
		return nil
	}
	if live := a.live[id]; live != nil && (live != owner || live.users != 0 || live.writable != nil && fileOpen(live.writable)) {
		return ErrArtifactInUse
	}
	if owner != nil && !owner.closed && a.live[id] != owner {
		return ErrStaleGeneration
	}
	if err := a.validate(ctx, a.store.db); err != nil {
		return err
	}
	r, err := readArtifact(ctx, a.store.db, id)
	if err != nil {
		return err
	}
	if !artifactUUID(id) || r.Name != id+".snapshot" {
		return ErrIdentityConflict
	}
	if r.Phase == ArtifactGone {
		if owner != nil {
			owner.disposed = true
		}
		return nil
	}
	if err = acknowledgedArtifact(ctx, a.store.db, r); err != nil {
		return err
	}
	f, openErr := a.open(r)
	if openErr == nil {
		f.Close()
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return openErr
	} else if r.Phase != ArtifactReserved && r.Phase != ArtifactDisposing {
		return ErrArtifactUnreconciled
	}
	if r.Phase != ArtifactDisposing {
		if err = a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
			if err := a.validate(ctx, tx); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, "UPDATE local_artifacts SET phase=? WHERE artifact_id=?", ArtifactDisposing, id)
			return err
		}); err != nil {
			return err
		}
	}
	if a.crashPoint != nil {
		a.crashPoint("disposing")
	}
	// Exact directory capability and recorded identity; never a recursive path.
	if openErr == nil {
		if err = unix.Unlinkat(int(a.directory.Fd()), r.Name, 0); err != nil {
			return err
		}
	}
	if a.crashPoint != nil {
		a.crashPoint("unlinked")
	}
	if err = a.directory.Sync(); err != nil {
		return err
	}
	if a.crashPoint != nil {
		a.crashPoint("disposed-synced")
	}
	info, err := a.directory.Stat()
	if err != nil {
		return err
	}
	a.directoryGeneration = statCTime(info)
	if err = a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if err := a.validate(ctx, tx); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "UPDATE local_artifacts SET phase=? WHERE artifact_id=? AND phase=?", ArtifactGone, id, ArtifactDisposing)
		return err
	}); err != nil {
		return err
	}
	if live := a.live[id]; live != nil {
		live.closed = true
		live.disposed = true
		delete(a.live, id)
	}
	if owner != nil {
		owner.disposed = true
	}
	if a.crashPoint != nil {
		a.crashPoint("gone")
	}
	return nil
}
func fileOpen(file *os.File) bool { _, err := file.Stat(); return !errors.Is(err, os.ErrClosed) }
func (r *ArtifactReservation) Dispose(ctx context.Context) error {
	return r.registry.dispose(ctx, r.id, r)
}

// Relinquish preserves the durable charge/row. Used when an operation or failed
// cleanup prevents disposal; all writable/read handles must already be joined.
func (r *ArtifactReservation) Relinquish() error {
	a := r.registry
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.users != 0 || r.writable != nil && fileOpen(r.writable) {
		return ErrArtifactInUse
	}
	r.closed = true
	delete(a.live, r.id)
	return nil
}
func (a *Artifacts) Charge(ctx context.Context) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(ctx, a.store.db); err != nil {
		return 0, err
	}
	_, charge, err := a.aggregate(ctx, a.store.db)
	return charge, err
}

// WithReader keeps its user reference through callback completion, preventing
// disposal and Store.Close. No external path or descriptor escapes the scope.
func (r *ArtifactReservation) WithReader(ctx context.Context, reader func(context.Context) (func(), error), fn func(io.Reader) error) error {
	a := r.registry
	a.mu.Lock()
	if r.closed || a.live[r.id] != r {
		a.mu.Unlock()
		return ErrStaleGeneration
	}
	record, err := readArtifact(ctx, a.store.db, r.id)
	if err == nil {
		err = a.validate(ctx, a.store.db)
	}
	if err == nil && record.Phase != ArtifactSealed {
		err = ErrIdentityConflict
	}
	if err != nil {
		a.mu.Unlock()
		return err
	}
	f, err := a.open(record)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	r.users++
	a.mu.Unlock()
	defer func() { f.Close(); a.mu.Lock(); r.users--; a.mu.Unlock() }()
	if reader == nil || fn == nil {
		return ErrIdentityConflict
	}
	release, err := reader(ctx)
	if err != nil {
		return err
	}
	defer release()
	before, err := f.Stat()
	if err != nil {
		return err
	}
	digest := sha256.New()
	input := captureContextReader{ctx, io.TeeReader(io.LimitReader(f, record.SizeBytes+1), digest)}
	if err = fn(input); err != nil {
		return err
	}
	if _, err = io.CopyBuffer(io.Discard, input, make([]byte, 65536)); err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if before.Size() != record.SizeBytes || after.Size() != record.SizeBytes || before.ModTime() != after.ModTime() || statCTime(before) != statCTime(after) || hex.EncodeToString(digest.Sum(nil)) != record.SHA256 {
		return ErrInvalidReceipt
	}
	return nil
}

func (a *Artifacts) CompactGone(ctx context.Context, limit int) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if limit < 1 || limit > MaxSourcePage {
		return 0, ErrSourceQuota
	}
	var removed int64
	err := a.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		if err := a.validate(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT CASE WHEN length(artifact_id)=36 THEN artifact_id ELSE '' END FROM local_artifacts WHERE phase='GONE' ORDER BY artifact_id LIMIT ?", limit)
		if err != nil {
			return err
		}
		ids := make([]string, 0, limit)
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			ids = append(ids, id)
		}
		err = errors.Join(err, rows.Err(), rows.Close())
		if err != nil {
			return err
		}
		for _, id := range ids {
			if a.live[id] != nil {
				return ErrArtifactInUse
			}
			r, err := readArtifact(ctx, tx, id)
			if err != nil {
				return err
			}
			if !artifactUUID(id) || r.Name != id+".snapshot" {
				return ErrIdentityConflict
			}
			if err = acknowledgedArtifact(ctx, tx, r); err != nil {
				return err
			}
			fd, err := unix.Openat(int(a.directory.Fd()), r.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err == nil {
				unix.Close(fd)
				return ErrArtifactUnreconciled
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			result, err := tx.ExecContext(ctx, "DELETE FROM local_artifacts WHERE artifact_id=? AND phase='GONE'", id)
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			removed += n
		}
		return nil
	})
	return removed, err
}
