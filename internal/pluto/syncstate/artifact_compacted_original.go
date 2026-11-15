package syncstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
)

// ConfirmDisposedOriginal proves an already ACKed captured original's artifact
// was compacted and is physically absent. It performs no deletion or repair.
// Generic Dispose still rejects a missing accounting row for an unknown owner.
func (a *Artifacts) ConfirmDisposedOriginal(ctx context.Context, given Operation) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.ready {
		return ErrArtifactUnreconciled
	}
	if !artifactUUID(given.SnapshotID) || given.Captured == nil {
		return ErrIdentityConflict
	}
	if a.live[given.SnapshotID] != nil {
		return ErrArtifactInUse
	}
	if err := a.validate(ctx, a.store.db); err != nil {
		return err
	}
	return a.store.transaction(ctx, func(tx *sql.Tx) error {
		if err := a.validate(ctx, tx); err != nil {
			return err
		}
		if _, err := readArtifact(ctx, tx, given.SnapshotID); !errors.Is(err, sql.ErrNoRows) {
			if err == nil {
				return ErrArtifactRetained
			}
			return err
		}
		op, err := readOperation(ctx, tx, given.OperationID)
		if err != nil {
			return err
		}
		if op.Stage != "CLIENT_ACKED" {
			return ErrArtifactRetained
		}
		if op.Captured == nil || op.RootID != given.RootID || op.EntryID != given.EntryID || op.LocalGeneration != given.LocalGeneration || op.SizeBytes != given.SizeBytes || op.SHA256 != given.SHA256 || op.SnapshotID != given.SnapshotID || op.IntentFingerprint != given.IntentFingerprint || op.SealedFingerprint != given.SealedFingerprint || fingerprint(given.Intent) != op.IntentFingerprint {
			return ErrInvalidReceipt
		}
		var raw string
		var receipt Receipt
		if err = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(receipt_json)<=16384 THEN receipt_json ELSE '' END FROM operations WHERE operation_id=?", op.OperationID).Scan(&raw); err != nil {
			return err
		}
		if json.Unmarshal([]byte(raw), &receipt) != nil || !validCapturedReceipt(op, receipt) {
			return ErrInvalidReceipt
		}
		var st unix.Stat_t
		err = unix.Fstatat(int(a.directory.Fd()), op.SnapshotID+".snapshot", &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return ErrArtifactUnreconciled
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		return a.validate(ctx, tx)
	})
}
