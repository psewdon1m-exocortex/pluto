package syncstate

import (
	"context"
	"database/sql"
)

// A job contains at most sixteen immutable originals. Group only their local
// persistence; every binding/receipt still passes the ordinary current-row
// checks. No transaction spans HTTP refresh, transport or physical deletion.
func (d *smallBatchDispatcher) applySmallJobOutcomes(ctx context.Context, plan *smallBatchPlan, outcomes []smallBatchItemOutcome) error {
	if !plan.executionJob || len(plan.entries) < 1 || len(plan.entries) > 16 || len(outcomes) != len(plan.entries) {
		return ErrInvalidReceipt
	}
	r := d.session.r
	published := false
	if err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		for n, outcome := range outcomes {
			if outcome.status == nil {
				continue
			}
			var current Operation
			if err := r.bindHTTPUploadTx(ctx, tx, plan.entries[n].original, outcome.status.binding.ServerUploadID, plan.entries[n].input.hash, &current); err != nil {
				return err
			}
			published = published || outcome.status.publication != nil
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.point("http_binding.after_commit"); err != nil {
		return err
	}
	if !published {
		return nil
	}
	if err := d.session.Refresh(ctx); err != nil {
		return err
	}
	if err := r.sources.change(ctx, MaxSourcePageBytes, func(tx *sql.Tx) error {
		var version int
		if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		for _, outcome := range outcomes {
			if outcome.status == nil || outcome.status.publication == nil {
				continue
			}
			if err := r.ackCapturedTx(ctx, tx, *outcome.status.publication); err != nil {
				return err
			}
			if version == daemonSchemaVersion {
				if _, err := tx.ExecContext(ctx, "DELETE FROM operation_retry WHERE operation_id=?", outcome.operationID); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, outcome := range outcomes {
		if outcome.status != nil && outcome.status.publication != nil {
			if err := r.afterContentAck(ctx, outcome.operationID); err != nil {
				return err
			}
		}
	}
	return nil
}
