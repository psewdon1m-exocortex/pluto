package syncstate

import (
	"context"
	"database/sql"
	"strings"
)

// CanInitializePreparedPolicy is a read-only fence for a failed first startup,
// not permission to change a policy or activate a writer. The caller must also
// hold the lifecycle lease and match the original PREPARED input/plan digests.
// No original, imported cut, observation, or installed policy may be present.
func (s *Store) CanInitializePreparedPolicy(ctx context.Context, expected RootBinding, codec string) (bool, error) {
	if codec != "portable_v1" {
		return false, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	root, err := readRoot(ctx, tx, expected.RootID)
	if err != nil {
		return false, err
	}
	if root.RootBinding != expected || root.NameCodec != "legacy" || root.AllowsDelete || root.EngineReady || root.Trust != TrustRequired || root.TrustGeneration != 1 || root.ActiveRemoteGeneration != 1 || root.MaxFileBytes != MaxFileBytes || root.MaxActiveVersions != MaxActiveVersions {
		return false, nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return false, err
	}
	var tables []string
	for rows.Next() {
		var table string
		if err = rows.Scan(&table); err != nil {
			rows.Close()
			return false, err
		}
		tables = append(tables, table)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	for _, table := range tables {
		query := "SELECT EXISTS(SELECT 1 FROM \"" + strings.ReplaceAll(table, "\"", "\"\"") + "\")"
		switch table {
		case "schema_migrations", "source_bindings", "source_prefix_work", "artifact_scope":
			continue // Startup identity/schema records; none contains an original.
		case "roots":
			query = "SELECT COUNT(*)<>1 FROM roots"
		case "source_sets":
			query = "SELECT EXISTS(SELECT 1 FROM source_sets WHERE set_id<>? OR attached_root_id<>? OR attached_root_id IS NULL OR owner_id<>'' OR owner_sequence<>0 OR gap_generation<>0)"
			var found bool
			if err = tx.QueryRowContext(ctx, query, expected.SourceIdentity, expected.RootID).Scan(&found); err != nil || found {
				return false, err
			}
			continue
		}
		var found bool
		if err = tx.QueryRowContext(ctx, query).Scan(&found); err != nil || found {
			return false, err
		}
	}
	return true, tx.Commit()
}
