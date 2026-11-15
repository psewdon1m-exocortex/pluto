package syncstate

import "database/sql"

// DBStats describes pool counters, not filesystem/kernel I/O or SQL row work.
func (s *Store) SQLStats() sql.DBStats { return s.db.Stats() }
