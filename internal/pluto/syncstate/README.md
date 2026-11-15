# Inactive transactional state foundation

This Linux package is additive. `Copy`, the daemon scheduler, configuration,
existing root binding, paused state, and `status.json` keep their current behavior.
No production path opens this database yet. `engine_ready` is constrained to zero;
there is no method that enables a metadata shortcut or a destructive operation.

`Open` places `sync-state.sqlite` in the caller's protected state directory. It
requires one process writer, uses SQLite WAL with synchronous FULL and foreign
keys, one connection, an 8 MiB page cache, and batches/pages of at most 1000 rows.
Transactions contain SQL only. Parent/identity checks, observation generations,
dirty work, and journal cursor advancement commit together.

Local observations (L), acknowledged baselines (B), and remote observations (R)
are separate records. Unknown B remains absent. A remote update never changes B.
Immutable operation IDs and intent are durable before transport; a sealed hash
must match an available hash for that observed local generation. Before first
transport, local generation/identity, root trust, and the authoritative R/B
comparison are checked again. R requires an adapter supplying a contiguous
committed server feed; ordinary HTTP metadata is insufficient evidence.

Only a verified publication receipt for that exact operation updates B. The
receipt's actual local generation and trust generation are retained honestly.
Newer local/remote work and trust invalidation survive an older acknowledgment.
Unknown B permits create-only intent; overwrite needs B from the current trust
generation, a valid remote cursor, and authoritative R matching B. No method
adopts a fresh remote version as a baseline to resolve a conflict automatically.
The 256 MiB file limit, 10-version server policy, and absence of remote delete
remain explicit immutable root constraints.

Legacy JSON migration is conservative: `config.json` and `status.json` are never
rewritten, no credentials are imported, B is UNKNOWN, and the legacy status bytes
are backed up before a private database generation is atomically published.
Migration has a versioned manifest. Existing databases are checked read-only for
application/schema version, full required DDL, quick integrity and foreign keys
before any writable connection. Unsupported/corrupt bytes are preserved.

A changed legacy `status.json` checkpoint on a later open increments root trust
generation and invalidates cursors while preserving B and operations. This detects
that observable old-client checkpoint change; it cannot prove that an old client
did not run without writing status. Protocol writer leases, explicit version
handoff, full rollback qualification, and safe trust activation remain gates.

Still required before activating the store: daemon/adapters and writer handoff,
gap recovery with a verified shadow remote generation, durable scan/conflict/chunk
and spool models, full reconciliation/adoption, authoritative server feed,
crash/power-loss qualification on target filesystems, and delivery of SQLite
dependency notices in actual release/install artifacts. This package does not
reduce repeat-sync work by itself.

## Inactive bounded advisory planner

`PlanDirtyPage` now reads up to 1000 dirty keys under one SQLite read snapshot.
Root/cursor lookups, dirty joins, pending outcomes and namespace lookups use
indexes; no source bytes or whole-tree arrays are read. For each destination,
at most 128 ancestors are checked using indexed L/B/R and pending-operation
lookups. Missing or deeper ancestry requires reconciliation. A stable folder
node ID does not authorize a renamed/moved path: all ancestor names, local
identities, kinds, parent relations, current baseline trust/epoch and remote
versions must still match. An unresolved ancestor operation also blocks writes.
An ancestor cache belongs to this read snapshot alone. The whole page retains
at most 4096 actual deserialized ancestor L/B/R/pending records and 8 MiB of their
encoded JSON/scalar payload; struct/pointer overhead is additionally bounded by
the record, depth and page limits. Common parents share the same descriptors.
Budget exhaustion produces reconciliation and is sealed into the witness;
unknown ancestry is never accepted because a cache/page budget was exhausted.

The caller must supply typed certificates from a future qualified adapter:
continuous local journal/reconciliation anchored to the exact source/device and
trust generation, plus a verified snapshot and contiguous remote feed through
the exact applied cut. These structures identify retained adapter evidence;
constructing a struct does not qualify real-world continuity. Validation windows
are at most 30 seconds and expire even when stored cursors have not changed.
This freshness limit is not a server lock or publication fence.

NOOP requires a current-generation verified local hash, a current-trust B, and
authoritative current R=B at the qualified cut. UNKNOWN never becomes ABSENT
from `metadata not_found`. Authoritative namespace absence permits create-only;
verified equal content permits conditional adoption; overwrite requires current
R=B and the expected baseline version. Conflicts retain remote data, and local
absence never schedules remote deletion. Every non-ACK operation is recovered
using its original immutable ID, including an old generation or uncertain
outcome. The store cannot cancel such an outcome and manufacture a new ID.
KEEP_REMOTE and RECOVER can route work even when cut qualification is missing,
because they authorize no publication, baseline adoption, dirty clearing or trust
change. A future executor must retain the current immutable outcome and apply
generation-conditional updates after its own qualified evidence checks.

Each decision seals the exact read-snapshot state, relevant certificates and
decision. `RevalidatePlan` must succeed immediately before any future execution;
an expired certificate, local/remote/ancestor update, pending outcome or trust
invalidation rejects the old witness. Publication still needs immutable durable
intent, local generation checks and real server CAS/fencing after revalidation.
No daemon or `Copy` path calls the planner, and `engine_ready` remains zero.
Witness domains are explicitly versioned. A snapshot-cached parent L/B/R/pending
binding is hashed once; each leaf seals the ordered entry/node/hash sequence,
terminal bound root identity, and reached-root/missing/pending/cycle/depth/budget
outcome. Exact-entry revalidation rebuilds the bindings under a new read snapshot
and recomputes the hashes. This retains ancestor evidence without serializing
long parent names for every leaf repeatedly.
Revalidation never regenerates or returns an upgraded decision: if planning a
whole page ran out of ancestor budget while an exact-entry read can now qualify
it, the former witness is stale. Only a new planning call produces a new witness.

Schema v2 adds a partial pending-entry index excluding `CLIENT_ACKED` history.
The exact v1 schema is recognized read-only, backed up through SQLite's WAL-aware
backup API in bounded page steps, then upgraded by an atomic index/version/journal
transaction. The hash-addressed private v1 backup is recorded in the migration
manifest. L/B/R, intents, cursors, bindings and legacy JSON keep their meaning;
reopening v2 does not repeat the migration. Unsupported/corrupt DDL still fails
before writable open. The v1 foundation binary fails closed on v2; an older
pre-SQLite binary still requires the explicit handoff/rollback trust gates above.

`PlanPage.Queries` counts logical SELECT calls, and `RowsRead` counts dirty joined
descriptor bundles, ancestor bundles, pending records and extra namespace R
records returned. They are not SQLite VM-step or filesystem-page measurements.
With one root-level dirty entry the planner uses five SELECTs independently of
tree size or ACK history. Ancestor work is explicitly bounded by depth rather
than hidden in an unbounded recursive walk. The 100k/500k fixtures and 10k/100k
ACK-history fixtures qualify this inactive planner boundary; they do not measure
real repeat-sync speed or establish production journal/feed coverage.
