# Indexed daemon and migration

Implementation handoff, 2026-10-14. This describes source code, not a qualified release. Tests, builds, typecheck, services, installation and deployment were not run.

The statement above records the original handoff, not the current test status. Later checks and remaining release gates are recorded in [qualification status](QUALIFICATION_STATUS_2026-10-16.md).

## Preserved behavior

Existing installations keep their current writer until explicit adoption. Enrollment does not activate indexed mode. After adoption, `indexed-activation.json` fences legacy fallback even if indexed config is removed. Source removal, exclusion, rename or disappearance never issues remote MOVE/delete. Legacy copy and indexed profiles without `scale-transfer-v2` retain the 256 MiB file limit. An explicitly selected and negotiated `scale-transfer-v2` stream uses the lower of the server's advertised maximum and the client's 2 GiB limit. The sealed-artifact accounting limit remains 256 MiB. Retention remains 10 active versions.

The normal service owns one indexed session across cycles, recovers original operations before new work, and joins work before pause/update/shutdown. Closing checkpoints SQLite, closes HTTP and detaches admission without freeing retained artifact charges. `indexed-session.json` records RUNNING/STOPPED; STOPPED requires successful close.

`intervalSeconds` schedules guarded health/reconciliation. Continuous inotify observation processes durable dirty generations with 750 ms quiet / 5 s maximum debounce. Cold restart, overflow, mount/source changes and detached watches retain a gap. Directory and regular-file inode watches include hardlink writes, bounded to 65,536 paths. Unavailable observation uses periodic guarded reconciliation. Silence, size and mtime are not universal content proofs. Guarded file symlinks retain their existing behavior and require periodic verification; directory links remain unsupported. Empty observed directories use durable folder operations.

## Protected profile

The candidate is a 0600 regular file owned by the executing service UID, with one hardlink and no final symlink. Run offline state-changing commands as the Pluto service account. Preserve original daemon configuration and credentials.

```json
{
  "schema":"pluto.indexed-profile/v1",
  "local_root_id":"backup-main",
  "mapping_id":"mapping-main",
  "source_set_id":"sources-main",
  "sources":[{"id":"source-main","selected_path":"/srv/data","working_directory":"/"}],
  "remote":{
    "domain":"pluto.guarded-daemon-http/v1",
    "origin":"https://saturn.example.invalid",
    "allowed_addresses":[],
    "binding":{
      "protocol":"neptune-sync/1",
      "descriptor_schema":"saturn.current-namespace.v1",
      "server_identity":"qualified-server-identity",
      "root_id":"00000000-0000-4000-8000-000000000001",
      "server_epoch":"00000000-0000-4000-8000-000000000002",
      "policy_version":"qualified-policy-version",
      "binding_version":"00000000-0000-4000-8000-000000000003"
    },
    "device_id":"00000000-0000-4000-8000-000000000004",
    "backend_identity":"storage-primary",
    "qualification_receipt_sha256":"REPLACE_WITH_QUALIFIED_SHA256",
    "token":"",
    "features":[],
    "name_codec":"legacy",
    "bandwidth_bytes_per_second":0
  },
  "small_batch_mode":""
}
```

The example is illustrative and intentionally not qualified. Use the real server binding/receipt and preserve the current ordered source list and existing local IDs. The daemon supplies its original access token; candidate tokens are not persisted into the adopted profile. HTTPS origin, device, backend, seven-field binding and qualification receipt must match capabilities. Optional `remote.policy_hash` pins the server namespace policy, distinct from the local source-policy digest. Empty address pins allow HTTPS DNS; explicit pins constrain resolved addresses. Redirects are refused. The protected daemon config selects `proxy: {"mode":"environment"}` (default), `{"mode":"direct"}`, or `{"mode":"explicit","url":"https://proxy.example:8443"}` for both heartbeat/legacy and guarded sessions. Configuration changes require reopening the service/session. Environment mode reads the process's HTTPS_PROXY/NO_PROXY settings; it does not follow Windows system proxy changes. CONNECT targets an approved resolved IP and origin TLS still verifies the Saturn hostname. Isolated HTTP profiles remain direct-only.

Accepted revisions: K1 r2, K2 r2, K3 r2, K4 r1. Base capabilities: snapshot-v1, changes-v1, folder-v2, catalog-upload-v2. An advertised feature alone never enables an optimization. K1 delete-plan approval is not used by Pluto.

## Migration and maintenance

These commands describe a later authorized deployment; none were executed during implementation:

1. Apply Saturn additive API/schema, qualify the root/backend and install a compatible Pluto package with optional features OFF.
2. `pluto pause` cancels and waits for drain. Stop the daemon before offline adoption or policy application. Preserve the prior enabled state and schedule in the migration record.
3. `pluto migrate-plan --profile /protected/profile.json` reads config/state and reports old/new bindings, schema, pending/unresolved originals and compatibility. Its digest binds these inputs without exporting credentials or original payloads.
4. `pluto adopt --profile /protected/profile.json --plan-digest DIGEST` rechecks the paused plan under an exclusive lifecycle lock, saves a WAL-aware backup when state exists, records PREPARED activation, writes config and completes the journal. Repeating a matching adoption is idempotent. Incompatible originals or unreconciled legacy spool block adoption and remain untouched.
5. Start the daemon while paused, inspect status, then explicitly `pluto resume`. The first run negotiates authority, adds state modules and performs recovery/reconciliation.

All commands retain `--config`, `--state`, `--socket` overrides. `inspect` reports schema, pending work, retained artifacts, retry states and conservative rollback information. `diagnostics` prefers live status/transport counters and falls back to readonly inspection. `checkpoint` and `backup` use the paused local service or exclusive offline ownership. Backup uses SQLite's backup API, including committed WAL, and returns its SHA-256.

Additive v8 stores observer/dirty generations, retries, parent cache, policy and stream progress. Original JSON, IDs, receipts and batch membership remain intact. Feature rollback disables future selection while recovering originals. Binary update checks `--writer-schema`; incompatible rollback retains the profile, previous binary and update journal. Never restore an older database over newer remote publications.

## Source policy and names

`policy-plan` / `policy-apply` and `namespace-plan` / `namespace-apply` take protected JSON via `--profile`:

```json
{"revision":2,"codec":"legacy","excludes":["srv/data/cache"],"sources":["/srv/data"]}
```

`sources` is optional; omission preserves current sources. Excludes are exact relative destination prefixes. There are no implicit `.git`, `node_modules` or `.audit` exclusions. Plans report affected indexed scope, invalid names, collisions and unresolved originals. Apply requires the exact digest, paused/stopped daemon, no pending originals, a WAL-aware backup and the next revision. `policy-apply.json` records PREPARED → STATE_APPLIED → COMPLETE. Remote copies remain.

Legacy retains spelling/case semantics. `portable_v1` requires an explicit local/server transition: NFC, ≤255 scalars / 1020 UTF-8 bytes; no controls/surrogates, separators, Windows punctuation, trailing dot/space or DOS device stems (including COM/LPT superscript digits). Collision keys fold ASCII A–Z only. Non-NFC/colliding names are reported, never normalized or renamed. Pluto gains no MOVE rights for case-only changes. Coordinate the server policy before resuming.

For an already active profile, the same `migrate-plan` / `adopt` commands accept a reviewed replacement binding after the server transition. Root/mapping/source/device identity and local policy remain fixed; pending originals block rebinding. A durable binding-transition cursor resumes after interruption. Only after HTTPS qualification and a complete new snapshot are baselines with matching node/parent/name and exact file version/hash rebound. Changed/missing objects remain conflicts. Historical operation JSON and receipts are never rewritten. This also permits explicit feature-setting changes with an unchanged binding.

## Optional transport

All features start OFF and require local selection plus qualified server support:

| Setting | Behavior |
|---|---|
| `features: ["changes-wait-v1"]` | Cancellable feed wait ≤25 s, original cursor semantics. Ordinary polling is the fallback. |
| `folder-batch-v1` | Same-original singleflight, ≤500 items / 4 MiB, parent refs and independent outcomes. Unsupported/oversized requests fall back to original individual requests. Bounded positive/negative cache is invalidated by feed/policy. |
| `namespace-mutations-v1` | Independent original metadata items coalesce into bounded batches with per-item outcomes and individual fallback. Create-empty avoids a content-upload session; metadata-patch requires guarded capture and exact baseline/content-version proof. Capability fallback is existing upload. |
| `clone-content-v1` plus `namespace-mutations-v1` | Lookup of an already captured hash inside the authorized root; clone binds immutable source version. No match/unsupported lookup falls back to upload. Submitted uncertainty retains the original. |
| `stream-upload-v1` | Files ≥8 MiB send 4 MiB chunks before whole SHA completion. Durable identity, ACK map and final source guard precede seal. Restart rehashes source and skips ACKed chunks; changed source remains deferred. |
| `scale-transfer-v2` plus `stream-upload-v1` | Explicitly selected indexed streams support up to 2 GiB, subject to the negotiated server maximum, using bounded 4 MiB parts and paged acknowledgements. A 2 GiB + 1 byte source is refused before a content original or payload is created. Enrollment and an advertised capability do not enable this feature automatically. |
| `metadata-gzip-v1` | JSON >16 KiB only, bounded compressed/expanded reads and unchanged canonical intent. File/binary batch bytes are not compressed. |
| `small_batch_mode: "bulk"` / `"changes"` | Existing ≤500-item / 32 MiB batches, private aggregate accounting and per-original receipts. Disabling retires aggregates while preserving individual recovery. Separate enablement gate: ≥15% throughput benefit and p95 regression ≤20%. |

Process budgets retain two data workers, one source reader and 256 MiB plaintext accounting. Streaming reserves two 4 MiB buffers plus metadata. Network admission starts at one data request, adapts within 1–2, reserves metadata admission and schedules live/recovery/bootstrap by weighted bytes with aging. Only publication receipts drive useful throughput; received bytes are not publication. Nonzero `bandwidth_bytes_per_second` adds cancellable aggregate pacing.

Durable retries: RETRY_WAIT, SOURCE_BUSY, WAIT_CONNECTIVITY, DEGRADED. Jitter is capped at 60 s; Retry-After is a lower bound; eight failures impose a 15-minute minimum. Original status/identity precedes retry. 401/403/407 pause network work and retain credentials and originals; an intermediary response alone cannot revoke registration. Binding/policy mismatch and 412 require reconciliation. New source hints can wake retry waiting without replacing the delayed original or bypassing its deadline. Control requests and long polls have a 45 s complete-response deadline; progressing data has a 30 s inactivity deadline and no fixed whole-transfer timeout. Legacy copy preserves its separate 120 s header wait.

Status/check-in expose phase, queue/capture/publication counts, oldest dirty age, gap, HTTP totals and selected features. TUI shows the operational summary; local diagnostics include network pressure. No credentials or file contents are exported.

With `namespace-mutations-v1` enabled, a committed content acknowledgement can leave a source metadata followup. The daemon records a bounded dirty hint and reconciles the metadata through its own original before reporting an observing state. A crash between the content acknowledgement and the hint is recovered through the normal reopened session. Content intents and receipts remain unchanged. An unchanged source can still be read and hashed during a NOOP; zero payload and stable originals/versions do not imply zero source reads.

## Local progress, elapsed and ETA

Local `/status` has an optional top-level `progress` object. It is outside `observation`, so the strict Saturn check-in body and saved observation format are unchanged. Older native status consumers can ignore the new object. It contains a run ID, process-monotonic elapsed milliseconds, attempt number, checked-file/publication counts, payload request bytes and an explicit ETA state. This telemetry does not alter originals, receipts, writer authority or the durable-state schema.

The run clock starts when work starts and continues over automatic network retries and TUI detach/reattach. Attempt counters restart on retry; elapsed and request-byte accounting remain attached to the logical run. Continuous indexed observation keeps that run open and has no finite ETA while waiting for changes. Pause, completion and failure freeze elapsed. An explicit Copy now, including a NOOP, creates a new run. A new OS process exposes no old monotonic clock until it starts work; historical wall-clock timestamps are not used to invent continuity.

The indexed path uses existing verified/publication reports and atomic HTTP request counters. It does not scan the source or query the state database to obtain a total. Its total is therefore unknown. The legacy path counts the file tasks already admitted by its ordinary enumeration and seals the total only when enumeration ends. A numeric ETA estimates the remaining file checks from that total and the observed checked-task rate, including elapsed waiting. Discovery growth withdraws the estimate until the new total is established. Zero speed, unknown total, waiting, pause and finalization never produce a fabricated zero ETA or 100% completion. A known nonempty task set can reach 100% only after successful completion.

Payload request bytes are declared data bytes in attempted requests, including retries; they are not acknowledged or physically stored bytes. After five seconds without a new observed counter, the UI reports **waiting progress** (`waiting_progress` in status) and makes ETA unavailable. A single healthy in-flight upload can also have unchanged admission counters, so this state does not diagnose a network stall. The publication count mirrors existing per-attempt results, not a unique resource inventory. `noDataPayload` means no data payload was requested; metadata-only effects can still exist. NOOP acceptance separately checks stable originals/versions and full readback.

The native main menu shows these values without another input reader or ticker. A failed IPC refresh labels the displayed snapshot as last known and later recovers without sending a control command. The daemon clock continues while that snapshot is unavailable. Exit and context cancellation restore the terminal attributes.

## Remaining qualification

The original implementation handoff did not establish a runtime PASS. Subsequent local results and the exact limitations of the 2026-10-20 RC01 checks are recorded in [qualification status](QUALIFICATION_STATUS_2026-10-16.md#2026-10-20-rc01-local-acceptance). Production release gates still include the published mixed-version matrix, real provider qualification, installed upgrade/rollback, shared clean artifacts, bounded resources/fairness and measured performance.

The optional [Saturn host verifier](../../saturn/packages/storage-verifier/README.md) is separate from Pluto. CHAT-A owns server integration and registry delivery. Host installation, TLS/fencing/no-follow/fsync and readback fallback need separate qualification. O01–O03 and the six-hour run remain outside this work.
