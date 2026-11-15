# Local qualification status — 2026-10-16

The 2026-10-14 indexed-daemon handoff remains historical. Subsequent local audit exercised daemon pause/restart, original recovery, guarded interop, network recovery and migration boundaries. The 2026-10-16 remediation repeated the three failed copy/syncstate tests with the race detector and additional HTTP-error/retry regressions.

The embedded runtime notices were regenerated with Go 1.26.9 for linux-amd64 and linux-arm64. The linked inventory now includes `golang.org/x/text@v0.43.0`; the release builder continues to reject stale notices. Release builds and bootstrap verification passed with a disposable test signing key. Nothing was published or installed on production.

Test distinctions preserved by the remediation:

- A conclusive pre-effect HTTP 400 is a per-entry failure. HTTP 500 is transport uncertainty and can stop admission for the cycle; it is not a safe signal to keep writing unrelated entries.
- A sealed original can recover after its source disappears. Recovery must preserve its original identity and bytes, and must not recreate the local source.
- Recovering retained originals requires zero source reads. A subsequent ordinary source scan may read unchanged files to prove the current state; those reads must be accounted for separately.

Run focused native checks with the pinned toolchain, for example:

```sh
go test -race -count=1 -timeout=30m ./internal/pluto ./internal/pluto/syncstate -run '^(TestCopyEnumerationOverlappingFailureCanRetryAndUnreadableParentDoesNotHideDirectSource|TestHTTPCurrentScanMissingHistoricalSourceRetainsOriginal|TestSmallBatchEngineDisabledModeRetiresAggregateAndRecoversIndividually)$'
```

Prepare native helpers, evidence directories and shared Saturn codec fixtures when selected tests require them. Privileged mount/disk fixtures belong in an explicitly owned Linux container. Set a sufficient package timeout for a selected race-enabled resource test; a default package timeout is not a product throughput measurement. Do not silently count skipped native/live tests as acceptance.

Parent-workspace receipts: `.audit/2026-10-16/pre-release-remediation/REPORT.md`; original audit and mixed-version evidence: `.audit/2026-10-16/pre-release-snapshot/REPORT.md` and `compatibility/REPORT.md`.

**Production qualification remains open.** Existing qualification scripts pin Kernel 0.3.11 / Saturn 0.2.10, while this local candidate audit used Kernel 0.3.12 / Saturn 0.2.13. Pins were not raised implicitly. A new release must bind its exact source, package signatures, helper/image digests, compatible dependency matrix and systemd install/update/rollback evidence. A disposable signature does not establish production trust.

## 2026-10-20 RC01 local acceptance

RC01 lane C used an immutable coordinator source archive plus the R10-C-NOOP-001 client repair, and independently built the approved two-file Saturn A-C02 patch. The tested Linux amd64 client binary SHA-256 is `bdd94d4908d890f716fc74aa5667720c4a74a692ebe9be61e6af1875d58cb1d3`. C05 and the C07 test extension have identical production source files and native binary bytes. These are local candidate checks; C's Saturn build is separately identified and is not claimed to be bitwise identical to another lane's build.

The ordinary indexed daemon passed initial 512 files, 128 additions, 128 replacements, 30 individual changes, and five NOOP cycles before and after an OS process restart. Full physical SHA-256, resource/version identities and original/receipt equality were checked. The 256 MiB + 1 byte stream also passed ten NOOP cycles with zero payload and stable originals. Each of those cycles still read and hashed the complete source file.

An actual 2 GiB file passed full source/catalog/physical SHA-256 verification after the first 4 MiB acknowledgement response was lost and the daemon was killed and restarted. The server retained 512 distinct acknowledged parts and received 512 chunk requests. An actual 2 GiB + 1 byte source was safely refused with no content original, data payload or file version. A separate post-publication lost-response case preserved the original publication after restart; changing the source after seal produced a distinct second version of the same resource.

Real isolated Kernel and normal Saturn API/worker processes supported native discovery, owner-created enrollment, single-use code redemption, a Saturn 503 outage and automatic copying after connectivity returned, token refresh and revoke. The Volt reference HTTP service was a declared fixture. Saturn revoke exposed `SERVER_AUTH_REQUIRED`, preserved the local credential and stopped further copying; stored bytes remained readable. Repository discovery was checked; signed update installation was not qualified.

Eight actual Linux PTY checks covered source addition/cancellation/removal, interval validation, terminal attribute restoration and settings retained by a new daemon process. This does not establish complete UI progress/elapsed/ETA coverage or systemd qualification. A separate acceptance-only store probe reached native ENOSPC inside a private 64 MiB tmpfs while touching 64 MiB of memory under a 384 MiB container bound; it preserved the committed descriptor, reopened it and accepted a new transaction after pressure relief.

The parent workspace records raw results under `.audit/release-acceptance-2026-10-20/rc01/lanes/c`, including `PATCHSET_C.json`, `c05-c07-equivalence.json`, `F13-P-RESULT.json`, the per-attempt source/build/process receipts and the PTY transcript. F16's additional complete hash binding was recorded after execution; it is explicitly not a contemporaneous launch receipt. Failed attempts and fixture corrections remain preserved.

Systemd PID 1 could not create its private `/init.scope` because the approved container exposed read-only cgroups. No host cgroup, WSL, Docker engine or privilege changes were made. Real production provider scope, actual installed identities, published old/new compatibility, trusted signed native upgrade/rollback, the shared clean T09 tuple, performance/endurance and the final joint run remain open. These results do not qualify a production release or change deployment pins.

The subsequent R10-C-UI-002 repair changes only `internal/pluto/tui.go` among production Go files relative to the C05 sync candidate. Its immutable C11 Linux binary SHA-256 is `0f22bac14d93b69e5833fc3d63cda7a2c69f0f659bcd21b447a736b93e578491`. Idle status reads now refresh the native main menu without another input reader or ticker goroutine. A transient status failure marks last-known values, preserves selection and recovers on the next successful read; explicit cancellation still ends the UI. Eight addressed TUI tests with the race detector and two transient-failure subtests passed. Actual native PTY checks covered a 503, a headers/body stall, recovery without control POSTs, Exit and SIGINT with exact terminal restoration. The same retained profile/backend also passed Copy now as a **NOOP** with zero data payload, full physical readback and `Running: false` shown without keyboard input. Online enable, Saturn outage/reconnect and pause were checked on C10; its pause completed in 0.56 seconds. C05 large/sync receipts remain bound to C05 and were not relabeled as C11 results. Elapsed/ETA was still a product gap at that checkpoint; the following candidate addresses it.

### Progress and elapsed follow-up

C14 adds local status/TUI progress, process-monotonic elapsed and conservative ETA semantics. Its immutable Linux binary SHA-256 is `0fc50dd8ee09c6ac7dc74da23df6192ea2e0928f53101b68e49f26b2f142660c`. This change also touches the service lifecycle and passive existing copy/HTTP counter hookups; the earlier C11 UI-only scope does not apply to C14. No durable schema, publication/receipt rules, transport policy or source scan was added.

Addressed RED/GREEN records cover missing telemetry, a misleading stall diagnosis from request counters and missing confirmed indexed counts. Twelve selected tests with the race detector and two transient-IPC subtests passed, including known/unknown totals, zero rate, growth, a numeric estimate while actual legacy workers finish, waiting/recovery, pause, completion/NOOP, a new run/process and cancellation. A native daemon/PTY case uses an actual 16 MiB payload and an eight-second outage through an owned proxy. Its retained continuation preserves the original file and adds a second 16 MiB file in the same profile/backend, for a 32 MiB source corpus and one version per file. Full physical SHA-256 and immutable original identity are checked. It verifies elapsed over network waiting and UI reattach, frozen paused time, a new manual NOOP run, and no inherited clock after OS restart. Launch tuples bind source, binary, config and backend hashes before execution. A separate native IPC probe covers a 503, a body stall, recovery, unchanged selection, zero control POSTs, Exit/SIGINT and terminal restoration. Old C11 TUI status parsing and the unchanged strict Saturn check-in are checked separately. The first C14 payload attempt has a preserved final fixture FAIL: the textual assertion expected “waiting for progress” instead of the actual “waiting progress” label. Its corrected continuation uses the same retained profile, source and backend.

These are local component results. Prior F05/F06/F13 receipts remain bound to C05; no green large series was repeated or relabeled. The shared clean T09 candidate, full published-version matrix, real provider and native systemd/signed-update targets remain open.
