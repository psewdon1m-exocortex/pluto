# Part 06. Unified Acceptance Checklist

> This is a normative component of the [Part 00 documentation authority](./PART_00_SYSTEM_UNIFICATION_SPECIFICATION.md).

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
normative. Numeric defaults may change only after workload measurement, while
the safety property behind every limit MUST be preserved.

## Central Authority And Material Divergence

This Part takes precedence over conflicting project-local documentation.
Project documents MUST adapt these rules to current project-specific values
without weakening them. A material implementation difference follows the
reporting and decision protocol in [Part 00](./PART_00_SYSTEM_UNIFICATION_SPECIFICATION.md#1-mandatory-material-divergence-protocol); stale local documentation is corrected and is not an alternative authority.

---
## 35. Interface

- [ ] The five-hue palette uses black, white, configured accent, `#62FF8C`
      success and `#F83D3D` danger; hover fill is exactly `#111111`.
- [ ] Only accent is configurable; valid preview is immediate, persistence
      requires Apply, and Reset restores `#00A8FF` through the same step.
- [ ] Outline hierarchy has exactly two levels: 100%-white top-level and
      80%-white nested, with no deeper opacity reduction.
- [ ] Space Grotesk Regular/Bold is limited to service/page display names;
      Consolas Regular/Bold covers all other UI roles.
- [ ] Rest, Hover 1, Hover 2/focus, pressed, disabled and pending states match
      the linked templates and preserve layout geometry.
- [ ] Hover growth adds one short-side-derived absolute delta to both axes;
      canonical press feedback uses `scale(.985)` for about `60ms`; reduced-motion
      preserves non-motion state indicators.
- [ ] Login contains one empty Access Key field and no login/username field;
      reachability is independent, textual and uses green two-second fade or
      static red failure as specified.
- [ ] Every Access Key path treats an explicitly supplied key as opaque exact
      text: no service-specific minimum/maximum length, composition, character
      set, URL-safe/ASCII, entropy/strength or breached/example/placeholder
      policy, and no trimming, normalization, case folding or truncation. Only
      an absent/unconfigured value is rejected.
- [ ] Automated parity tests cover at least a one-character key, a key with
      leading/trailing spaces, and a key containing whitespace, Unicode and
      non-URL-safe punctuation across bootstrap/import, login, rotation,
      backup/restore and offline unlock wherever those paths apply. The exact
      same value succeeds; a different value and missing configuration fail.
- [ ] Every secret, token and verification input is empty on first open/reset;
      no default, example or previously submitted credential is present in
      markup, initialization, URL, browser persistence or a read API.
- [ ] The desktop sidebar is `250px`, active and hover states match the template,
      Documentation/Logout remain unboxed and non-draggable, and reordered
      primary tabs persist with adaptively recomputed ordinals.
- [ ] Closing the sidebar expands and reflows main content in logical order with
      no overlap, stale gap or horizontal overflow; narrow screens use an
      explicit overlay menu.
- [ ] Universal `1x`, `2x` and `4x` cards have the specified ordinal, optional
      title/header, four-dot handle, nested outline and responsive spans.
- [ ] Two-dimensional card dragging previews the exact future grid, persists
      order, recomputes ordinals and has a keyboard equivalent.
- [ ] Every dashboard includes CPU, RAM, Disk and Uptime in that logical order;
      unknown or stale telemetry is not rendered as zero.
- [ ] Dashboard Disk Usage is sampled from the filesystem containing the
      service's authoritative data and uses POSIX `f_bavail`, not `f_bfree`, to
      derive service-available bytes and displayed occupancy. Reserved blocks
      unavailable to the service count as occupied/unavailable.
- [ ] Dashboard Uptime is derived from the monotonic lifetime of the current
      operator-facing service/API process, resets when that instance restarts
      and is proven not to expose host, proxy, database or Updater uptime.
- [ ] Every service Settings view includes Appearance, Security, Backup, Updates
      and Logs, uses immediate committed-control persistence except accent, and
      has no page-level Save button.
- [ ] Access Key rotation, control-plane token rotation, restore and update discovery
      use the specified custom overlays; the native file picker remains native.
- [ ] Context menus use the approved inverted palette, viewport clamping and
      complete pointer/keyboard dismissal and activation behavior.
- [ ] Every editable search field shows an accessible cross/clear control at
      its padded inline end for a non-empty query; activation clears the full
      query, refreshes results, retains input focus and causes no overlap,
      resize or duplicate native cancel icon.
- [ ] The canonical collection search is a square-cornered `40px`-minimum
      three-track unit (`18px` icon / flexible input / `32px` clear action),
      with `12px` inline insets and gaps, `14px` Consolas input text, black fill,
      80%-white resting border/icon/placeholder and white query text.
- [ ] Search focus-within changes the outer border to accent without drawing a
      second input outline; hover/focus growth is composited for `160ms`, clear
      hover/focus uses accent over `#111111`, and reduced motion preserves all
      non-motion state cues.
- [ ] Bounded collection search updates on every edit using trimmed,
      locale-stable case-insensitive substring matching across title, grouping
      labels and field keys plus non-secret values only; active scope composes
      with AND, and empty/Escape/clear restores the current scope and canonical
      order without an audit event.
- [ ] Overlays center on every open, remain within the viewport, trap and restore
      focus and do not discard credential or restore state accidentally.
- [ ] Mutations show pending and final notices.
- [ ] Search, collection metrics and page-level actions share one sticky command
      bar above the list and remain visible during list scrolling.
- [ ] The canonical collection bar is at least `60px` high with `10px 30px`
      padding, `12px` grid gaps and a `minmax(240px, 1fr)` search track; it
      reflows to two columns at `1000px` and one column with `8px 16px` padding
      at `720px` without changing the search component's internal measurements.
- [ ] Filtered lists preserve clear result counts and disable ambiguous reorder.
- [ ] Documentation is a viewport-bounded workspace below the shared header;
      its outer grid, page body and browser document do not become scroll owners
      when the guide or its navigation exceeds the available height.
- [ ] Documentation has exactly two independent vertical scroll regions: the
      complete search/navigation column and the complete article surface. Both
      hide the visual scrollbar while preserving wheel, trackpad, touch and
      keyboard scrolling, visible focus and accessible names.
- [ ] Scrolling either Documentation region changes only that region's offset;
      search and section destinations remain stationary while the article moves,
      article content remains stationary while navigation moves, and boundary
      gestures do not chain to the page or the other region.
- [ ] Documentation destination activation scrolls only the article owner with
      the prescribed reading offset; filtering/clear handles article scroll
      state and no-result output coherently; responsive stacking preserves the
      same two-owner contract with no horizontal page overflow.
- [ ] A visual-only node canvas exposes no execution path and loads only
      allow-listed node definitions.
- [ ] Every supported node can enter and leave a Container without losing its
      recognizable visual representation, functional controls, actions, state
      or assets; full and contained text nodes preserve proportional editable
      width.
- [ ] A browser-document node validates content and size on client and server,
      persists the original bytes or a durable checksummed reference, and
      survives reload.
- [ ] Document Open delegates to the browser or an existing graph editor;
      Download preserves bytes, object URLs are short-lived, and forged MIME
      metadata cannot create executable content.
- [ ] A dependency graph derives edges from authoritative records, validates
      every setting and provides a non-canvas accessible representation.
- [ ] Graph animation and redraw stop when hidden or disabled, and measured
      limits protect frame time.
- [ ] Visual checks cover every linked PNG plus `1919x1034` and `1920x1080` with
      sidebar open/hidden; screenshots contain no overlap or clipped focus.
- [ ] Every mutation that affects protected state writes an audit event.
- [ ] Settings matches the applicable Logs, Backup, Updates, Gryphon
      Connection and Wyverne Connection state examples in Part 01 section 10.5,
      including typography, measured spacing, borders and controls. The newer
      Wyverne gallery is the target for a separate card rollout; existing
      Laboratory and Mastermind card visuals remain unchanged until then.
      Written corrections to illustrative labels/data take precedence.
- [ ] Every applicable interface and embedded guide uses the canonical
      Gryphon Connection title. Unused integrations have no dummy ready card.
- [ ] Neptune Initialize actions use Part 01 section 10.9's common overlay
      family. Gryphon and Wyvern card controls direct the operator to
      `sudo updater tui` and make no lifecycle request. All necessary
      controls remain usable on narrow screens, at 200% zoom and by keyboard.
- [ ] Applicable application and consumed-component update dialogs match all six embedded
      Part 01 section 10.8 examples: measured dimensions, font roles, colors,
      spacing, close/warning controls, responsive layout and required progress.
- [ ] Reference-image names/versions are replaced by actual scoped data;
      historical server-backup text and unsafe enabled actions are corrected,
      and an approved alternative theme preserves the same workflow.

## 36. Logging

- [ ] Database audit is bounded by count, age and bytes.
- [ ] Every file and complete log directory have byte and age budgets.
- [ ] Container and host journals have rotation/retention, not only rate limits.
- [ ] Log writes and tail reads do not load complete files on the main thread.
- [ ] Redaction is recursive and central.
- [ ] Web queries are paginated and hard-capped.
- [ ] Settings receives a bounded ordered real-time stream, resumes by cursor
      after disconnect/visibility changes and never accumulates an unbounded DOM.
- [ ] ZIP generation streams or spools within RAM and temporary-disk budgets.
- [ ] Archive contains manifest, events, README and detailed `errors.json`.
- [ ] Export is authorized, audited and sent with no-store headers.
- [ ] The revision-logging checkbox persists the future routine-event recording
      preference rather than filtering already stored rows. Mandatory errors,
      security and mutation events remain recorded; rejected saves revert.
- [ ] Live entries and older pages remain newest-first, deduplicated and
      bounded; pagination preserves the reading position and handles pending,
      empty, end-of-history and retry states independently of export.

## 37. Backup And Restore

- [ ] Backup scope and replace/merge semantics are explicit.
- [ ] Required authoritative state and recovery metadata are present.
- [ ] Plaintext secrets, `.env`, caches and reproducible binaries are absent.
- [ ] Every archive member has a digest, size and record count.
- [ ] Compressed, uncompressed, per-member, count and ratio limits are enforced.
- [ ] All validation completes before live mutation.
- [ ] Restore is transactional or has an equally strong rollback boundary.
- [ ] One Settings action creates and downloads a fresh ZIP; restore uses the
      custom overlay around the native picker and validates before mutation.
- [ ] External decryption-key recovery is documented and tested.
- [ ] A real round-trip and a failed-restore rollback test pass.
- [ ] Each service's Backup card owns manual ZIP download/restore, Neptune
      initialization and its own automatic enabled/interval policy. It has no
      manual remote-run control; service-facing APIs reject new manual runs.
      The central panel exposes observation and authorized fleet/identity
      administration, with no second schedule editor or backup-run action.
- [ ] Encrypted-store initialization proves both independent workers: recovery
      ZIP and its single-file portable-vault mirror. Partial configuration is not success
      and exposes the repair workflow.

### 37.1 Service-Owned Schedule Acceptance

Use [Part 09 section 5](./PART_09_SERVICE_AGENTS_DEPLOYMENT_AND_LIFECYCLE.md#5-ongoing-neptune-interaction)
and [Part 10 section 2](./PART_10_SERVICE_AGENTS_UI_AND_OPERATOR_WORKFLOWS.md#2-backup-and-neptune-panel).
Record behavior for every declared archive, mirror or folder pipeline.

- [ ] Owner/deployment/pipeline identity is derived server-side; cross-service
      policy reads/writes and runs are denied. Typed authenticated actions use
      expected revision and stable operation/request IDs.
- [ ] New profiles default to disabled/24 hours. Existing values are preserved.
      Invalid hours, integer overflow and overlapping Enter/blur submissions
      cannot produce an unintended policy change.
- [ ] Draft, saving, persisted/pending and agent-applied are distinct.
      A stale revision is rejected; multiple tabs converge without lost edits.
      Failed persistence does not claim a durable browser-local queue.
- [ ] Enabling/changing interval calculates the next due without an implicit
      run. Disable prevents new scheduled runs while an accepted transfer
      reaches its safe terminal/retry state.
- [ ] `POST .../policy/runs` and legacy manual-run entry points cannot create
      new service backup commands. Previously accepted commands may finish and
      remain visible in read-only history; an old browser retry hint cannot
      replay one after an upgrade.
- [ ] Browser closure, application/agent restart and control-plane outage
      preserve the applied schedule and resumable transfer. Test bounded
      overdue recovery without a catch-up storm and display timezone correctly.
- [ ] All required pipelines have separate status and correct remote receipts.
      Volt and Mastermind expose one enabled switch and one hourly interval;
      `schedule-all` changes archive and mirror policy atomically under one
      expected revision and request ID. Imported differences remain intact
      until an explicit edit. Export, upload and committed success are different
      states; a healthy archive worker cannot hide a failed required mirror.
- [ ] A real logical backup/restore retains enabled state, interval, safe
      destination/profile intent and recording/UI preferences. Missing policy
      data fails export rather than silently omitting settings.
- [ ] Restored enabled intent remains visible while execution awaits owner,
      enrollment, destination and applied-policy verification. Old queued
      commands and cloned owner identities do not cause duplicate remote work.
- [ ] Migration preserves policy revisions, due times and active runs; central
      schedule writes are fenced before the owning service becomes the sole
      authoring workflow. Delayed old commands and duplicate manual requests
      are rejected/deduplicated. Rollback also preserves one writer.

## 38. Deployment

- [ ] Server, base OS, network and host access are operator-prepared before the
      service procedure starts; bootstrap does not claim ownership of them.
- [ ] One bootstrap command prepares verified, root-owned files.
- [ ] The bootstrap URL names an exact versioned release asset, not `main`, a
      mutable branch or an unpinned `latest` endpoint.
- [ ] Every deployable component has its own versioned `bootstrap.sh` and
      namespaced configuration; any required mode-`0600` `.env` is not shared.
- [ ] Protected GitHub Secrets retain each private release-signing key; tag CI
      signs with it and exports only the derived public part.
- [ ] Bootstrap embeds and installs the public release key as
      `/etc/exocortex/release-trust/<service>.pem` and creates any additional
      compatibility trust path declared by that service's technical contract.
- [ ] No `scp`, release-key fingerprint prompt or manually prepared public key
      is required; manifest signature verification precedes artifact download
      and configuration generation.
- [ ] Operator edits only the documented `.env` group.
- [ ] Generated secrets and release locks are machine-owned.
- [ ] The documented command order is bootstrap, `sudoedit` of the generated
      service `.env`, `chmod 600`, install, installer status and bounded
      loopback health check.
- [ ] Bootstrap creates the single Access-Key verifier and imports the initial
      control-plane URL seed exactly once; server settings then become authoritative.
- [ ] Initial and rotated control-plane credentials remain in the approved write-only
      secret boundary rather than ordinary settings or frontend state.
- [ ] Safe extraction and exact image digest checks run before start.
- [ ] Compose or system-service configuration validates before mutation.
- [ ] Health checks gate success and diagnostics remain bounded.
- [ ] Existing installations use update/repair, not destructive re-bootstrap.
- [ ] On a clean Linux host, exact-version bootstrap installs Updater alone;
      each Neptune/Gryphon/Wyvern bootstrap ensures that same Updater and only
      its own healthy local daemon, without Kernel or another agent.
- [ ] Root TUI works with zero registered heads: Updater check/self-update and
      agent install/check/update each use Updater's own Kernel connection first
      or that component's saved TUI URL when Kernel is unavailable.
- [ ] A reachable invalid/conflicting Kernel source, bad manifest/signature/
      digest or failed health stops without trying another source.
- [ ] All seven application installers synchronously ensure only their
      [declared agents](./PART_13_HOST_DEPENDENCIES_AND_EXTENSION_GUIDE.md#2-current-consumption-matrix),
      wait for local health, and report installed/reused versions. A second
      consumer does not duplicate/downgrade an agent or rotate its secrets.
- [ ] Bottom-up and top-down installations reach the same authorized state:
      unavailable external credentials produce precise pending connection
      states; when present, known values are reused without repeated input.
- [ ] UI agent initialization reaches only a typed local-update operation with the
      requesting head's token; the application has no sudo, Docker socket or
      arbitrary command surface.
- [ ] Each backup-agent project has distinct control, export and destination credentials, and
      another module's setup code/profile is rejected.
- [ ] One server-managed Nginx owns public routing and TLS. Services publish
      loopback upstreams and contain no embedded Nginx or Caddy runtime.
- [ ] Nginx configuration begins only after local health passes; the operator
      runs `nginx -t`, reloads Nginx and verifies canonical public HTTPS from an
      external client. The installer never mutates or reloads Nginx.
- [ ] coturn is absent unless an explicit WebRTC NAT-traversal requirement and
      project-specific security decision make a separate TURN service necessary.

### 38.1 Shared-Agent Initialization Acceptance

Use the [Initialize workflow](./PART_10_SERVICE_AGENTS_UI_AND_OPERATOR_WORKFLOWS.md#8-initialize-overlay-workflow)
for applicable Neptune integrations. Gryphon and Wyvern service cards direct
the operator to the root TUI for host repair and do not submit interactive
host-wide installation. New consuming installers ensure their local agents.

- [ ] Opening Initialize performs read-only preflight. Cancel before submit
      causes no installation, enrollment, binding or schedule change.
- [ ] Confirmed absence, unreachable existing instance, incompatible version
      and missing client enrollment have distinct next actions. A timeout
      never causes a duplicate installation.
- [ ] Test valid, invalid, expired, consumed and wrong-profile enrollment
      input where applicable; verify owner-scope and authorization failures.
      No consumer form collects adapter/provider secrets or a shared admin token.
- [ ] Double submit, concurrent consumers, helper restart and lost acceptance
      response preserve one shared instance and one scoped operation.
      Existing clients and healthy pipelines retain their configuration.
- [ ] Durable Job/State/message and real or indeterminate progress survive
      close, reload and authenticated reconnect. Stale responses are ignored;
      queued/accepted and reachable are not shown as initialization success.
- [ ] Completion refreshes component health and verifies the declared client/
      pipeline profile. Partial install/enrollment and failed verification
      expose safe retry/repair without an implicit uninstall.
- [ ] Initialize does not enable schedules, start backups or bind a function/
      user implicitly. A separately required component update uses the common
      update flow; it is not hidden inside enrollment.
- [ ] Gryphon pairing uses one TUI `/link` challenge for the adapter owner.
      Service function selection applies that verified account automatically;
      revoke/unlink has service scope. No unpaired adapter is offered as ready.
- [ ] LLM client enrollment, allowed Adapter selection and function readiness
      are distinct. Failed probes preserve binding; stale changes cannot
      overwrite newer configuration or alter another client's Adapter.
- [ ] Sensitive input starts empty and is cleared after use/dismissal; URLs,
      browser persistence, logs, analytics and job receipts contain no secrets.
- [ ] Keyboard focus, inline validation, accessible names, multiline failures,
      reconnect, partial repair and terminal Done/Close match the common overlay.

## 39. CI, Release And Update

- [ ] Every independently versioned service starts at `0.0.1`; `0.0.0` remains
      unreleased state and subsequent versions follow `MAJOR.MINOR.PATCH`.
- [ ] A plain `v0.0.1`-style tag starts verification-only CI and cannot receive
      signing secrets, publish a release or upload production artifacts.
- [ ] Only the exact current `service-v0.0.1`-style tag starts that service's
      release pipeline, which reuses the complete CI and pre-push gate before
      publication.
- [ ] Default-branch and pull-request pipelines give feedback without publication.
- [ ] Tests, builds and smoke checks finish before publication.
- [ ] The exact candidate passes the Part 12 known-problem gate: catalog
      structure and ID uniqueness are valid, every active problem ID appears
      exactly once as evidence-backed `PASS` or reasoned `N/A`, and
      `known-problems-report.json` matches the full service revision, qualified
      tag, immutable central-documentation revision and catalog SHA-256.
- [ ] Missing/stale known-problem evidence, `FAIL`, `UNKNOWN`, an omitted or
      duplicate ID and an unsupported `N/A` block the next privileged stage:
      pre-signing failures prevent access to signing secrets, and final
      signature/trust/provenance failures prevent publication. Production-only
      checks remain visibly blocked in deployment readiness rather than
      receiving a fabricated pass.
- [ ] Cross-repository dependencies are version- and checksum-pinned.
- [ ] The manifest binds role, version, artifact digest and compatibility.
- [ ] The updater independently resolves artifacts and cannot receive arbitrary
      URLs, images or commands from the web application.
- [ ] Browser update discovery occurs in an overlay and cannot initiate installation;
      Apply appears only after a newer release passes provenance and
      compatibility checks.
- [ ] Before application mutation, the exact standard full ZIP is saved on the
      operator's computer and its scoped receipt/checksum are verified; typed
      shared-component updates omit only this application-backup gate.
- [ ] Pull precedes atomic image/version replacement.
- [ ] Health failure triggers tested rollback.
- [ ] Job metadata is count- and age-bounded. No update backup ZIP or copied
      secret-bearing environment is retained on an application/helper host;
      temporary memory/tmpfs is cleaned on every terminal path.
- [ ] Interrupted jobs have an explicit startup reconciliation policy.
- [ ] Local update-helper self-update retains the old binary until new health succeeds.
- [ ] Update-helper restart preserves the socket runtime directory; stale bind mounts
      are detected and only affected running service containers are recreated.
- [ ] Shared-agent initialization and component updates are polled to a
      terminal persisted job and refreshed health; HTTP acceptance alone never
      produces a success message.
- [ ] Portable clients verify a signed manifest from a prior trust anchor and
      checksum artifact bytes after download.
- [ ] Security documentation distinguishes implemented guarantees from trust
      assumptions and known gaps.

### 39.1 Universal Update Workflow Acceptance

This matrix applies to every current/future application and the root TUI for
shared host components. Updater, Neptune, Gryphon and Wyvern use the root TUI
for discovery and installation; their service Settings cards have no update
operation. Use the authoritative
[visual ledger and embedded examples](./PART_01_INTERFACE_AND_INTERACTION_UNIFICATION.md#108-update-dialog-templates),
[backup lifetime](./PART_03_BACKUP_AND_RECOVERY.md#132-backup-lifetime-during-an-application-update)
and [behavior contract](./PART_05_CI_RELEASES_AND_LOCAL_UPDATES.md#34-operator-update-ui).
A checked item requires recorded evidence; these requirements are not claims
that an arbitrary existing implementation has passed.

- [ ] On a browser update surface, opening `Check for updates` opens the overlay
      immediately and sends one discovery request. `Check again` sends a fresh
      request; repeated clicks and stale/out-of-order responses do not duplicate
      work or change target. The root TUI performs equivalent checks for all
      four shared host components without selecting a service.
- [ ] Test no newer version, a valid newer version, incompatible version,
      unknown installed version, offline source, unauthorized request, bad
      provenance, unavailable helper and unsupported protocol independently.
      Only a successful no-candidate result displays up-to-date.
- [ ] Numeric semantic-version ordering, qualified namespace/channel filtering
      and exact-target binding reject draft/prerelease, downgrade, wrong
      component and same-version replacement. The helper independently verifies
      the signed manifest and actual artifact bytes before mutation.
- [ ] Shared-component Settings controls and service-token update routes cannot
      start Updater, Neptune, Gryphon or Wyvern check/install. Status groups
      direct the operator to the root TUI. Application and component versions
      remain distinct; unused components receive no fabricated ready card.
- [ ] Application Install opens the mandatory full-ZIP warning. Cancel/Close
      before submission leaves the running application unchanged. The combined
      action creates and downloads the backup before starting installation.
- [ ] Native save success, picker cancellation, denied permission, write
      failure and ordinary-download fallback are exercised. Fallback starts
      installation from the same action without claiming the ZIP is saved.
- [ ] The combined `Create backup and install` action continues after native
      write/close or ordinary download initiation, without another confirmation.
      Filename, size, selected target and recovery consequences remain visible
      without exposing archive contents; cancelled preparation cannot submit.
- [ ] Wrong ZIP bytes, wrong target/profile, expired/malformed receipt,
      oversized body and archive-expansion abuse
      fail before mutation. The accepted ZIP equals the saved operator bytes;
      automatic backup alone and a newly generated second snapshot cannot pass.
- [ ] Receipt/ZIP data never enter persistent browser storage, cache, URLs or
      logs. Transfers require authentication and no-store responses. All
      temporary memory/tmpfs is bounded and cleaned; unavailable tmpfs cannot
      trigger a persistent-disk fallback.
- [ ] A request ID is retained before submission. Repeated same-scope requests
      resolve to one job; changed payload/scope is rejected. Two tabs and two
      applications cannot bypass the host mutation lock.
- [ ] A response containing a job ID is pending, not success. The progress
      panel displays the correct job ID, target, machine state and sanitized
      message from the server throughout apply and recovery.
- [ ] Determinate progress has a valid measured total/unit; unknown totals use
      an indeterminate track. No timer or state ordinal manufactures a percent.
      Terminal `complete`/`1/1` on a failed job is never styled as success.
- [ ] Closing/reopening, browser reload, lost submission response, session
      expiry, container replacement, helper self-restart and offline recovery
      preserve job identity and resume authenticated observation without an
      automatic new mutation. Stale status and reconnecting are visible.
- [ ] Verify a real signed upgrade and a forced post-mutation failure/rollback
      from every declared supported previous-release baseline on the target
      Linux/system-service/container environment. Compare authoritative data,
      environment values, bindings and actual running versions.
- [ ] `COMPLETED` requires matching running version/digest and health.
      Installed metadata refreshes and fresh discovery runs afterwards.
      A no-update result hides Install; a new candidate uses a new gate.
      Recheck failure does not relabel a completed job as failed.
- [ ] Rejection, `FAILED`, `ROLLING_BACK`, `ROLLED_BACK` and
      `ROLLBACK_FAILED` have distinct persistent presentations and safe next
      actions. Preserve both installation and recovery errors where relevant.
- [ ] Rollback appears only for an authorized supported job and cannot race
      active apply. Its confirmation identifies the restored version and
      snapshot data-loss boundary. Correct saved ZIP succeeds; wrong ZIP fails
      before restore; successful rollback reports the verified previous version.
- [ ] Normal reboot preserves installed services and data. Interrupted-update
      reconciliation exposes an actionable outcome; recovery after volatile
      backup loss requests the original operator copy instead of pretending to
      resume with an unavailable archive.
- [ ] Shared-component updates in the root TUI retain explicit target/impact
      confirmation, progress, reconnect and terminal checks without an
      application backup. Configuration, tokens and registrations survive; a
      shared instance is not duplicated or re-enrolled per consumer.
- [ ] Remote component acceptance/waiting/check-in is not completion. The
      operation ends only after the selected running version and health are
      reported by the target, with offline state visible.
- [ ] All six PNG compositions and additional checking/save/error/recovery
      states pass the desktop, narrow, short-height, zoom, keyboard, native
      picker, reduced-motion and approved-theme checks in Part 01 section
      10.8.10. Explicit historical deltas are documented, not silently copied.
- [ ] Operator documentation distinguishes the ordinary browser workflow from
      a first-transition compatibility bridge. Bridge instructions name the
      execution side/shell, exact source/target, binary-safe ZIP transport,
      legacy retention cleanup and job verification. No manual private-key
      transfer, weakened SSH access or destructive re-bootstrap is required.

## 40. Security And External Connections

- [ ] Untrusted CI jobs receive no production secrets, signing keys, deploy
      permission or general-purpose write token.
- [ ] Release, publication and deployment use separate least-privilege
      identities and immutable artifact references.
- [ ] Final archives and image layers pass secret and high-risk-file scanning.
- [ ] Deployment injects runtime secrets without printing substituted
      configuration or packaging secrets into artifacts.
- [ ] The messaging gateway alone stores adapter tokens and owns provider webhooks;
      consuming services receive only service-scoped credentials and expose authenticated
      command adapters.
- [ ] Gryphon adapter registration and one-time `/link` pairing work through the
      root TUI; service Settings lists only paired adapters and grants the paired
      account on selection, without requesting another code. Unlink/revoke
      affects only the selected service scope.
- [ ] Interactive Gryphon and Wyvern release check/update are available
      without service selection in the root TUI; browser-initiated host-wide
      lifecycle/update requests are denied. A privileged consuming installer
      has only the separate, allow-listed initial dependency-ensure operation.
- [ ] Wyvern enrollment accepts only Updater's instance/host-scoped machine
      right. Operator cookie/Access Key, an unscoped legacy service token and
      another instance's credential fail; retry does not rotate existing
      `manager/runtime` identities or create duplicate client links.
- [ ] Access Key change requires current proof, two exactly matching explicitly
      supplied replacement entries and revokes other sessions; it applies no
      password-strength or value-shape policy. Control-plane token rotation is
      write-only, validated before atomic activation and never exposed in UI,
      logs or backup.
- [ ] Every listener and route has an explicit public, non-indexable, private or
      concealed exposure mode.
- [ ] Browser operator login uses `public authenticated`: it is reachable from
      every client IP, no `OPERATOR_CIDR`/VPN/IP allow-list gates sign-in, and
      Access Key plus application sessions protect all operator data.
- [ ] Private/concealed reachability is tested from an unauthorized external
      vantage point.
- [ ] Bot, crawler and automation decisions derive from one versioned policy;
      `robots.txt`, `noindex` and User-Agent strings are not treated as access
      control.
- [ ] Known bots are verified at the trusted edge and client-supplied
      verification headers are discarded.
- [ ] Unknown automation is observed, rate-limited, challenged and blocked by
      measured policy; prompt injection and data poisoning are never defenses.
- [ ] When a Telegram connection is in scope, adapter credential validation
      and owner pairing are separate; the TUI link code is short-lived,
      single-use and consumed transactionally.
- [ ] Every Telegram command and callback is authorized by stable identity;
      unlinking and rotation revoke access and are audited.

## 41. Definition Of Done

### 41.1 Mandatory Pre-Push Integrity And Documentation Gate

Every branch or tag push MUST complete this section against the complete
outgoing diff. All seven areas below are reviewed on every push. Security is
always applicable and must produce `PASS`; the other areas may use `N/A` only
with evidence. A failed or unknown item, unchecked area, stale documentation,
missing exposure classification or unexplained `N/A` blocks the push.

Public SEO/GEO and private/concealed exposure use `N/A` only when their entire
profile is absent from the classified system. Once a conditional profile is
active, every push records a proportionate `PASS`, including for a reviewed
no-impact diff.

- [ ] The exact outgoing revision and range were recorded, and all changed
      deployable units, persisted-state owners and operator-facing surfaces were
      identified.
- [ ] **Backup and restore:** every added, renamed, transformed or removed
      persisted value was classified as mandatory, conditional, derived or
      forbidden; export, manifest, import, defaults/migrations and archive
      compatibility were updated; affected coverage passed a real backup to
      clean-instance restore comparison and failure/rollback exercise.
- [ ] **Service update:** changes to runtime, dependencies, artifacts,
      manifests, migrations, configuration, service definitions, updater
      handoff, health or rollback passed the Part 05 compatibility audit; an
      affected contract was exercised from the oldest supported source version
      through candidate health and rollback.
- [ ] **Documentation view:** every changed operator-visible workflow, setting,
      action, permission, limit, status, failure, backup/restore or update
      behavior is described accurately; navigation/search metadata and links
      are synchronized; documentation render, broken-link and findability checks
      pass.
- [ ] **Technical documentation and root README:** API, configuration,
      environment, ports, dependencies, security, deployment, migrations,
      recovery, update and development commands were reviewed for every affected
      service; affected service docs were updated, and the root README was
      updated when workspace-wide topology or entry instructions changed.
- [ ] **Security — always applicable:** the complete diff passed secret and
      high-risk-file scanning, dependency/supply-chain policy, security-policy
      lint and the narrowest relevant security tests; changed trust boundaries,
      identities, authorization, routes, listeners, secrets and untrusted-input
      paths have updated exposure/threat evidence and positive/negative tests.
- [ ] **Public SEO/GEO — conditional:** when a public/indexable or
      maximum-discovery surface is in scope, every added, changed or removed page
      type is represented in the registry and SEO release diff; first-response
      HTML, metadata, structured data, canonical/lifecycle, sitemap/discovery,
      internal links, accessibility, performance and UI/UX checks pass without
      exposing a private URL.
- [ ] **Private/concealed exposure — conditional:** when maximum concealment or
      a private/concealed surface is in scope, route/listener and public-artifact
      diffs contain no accidental exposure; an unauthorized external vantage
      cannot reach concealed services or protected content; crawlers, agents and
      forged trusted-bot claims gain no reachability or privilege.
- [ ] Every area is recorded as `PASS` with exact commands/results or `N/A` with
      inspected registries/paths and a concrete no-impact reason. Security cannot
      be `N/A`. Cost, time pressure or an unchanged checkbox without evidence is
      not a valid `N/A`.
- [ ] The project's reproducible pre-push command succeeds. CI repeats the
      machine-verifiable subset and blocks merge, release and publication on
      failure; bypassing a local hook does not waive this gate.
- [ ] Before a service-qualified release, CI completes the full
      [Part 12 known-problem evaluation](./PART_12_KNOWN_DEPLOYMENT_AND_OPERATIONS_PROBLEMS.md),
      retains its revision-bound JSON report and prevents release finalization
      when the report is incomplete or unsuccessful.

Use this minimal record with the change or handoff:

| Area | Status | Evidence or reasoned non-applicability |
| --- | --- | --- |
| Backup and restore | `PASS` / `N/A` | Changed paths, command/result or no-impact reason |
| Service update | `PASS` / `N/A` | Source and candidate versions, command/result or no-impact reason |
| Documentation view | `PASS` / `N/A` | Articles, render/link/search result or no-impact reason |
| Service technical docs and root README | `PASS` / `N/A` | Reviewed/changed documents or no-impact reason |
| Security | `PASS` | Scans, security tests, affected boundaries and results |
| Public SEO/GEO | `PASS` / `N/A` only if profile absent | Page/URL registry diff, control URLs and validation results, or system-wide mode-based reason |
| Private/concealed exposure | `PASS` / `N/A` only if profile absent | Exposure diff and external/internal-vantage results, or system-wide mode-based reason |

The full rules are in the
[orchestrator's Mandatory Pre-Push Change-Impact Gate](./PART_00_SYSTEM_UNIFICATION_SPECIFICATION.md#46-mandatory-pre-push-change-impact-gate),
[Part 03 section 17.1](./PART_03_BACKUP_AND_RECOVERY.md#171-pre-push-backup-scope-audit),
[Part 05 section 25.4](./PART_05_CI_RELEASES_AND_LOCAL_UPDATES.md#254-pre-push-update-compatibility-audit)
and [Part 01 section 5.7](./PART_01_INTERFACE_AND_INTERACTION_UNIFICATION.md#57-documentation-view),
with the additional profiles in
[Part 07 section 50.3](./PART_07_SECURITY_AND_EXPOSURE_CONTROL.md#503-mandatory-pre-push-security-and-exposure-audit)
and [SEO/GEO/MCP section 26.8](<./PART_08_SEO_AND_GEO.md#268-mandatory-pre-push-seogeomcp-impact-audit>).

### 41.2 Unified Completion Conditions

The system is unified only when the same limits and states are visible in four
places:

1. configuration defaults;
2. runtime enforcement;
3. operator UI and documentation;
4. automated tests.

A value displayed but not enforced is not a limit. A backup never restored in
a clean environment is not a recovery mechanism. A checksum without a trusted
source is not publisher authentication. A process that started but failed its
health contract is not a successful deployment.
