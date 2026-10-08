# Part 05. CI, Releases And Local Updates

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
## 24. Responsibility Boundaries

Keep these roles separate:

- CI turns a tagged source revision into immutable release artifacts.
- A protected release-signing job receives only that service's private key from
  GitHub Secrets, signs the release manifest, derives the public counterpart and
  embeds only that public part in the service's release `bootstrap.sh`.
- A control-plane registry distributes repository locations and compatibility
  policy. For Updater and shared host agents, Updater reads it through its own
  host machine connection, with component-specific root TUI fallback only when
  that connection is unavailable.
- The application exposes the operator workflow, creates its standard full
  logical backup and submits a scoped target version, request ID, saved-copy
  receipt and exact archive bytes to the local update helper.
- The privileged updater independently resolves and verifies that version,
  owns the container-engine boundary and mutates only services registered on
  its host.
- A portable client validates a separately signed update contract because it
  runs outside the server-host trust boundary.

The web application MUST NOT receive the container-engine socket. It MUST NOT
send an arbitrary command, image or release URL to the updater.

## 25. CI Trigger And Pipeline Shape

### 25.1 How Release Pipelines Start

Each deployable module has its own repository and release workflow. An embedded
dependency is consumed as a version-pinned, checksummed published asset rather
than from a sibling checkout.

Every independently versioned service uses the numeric
`MAJOR.MINOR.PATCH` model. Its first releasable version is `0.0.1`; `0.0.0` is
reserved for unreleased or development state and MUST NOT be published. Numeric
components contain no leading zero unless the component is exactly `0`.

- `PATCH` increments for compatible fixes and documentation/package corrections;
- `MINOR` increments for compatible functionality or an explicitly documented
  pre-1.0 contract change;
- `MAJOR` increments for an intentionally incompatible stable contract.

Two non-overlapping tag namespaces are mandatory:

| Tag | Example | Required effect |
| --- | --- | --- |
| Plain validation tag | `v0.0.1` | Starts verification-only CI for that revision. It MUST NOT publish a release, receive a release-signing secret, create or move a release alias, or upload production artifacts. |
| Service release tag | `service-v0.0.1` | Starts that service's release pipeline. The service slug is the current lowercase repository/service identifier. Release publication is blocked until the same revision passes the complete CI and pre-push gate. |

A plain tag and a service-qualified tag are never aliases for one another. A
release workflow MUST match only its exact service prefix and MUST reject an
empty, foreign or malformed prefix. The manifest version is derived from the
qualified tag, the published release remains attached to that immutable tag,
and rerunning a workflow MUST NOT reinterpret or move an existing tag.

Ordinary pushes to the default `main` branch and pull requests run CI without
publication. A service release tag may invoke the same reusable CI workflow as
a prerequisite, but only its protected release job receives signing secrets and
publishes artifacts. Manual release publication is outside the baseline unless
an explicit recovery procedure preserves the same immutable tag, approval and
evidence contract.

### 25.2 Fail-Closed Build Chain

1. Check out the tagged revision and select the pinned toolchain major.
2. Derive and validate the version from the tag.
3. Validate shell entry-point syntax.
4. Install dependencies from lock or requirements files.
5. Run tests, compilation and type checking.
6. Fetch cross-repository dependencies at pinned versions and verify their
   SHA-256 files before extraction or embedding.
7. Build a release candidate and run profile-specific smoke tests.
8. Build the final OCI image or package and resolve its immutable digest.
9. Build checksummed installation bundles and the complete narrow release
   manifest.
10. Run the Part 12 pre-signing phase for catalog integrity, applicability and
    every check that does not depend on final signatures. Any unresolved result
    stops before release secrets are exposed.
11. In a protected release-only job, load this service's private signing key
    from GitHub Secrets, sign the canonical manifest and derive its public key.
12. Generate this service's standalone `bootstrap.sh` with the public key
    embedded; verify that no private-key bytes enter the bootstrap, bundle,
    image, cache, log or artifact set.
13. Verify the detached manifest signature and every artifact digest using the
    generated bootstrap/public-key outputs.
14. Generate provenance attestations; request an SBOM and provenance for OCI
    builds.
15. Complete the final [Part 12 known-problem release phase](./PART_12_KNOWN_DEPLOYMENT_AND_OPERATIONS_PROBLEMS.md#обязательный-проверочный-gate-перед-релизом)
    for signature/trust/provenance-dependent checks and retain
    `known-problems-report.json`.
16. Publish all artifacts under the original immutable version tag.

Any failed step prevents publication.

### 25.3 Tests By Module Profile

| Profile | Build and test gates | Published form |
| --- | --- | --- |
| Static host daemon | Shell syntax, all language package tests, static target build with version/build ID | Native package, install archive, manifest and SHA-256 files |
| Web/API head | Deterministic package install, API/security tests, type check, production UI build, browser end-to-end tests, container health smoke test | OCI image by digest, Compose archive, release manifest |
| API head with database | Installer syntax, dependency install, migration-head validation, full integration suite, embedded dependency checks, database/cache/API health smoke tests | OCI image by digest, Compose archive, release manifest |
| Head with separate web UI | Database-backed server suite, frozen UI install, UI unit tests and production build, container health smoke test | OCI image by digest, Compose archive, release manifest |
| Portable desktop client | Third-party runtime version/URL/SHA verification, unit tests, portable build, signed-manifest generation and verification tests | Executable, SHA-256, signed discovery manifest, public key |
| Local updater daemon | All package tests and static target build | Binary, native package, install archive, manifest and SHA-256 files |

Behavioral coverage demonstrated by the reference suites includes:

- configuration round trips, refusal of arbitrary shell jobs, queue
  idempotency, redaction, enrollment, certificate handling, approval forwarding
  and post-execution secret disposal for a host daemon;
- separate per-service registry profiles, safe identifiers, API token checks,
  local-host enforcement, socket collision, backup checksum enforcement,
  request idempotency, atomic image/version persistence, health rollback,
  minimum updater version and download-size limits for the updater;
- production-secret validation, authenticated APIs, revision checksums,
  backup/restore, release discovery, updater handoff, navigation, restore and
  responsive browser flows for web heads;
- password hashing, rate limiting, migrations, last-known-good policy,
  signed-client caching, tamper rejection, identity revocation and bounded logs
  for the larger control plane;
- session security, protected dashboards and formatting/category behavior for
  the scheduling profile;
- canonical JSON, signed heartbeat or identity data, device-bound protected
  storage, navigation policy, checksum staging and release-manifest validation
  for the portable client.

One important boundary remains: a locally built candidate is smoke-tested and
the registry image may then be built again. The pipeline does not necessarily
promote the exact tested image object. Reproducible inputs reduce this risk but
do not prove byte identity. The stronger design builds once, tests that digest
and promotes the same digest.

### 25.4 Pre-Push Update-Compatibility Audit

Before every branch or tag push, inspect the outgoing diff for effects on the
service update path. The audit covers runtime dependencies, images and
packages, release manifests, migrations, configuration/schema versions,
bootstrap and service definitions, updater APIs, backup handoff, health checks,
timeouts, job persistence and rollback. The audit itself is mandatory even
when the result is `N/A`.

An affected push cannot pass until evidence demonstrates, as applicable:

1. release and update manifests still describe the exact candidate artifacts,
   immutable digests, compatibility range and minimum updater version;
2. configuration and data migrations accept every supported source version or
   reject it before mutation with a clear compatibility result;
3. the updater verifies a fresh backup before mutation and any changed state is
   covered by the [Part 03 pre-push backup-scope audit](./PART_03_BACKUP_AND_RECOVERY.md#171-pre-push-backup-scope-audit);
4. installation starts the intended candidate and the declared health contract
   succeeds within its bounded timeout;
5. a failed health or migration path restores the previous runtime/version and,
   when data changed, restores the verified logical backup;
6. the web application still cannot supply arbitrary artifact URLs, images or
   commands to the privileged updater;
7. operator-facing update status, compatibility and recovery instructions are
   synchronized in internal and technical documentation.

Changes to migrations, backup/update contracts, manifest structure, updater
handoff, service definitions or health/rollback behavior require an update from
the oldest supported source version to the outgoing candidate and an exercised
rollback failure path. A `PASS` records exact commands, source/candidate
versions and results. `N/A` names the inspected paths and explains why the diff
cannot affect discovery, packaging, installation, health or rollback.

### 25.5 Known-Problem Regression Gate

Every service-qualified release MUST evaluate every active ID in
[Part 12](./PART_12_KNOWN_DEPLOYMENT_AND_OPERATIONS_PROBLEMS.md) against the
exact tagged revision and candidate artifact set. This gate runs after the
profile-specific build, tests and smoke checks have produced evidence, and
before the protected publication job may finalize the release.

The gate has a pre-signing phase and a final signed-artifact phase. The first
validates the catalog, classification and every check that does not need the
release signature; a failure prevents access to signing secrets. Only checks
whose evidence inherently depends on the final signature, derived public key,
bootstrap or provenance continue in the protected job, and they must pass
before publication.

The pipeline requires exactly one `PASS` or reasoned `N/A` for every active ID
and emits `known-problems-report.json` with
the service, full service revision, qualified tag, immutable central-documentation
revision and SHA-256 of the exact catalog bytes. A missing/stale report,
duplicate or omitted ID, `FAIL`, `UNKNOWN`, or
unsupported `N/A` blocks the next privileged stage. Evidence references
immutable job outputs, reports or exact commands; prose asserting that a
problem is fixed is not evidence.

Default-branch and plain validation-tag CI run catalog lint plus every
machine-verifiable affected check without release permissions. The qualified
tag reuses those results only when they belong to the identical revision and
then completes the full release-scope evaluation. Checks needing real
production inputs remain in deployment readiness; the release may prove the
template, fail-closed validation and operator runbook but MUST NOT report the
external production result as passed.

## 26. Release Artifact Contract

A server release manifest is an installation contract, not release notes.

`known-problems-report.json` is required companion release evidence. It is
bound to the exact service revision, service-qualified tag, immutable central
documentation revision and Part 12 catalog digest, published with the release
evidence/provenance set and retained for at least the supported lifetime of
that version. It is not a bootstrap trust input and never contains secrets or
private production coordinates.

| Generic field | Purpose |
| --- | --- |
| Schema version | Reject a contract the installer cannot understand |
| Component role and version | Bind the manifest to the selected tag and target |
| Image reference and digest | Form the immutable registry pull target |
| Bundle URL and SHA-256 | Bind the installation archive to exact bytes |
| Minimum updater version | Prevent an incompatible privileged update |
| Database schema generation | Declare migration compatibility information |
| Release notes URL | Give operator context without becoming a trust input |

The portable-client manifest additionally contains exact artifact URL,
SHA-256, byte size, channel, semantic version, API compatibility and minimum
controller version. It is signed over canonical JSON with an asymmetric key;
the signature field itself is excluded from the signed payload.

Each service owns a distinct private signing key stored only as a protected
GitHub Secret. It is exposed only to the release signing step, never to pull
request or ordinary branch CI. That step exports only the public counterpart
and embeds it directly in the same service's versioned `bootstrap.sh`; it is not
published as a standalone trust-on-first-use key asset. The private key is never
uploaded, cached, printed, added to an image layer or copied to a deployment
host.

On first installation, the bootstrap writes the embedded verifier to
`/etc/exocortex/release-trust/<service>.pem`. A service-specific technical
contract may declare one additional legacy compatibility path, written from the
same embedded verifier. Bootstrap then verifies the manifest signature before
following release URLs. Distribution does not use `scp`, a separately supplied
fingerprint or manual public-key preparation.

Rotation for an existing host is a signed trust transition: a manifest accepted
by the current key introduces the next public key, both keys overlap for a
bounded release window, and only then may releases require the new key. A new
bootstrap alone MUST NOT overwrite an existing non-matching trust anchor.

## 27. Release Discovery And Data Provenance

The operator's update check is informative. The privileged updater resolves
the release independently and does not trust the UI response.

1. The application authenticates to the control-plane configuration registry.
2. Its local update helper validates registry schema, revision and checksum. Only
   non-secret reference metadata may enter a last-known-good copy.
3. The helper reads the repository location from a namespaced registry entry.
4. The helper queries the hosted release API; the application displays its
   installed/available version result.
5. On application installation, it sends a request ID, local service identity,
   selected version, saved-copy receipt and checksummed backup to the helper.
   A typed shared-component update uses its own authorized scope without an
   application backup.
6. The updater reloads its root-owned local profile and the validated registry
   snapshot, obtains the repository location itself and queries releases again.
7. It selects an exact non-draft, non-prerelease semantic version and binds manifest identity
   to that tag.

A checksummed last-known-good cache detects corruption and permits temporary
offline resolution. A checksum is not a signature; authenticity still depends
on the authenticated registry connection and protected local cache.
This generic application-release cache does not override the host-component
source order below.

For the host-wide Updater, Neptune Linux, Gryphon and Wyvern release paths,
steps 1–6 use Updater's own scoped Kernel connection rather than a selected
application head. If Kernel is unreachable, Updater may use the URL saved by
the root operator in that component's TUI section. A reachable but invalid or
conflicting Register response fails closed; a later signature, manifest,
digest, compatibility or health failure never triggers another source. A
verified exact-version bootstrap/bundle may provide its own first-install
artifact and seed only its own editable fallback URL. No compiled catalog of
all host repositories is required. See
[Part 13](./PART_13_HOST_DEPENDENCIES_AND_EXTENSION_GUIDE.md#3-release-source-trust-and-authorization).

Channel policy MUST be explicit and uniform. Do not emit a manifest channel
that the installer ignores. Stable selection rejects prerelease suffixes at
both discovery and application boundaries.

## 28. Local Update-Helper Trust Boundary

One root-owned update-helper daemon serves a host. Multiple local applications share
its Unix socket but have separate registered profiles and control tokens.
Typed component operations for shared host agents are described in
[Service Agents: Deployment, Initialization And Lifecycle](./PART_09_SERVICE_AGENTS_DEPLOYMENT_AND_LIFECYCLE.md);
they do not widen this trust boundary into arbitrary command execution.

Required controls:

- Unix socket instead of a TCP listener;
- socket mode `0660`, dedicated group and explicit application membership;
- required local Host identity;
- one token per registered service, compared in constant time for mutations;
- exact match between requested service and registered profile;
- a host-wide mutation lock;
- rejection of a second daemon on an active socket;
- bounded bodies, downloads, headers and command durations;
- root-owned registry and job metadata paths with restrictive modes;
- no persistent update backup archive.

Read-only health and job status may rely on socket access. Update and rollback
require both socket access and the matching token.

The daemon needs root to control containers and rewrite root-owned deployment
files. Its system unit still constrains privilege with no-new-privileges,
private temporary storage, protected system/home paths, an explicit write-path
allow-list, restrictive umask and bounded journal rate. This contains
privilege; it does not eliminate it.

The runtime directory containing the Unix socket MUST be preserved across
update-helper restarts. On startup the daemon SHOULD detect a running registered
container whose bind-mounted socket directory no longer matches the host
directory and recreate only that affected service. It MUST leave healthy,
stopped and uncreated services untouched.

## 29. Update State Machine And Apply Algorithm

An application update request is accepted only when a non-empty backup within the defined
limit matches its SHA-256. The implemented privileged boundary uses a 128 MiB
decoded-byte maximum. The head signs a short-lived receipt binding the exact
standard ZIP to its head ID, service, target version, request ID, size and SHA-256.
The browser starts the ZIP download and returns the same bytes without a second
operator action. The update helper verifies the receipt and checksum before mutation.
Only job metadata is persisted; backup bytes remain in memory for the operation.
Reusing the request ID with the same scope returns the existing job.
Reusing it with a different target or payload is rejected, not interpreted as
a second operation. Typed shared-component requests follow the same
authorization, exact-target, idempotency, health and job rules without an
application ZIP or saved-copy receipt.

| State | Meaning |
| --- | --- |
| `REQUESTED` | Scoped request and, for an application, saved backup are accepted; only job metadata is persisted |
| `BACKUP_VERIFIED` | Application backup bytes are available in memory and match the scoped receipt and digest |
| `ARTIFACT_VERIFIED` | Tag, manifest, bundle, image and updater compatibility passed |
| `PULLING` | Exact immutable image is being downloaded |
| `APPLYING` | Version and image lock are written atomically and target is replaced |
| `HEALTH_CHECK` | Loopback and optional public endpoints are polled |
| `COMPLETED` | Target running version/digest and health are verified and the outcome is persisted |
| `FAILED` | Rejection, failure or interruption without a verified recovery outcome; the mutation marker and message determine recovery needs |
| `ROLLING_BACK` | Previous version and optional logical data are being restored |
| `ROLLED_BACK` | Recovery completed and health passed |
| `ROLLBACK_FAILED` | Previous runtime or data could not be restored fully |

The updater applies a release as follows:

1. Resolve the exact release again and download the manifest and bundle over
   HTTPS with size limits.
2. Verify identity, version, bundle SHA-256, immutable image shape and minimum
   updater version.
3. Capture the currently running image and displayed version.
4. Pull the new image by digest before configuration changes.
5. Rewrite image and version together through a restrictive temporary file and
   atomic rename.
6. Replace only the target Compose service without removing persistent volumes
   or unrelated services.
7. Poll loopback health, verify that its reported version equals the selected
   release and, when required, poll public verified HTTPS health.
8. On failure after mutation, stop writers and restore the original data and
   deployment through the service's supported recovery path, then verify the
   old running version. Normally this uses the old authenticated restore endpoint.
   If a signed manifest declares a compatible offline recovery tool, use that
   exact candidate image by digest before restarting the old deployment.

A legacy release that omits a health version may use an explicitly documented,
tested compatibility profile. Only for that bounded profile may the helper
verify the actual running container image and image ID against the pinned
immutable digest. A wrong reported version, mutable tag or stopped container
is never accepted through this path. New releases MUST report their running
application version; exact legacy ranges belong in the application's runbook.

Release resolution, compatibility or pull failure leaves the running service
untouched.

The updater applies allowlisted deployment files from the verified bundle and
preserves operator-owned environment values. Rollback metadata contains Compose
content and names of added environment defaults, never a copied .env with secrets.

## 30. Backup, Rollback And Job Retention

The application uses its standard full ZIP builder for manual, automatic and
pre-update exports. An update MUST use exactly the ZIP downloaded by the operator;
creating a second snapshot during apply is prohibited. With a native save API,
installation waits for the write and close. Otherwise the browser starts the
ordinary ZIP download and continues automatically. Download initiation MUST NOT
be represented as proof of a disk save.

Update archives MUST NOT be retained on the application host. Their durable homes
are the user's computer and the designated remote backup storage through the
shared backup agent's independent automatic pipeline.
Temporary generation files are deleted after transfer and cleaned after interrupted
downloads at startup. The update helper holds rollback bytes only in process memory, clearing
them at termination of the operation. Restore tools needing a path receive a
restricted, verified tmpfs file, removed in a finally/defer cleanup; no /tmp fallback.

After daemon/host restart or later manual rollback the operator uploads the saved
original ZIP. Its SHA-256 MUST match the original job. The UI must explain this
recovery condition. Compose metadata is retained; secret-bearing .env copies and
ZIP content are excluded. Terminal job metadata retention is bounded (20 jobs,
30 days by default). Legacy archive directories are migrated and cleaned at startup;
metadata preserves the original checksum for operator-copy recovery.

Before an upgrade that performs this legacy cleanup, the operator MUST have
saved fresh standard backups on their computer. Its runbook identifies the
cleanup and any historical copies needed for older recovery points. A terminal
job marked `rollback_available` after cleanup is not evidence that the archive
still exists on the host. Recovery uses its recorded digest and the operator's
matching copy. This policy concerns backup material, not installed binaries,
persistent application volumes or required deployment metadata.

An ordinary host reboot preserves installed applications and their persistent
databases/settings. It does not require restoring every service from backups.

### Docker image storage and offline rollback

Updater owns Docker image cleanup on the host. Its root TUI first displays a
bounded preview and requires a separate confirmation. The operator API for this
operation exists only on Updater's private root socket, never on a service
mounted socket. Window may report storage usage but cannot delete images.

The running image and the immediately previous deployment generation remain
local for an offline rollback. Updater persists the previous image references
separately from its bounded job history before changing a deployment. Active and
stopped container images, current registered head references, in-progress and
recovery jobs, and the two newest local images of each eligible registered
repository are also protected. If Updater cannot establish the previous
generation for a repository, it excludes that repository from cleanup. A stale
or changed preview cannot authorize deletion.

Only images in registered Exocortex repositories, older than seven days, may
enter a batch of at most 12. Updater removes exact image IDs without force;
Docker volumes, containers, build cache, logs and images from unregistered
repositories are outside this operation. Docker refusal stops the batch. Older
rollback images may be downloaded by their previously recorded immutable
registry digest. The pull and local image identity must be verified before
stopping the current deployment or restoring data; an unavailable or unverifiable
image leaves the current deployment untouched. Offline rollback of historical
generations beyond the immediately previous one is not promised.
The saved-copy recovery requirement applies to an interrupted update that needs
data rollback, or to an explicit later restore.

A persisted non-terminal job does not automatically resume its goroutine after
restart. Startup reconciliation must expose a terminal interrupted/error state with
an actionable recovery message, or recognize its still-running self-update supervisor.

## 31. Update-Helper Self-Update

Self-update is an explicit privileged command. It works with zero registered
application heads, resolves its own repository through the host source policy
above, selects an exact allowed version,
verifies a bounded manifest and binary SHA-256, and then:

1. copies the current executable to a previous-version path;
2. installs the staged executable atomically;
3. restarts the system service;
4. polls Unix-socket health for a short bounded interval;
5. deletes the previous binary only on success;
6. restores and restarts the previous binary on failure.

Binary self-update does not imply systemd-unit or package replacement. A change
to service hardening, runtime-directory behavior or packaging requires an
explicit signed package/install-repair contract and separate verification.

The selector MUST sort semantic versions and compare with the installed
version. Relying on the first provider API result is not a valid newest-version
algorithm. Every failed restart branch must attempt a restart after restoring
the previous executable.

## 32. Portable Client Update

A portable client receives a discovery URL, trusted public key, desired channel
and minimum allowed version from authenticated policy.

Before replacing itself it:

1. fetches the manifest over HTTPS without cache;
2. verifies schema, product role, required fields, channel, compatibility,
   artifact URL, size, SHA-256 and asymmetric signature over canonical JSON;
3. rejects downgrade and same-version/different-bytes cases;
4. downloads with a size limit and verifies artifact SHA-256 again;
5. stages through a temporary file and atomic rename;
6. launches a detached replacement helper and exits.

The helper preserves the current executable, starts the candidate with a
one-time health marker and waits a bounded interval. If the marker is not
created, it terminates the candidate, restores the previous executable and
starts it.

The controlling service performs the same signature, compatibility, size,
format and digest checks before caching client artifacts by digest. Network
failure or validation failure keeps the last-known-good or factory artifact.

## 33. Supply-Chain Guarantees And Boundaries

### 33.1 Guarantees Demonstrated By The Architecture

- server images install by immutable OCI digest;
- bundles, packages, binaries and backups are bound by SHA-256;
- off-host client manifests use asymmetric signatures;
- tag, version and manifest identity are cross-checked;
- privileged release paths accept HTTPS and allow-listed sources only;
- cross-repository assets are version-pinned and checksum-verified;
- build provenance is produced, and OCI builds request SBOM/provenance;
- runtime containers use least privilege and loopback-only publishing where
  possible;
- application update success requires a verified saved-copy backup, health
  checks and a persisted outcome with a tested recovery path; shared-component
  updates require the same release/health verification without an application ZIP.

### 33.2 Boundaries That Must Stay Visible

- A checksummed server manifest is not a signed manifest.
- Generated provenance is not enforcement unless installers verify it.
- Verifying that a tag exists is not cryptographic signed-tag verification.
- A version-addressed release may still be replaceable by repository
  administrators unless platform controls enforce immutability.
- CI actions referenced by moving major tags are not pinned to immutable
  commits.
- A dependency lock file is stronger than a bounded version range without
  package hashes.
- A public key downloaded beside an artifact is not a trust anchor and MUST NOT
  be used. First-install trust comes from the key embedded in the exact
  versioned service bootstrap; existing hosts use a transition signed by their
  already trusted key. No manual fingerprint step is part of release trust.
- A mutable `curl | sh` bootstrap is outside the protection of later artifact
  checksums.
- A locally smoke-tested build is not necessarily the exact published digest.
- Mocked updater tests are not an end-to-end container and system-service
  rollback test on a real host.
- Building a native package is not the same as installing and health-testing
  that package in CI.
- Unit-testing a replacement helper is not a complete end-to-end portable
  update and timeout rollback exercise.

Documentation MUST use precise words. Do not call a checksum a signature,
provenance generation provenance enforcement, tag presence signed-tag
verification, or a smoke test complete rollback validation.

## 34. Operator Update UI

This contract applies to every current and future application update. Shared
host components use the root TUI workflow in section 34.6. The permanent
application Settings card follows
[Part 01 section 5.5](./PART_01_INTERFACE_AND_INTERACTION_UNIFICATION.md#55-settings-information-architecture).
The six embedded examples, colors, fonts, dimensions, responsive rules and
historical-image corrections are authoritative in
[Part 01 section 10.8](./PART_01_INTERFACE_AND_INTERACTION_UNIFICATION.md#108-update-dialog-templates).

### 34.1 Target And Entry Points

The application Updates card shows its installed version, local update-helper
reachability and approved registry/release-policy reachability independently.
Its check/install control targets that application. Consumed shared components
may show health or installed version in their connection cards, but their
service Settings cards do not expose release check/install controls. An unused
component does not receive a misleading installed/healthy card. The chosen
application remains visible throughout discovery, confirmation and job
observation; an application version and a helper version are never interchanged.

If updates belong exclusively to an external package manager or administrator,
name that mechanism and the last verified version. Explain why local Install
is unavailable instead of simulating this workflow.

### 34.2 Discovery And Exact Selection

1. `Check for updates` opens the custom overlay immediately, displays
   `Checking...` and starts one fresh discovery request for the chosen target.
2. Show installed version, target identity, helper availability, registry
   status and the time of the last successful observation. An unknown installed
   version is not `0.0.0` and cannot authorize an upgrade.
3. Resolve the approved release source through the authenticated control plane.
   Compare semantic versions numerically; exclude draft, prerelease, wrong
   namespace and incompatible candidates according to the declared channel.
   A normal update rejects downgrade and same-version replacement.
4. Display a candidate only after release identity and the applicable
   compatibility checks succeed. Name exactly which checks have completed.
   Release discovery does not prove that artifact bytes/signatures have been
   verified unless that verification actually ran. The privileged helper
   independently verifies the signed manifest, artifact digests and exact
   target again before mutation.
5. With a newer compatible candidate, show `Install <version>` and approved
   release notes. Without one, show `No newer compatible release was found`
   and `Check again`, with no install offer or fabricated job.
6. `Check again` performs another real check. While it is pending, disable
   duplicate checks and install, retain last-known information as stale, and
   show pending feedback. Ignore out-of-order responses for an older target or
   request. An error, missing credentials, offline source, busy helper or
   unsupported protocol is not a successful no-update result.

A newer incompatible release is identified as blocked with its reason; it
cannot appear as an installable candidate. Last-known-good information may
remain visible with its age/provenance, but cannot stand in for the helper's
required fresh verification. Discovery may be available without the local
helper only when the application has an approved independent read path; Install
remains disabled with a named prerequisite.

Release-note and other generated links use the current approved coordinates
obtained through the control plane. Do not hardcode deployment addresses or
accept an arbitrary destination from browser input.

### 34.3 Mandatory Application Backup Gate

`Install <version>` opens the warning for an application release; it does
not yet submit a privileged update. The warning names the application and
exact target, explains replacement and possible recovery, and states that
the full ZIP must be saved on the operator's computer.

The required sequence is:

1. `Create backup and install` explicitly authorizes the named target. It creates
   a fresh standard full ZIP through the same
   application-owned builder used by manual and automatic backups. Export is
   authorized, bounded and internally consistent. Only one creation is pending
   for this confirmation.
2. The browser saves those bytes. Invoke the native save picker from a trusted
   user action where supported, await the write and successful close, then show
   `Backup saved` and continue the already explicitly authorized installation.
   Picker cancellation, denied permission, failed generation or failed writing
   leaves installation blocked and offers a retry.
3. Where verified file saving is unavailable, initiate the normal browser
   download and submit the update from the same action. The interface cannot
   detect an ordinary download's completion and MUST NOT claim that the ZIP
   was saved. There is no second acknowledgement, file selection or Install
   action. Both paths bind to the original explicit target and show the
   download state without exposing archive content. A cancelled preparation
   does not continue.
5. The application authenticates a short-lived receipt that binds profile,
   component, selected version, request ID, exact ZIP size and SHA-256. The
   helper verifies scope, expiry and byte equality before
   mutation. The receipt contains no signing secret; its key stays server-side.

The browser returns the same saved ZIP bytes; the application MUST NOT create
a replacement snapshot at submission. An automatic remote backup alone does
not satisfy this one-click download sequence. Changing target/profile, expired
receipt, mismatched bytes or loss of the pending browser state requires a fresh
authorized preparation.
Receipt lifetime is bounded (reference default: 15 minutes) and communicated
when expiry affects the action.

Before submission, Cancel/Close returns to discovery without changing the
installed service. After acceptance, closing a dialog or browser does not
cancel the host job. Keep ZIP bytes and bearer receipts out of URLs, logs,
browser persistent stores and service-worker caches; only non-secret
request/job references may survive reload.

The complete archive lifetime, size and recovery rules are in
[Part 03 section 13.2](./PART_03_BACKUP_AND_RECOVERY.md#132-backup-lifetime-during-an-application-update)
and section 30 of this Part.

### 34.4 Submission, Live State And Reconnection

Submit the exact selected version with a stable request ID and retain that ID
before sending. The response is an acknowledgement containing the durable job
ID, never an assertion of successful installation. Disable duplicate install,
backup creation and competing check/target changes while the job is active.
The host mutation lock remains authoritative across tabs and connected clients.

The job panel exposes target, job ID, current machine state, sanitized message,
actual progress and permitted recovery controls. Its data comes from
authenticated persisted job state, not a browser timer or optimistic steps.
Observe through authenticated push or bounded polling; the reference visible
poll cadence is 1–2 seconds. Poll failures back off to a bounded interval
(reference maximum: 30 seconds) and show `Reconnecting...`, the last known
state and last successful observation time. Resume promptly on regained
connectivity/visibility. A product may document another measured cadence without
weakening truthful state or durable execution.

Closing, navigating, reloading or losing the connection MUST NOT lose an
accepted operation. Reopen it by its retained request/job identity and verify
the component scope. If a submission response was lost, look up that request
before considering a retry; do not generate a new request ID automatically.
An expired application session requires sign-in and then authenticated status
recovery, not anonymous access to private jobs.

A restart-related HTTP error is not by itself an update failure. Keep stale
state visible rather than inventing progress or completion. For a remotely
managed component, command acceptance, waiting for agent check-in and verified
completion are distinct states. Only a reported target running version and
health complete the operation; queued/offline time is not download progress.

| Progress observation | Presentation |
| --- | --- |
| Current phase, no measured total | Indeterminate track with named phase; no numeric percentage |
| Valid measured completed/total in one unit | Bounded proportional fill and explicit unit/total; clearly identify phase-local progress |
| Different phase or changed total | Rebind to the new observation; do not fabricate an overall time estimate |
| Lost observation | Last known state plus reconnecting/stale indicator; no advancing fill |
| Terminal job, including `mode: complete` or `1/1` | Stop motion and render the actual outcome; completion of work is not necessarily update success |

Never map state ordinals, elapsed time or arbitrary increments to a supposed
measured percentage. Progress remains accessible with reduced motion and
without relying on color, as specified in Part 01.

### 34.5 Completion, Errors And Rollback

On `COMPLETED`, refresh actual runtime version and health, update the
installed-version row and start a fresh discovery check. Preserve the completed
job in its panel. If no newer compatible release is found, remove Install; if
another release exists, offer that exact candidate through a new confirmation.
Failure of the post-update discovery is reported separately from the completed
installation.

The error view distinguishes:

- rejection before mutation, with a safe prerequisite/retry action;
- installation failure followed by verified `ROLLED_BACK`, showing the
  restored version rather than claiming the requested version was installed;
- `ROLLBACK_FAILED`, preserving both the original failure and recovery
  failure with an actionable operator step;
- interrupted or unknown outcome requiring authenticated job reconciliation.

Errors remain inside the durable job view, not only a transient toast. Expose
safe stage/error codes and human-readable causes; redact credentials, private
headers, archive bytes and unrestricted command output. Do not replace the
running version with the requested version before health verification.

Rollback is a separate consequential action. Show it only for the scoped job
when supported; enable it only when the server permits recovery at a safe
boundary. Its confirmation names the previous version and warns that restoring
the saved snapshot discards changes made after that snapshot. Later manual
rollback, or data recovery after helper/host restart, requests the original
operator ZIP and verifies the job's stored SHA-256 before mutation. A different
archive is rejected. Automatic rollback during an uninterrupted update may use
the in-memory original copy. Retain the job and exact outcome after recovery.

An ordinary host reboot does not require restoring applications from ZIP.
The recovery-upload requirement belongs to interrupted update/rollback or
explicit restore, not to every restart.

### 34.6 Shared-Component Updates

Every consumed shared component, including the update helper itself, uses
the same exact-version selection, durable job and error/reconnection semantics.
The root TUI provides Updater check/self-update and Neptune/Gryphon/Wyvern
install/check/update without a registered application. The service Settings
pages do not expose shared-component release controls. Updater, Neptune,
Gryphon and Wyvern service APIs reject release checks and updates in favor
of the root TUI.

Host component updates have no application ZIP creation/download, saved-copy
acknowledgement or backup receipt. The root TUI names the component, exact
target and shared impact before confirmation, then observes the durable job.
This exception is not a way to classify an application upgrade as a helper
operation.

The helper preserves agent configuration, registrations and tokens through its
signed upgrade/recovery contract. Updates to a shared instance do not reinstall
it for each consuming application. Do not request a new enrollment merely to
update it. An approved failure recovery uses previous verified binaries and
configuration; it cannot claim restoration from an application ZIP that was
never requested.

The full ordinary **application update** workflow MUST be reproducible through
the connected application's UI without a native CLI. Shared host components
have their root TUI workflow. Both surfaces keep exact-target confirmation
and durable job observation; their supported operations are documented
separately.

The current request, backup and host-component sequences are mapped in
[Service update mechanism](./service_update_mechanism.md). This implementation
map does not replace the requirements in this Part.

## 35. Compatibility Migration To The Unified Update Workflow

This section is a first-transition exception, not an alternative everyday
update experience. It is universal: concrete executable names, versions,
supported source ranges, profile IDs, paths and shell commands belong in each
application's versioned runbook.

When an existing application cannot yet produce the required saved-copy
receipt, use a tested compatibility bridge:

1. Identify actual running versions and registered profiles. Inspect the newest
   relevant job by ID, component, target and timestamp; an old failed job is
   not evidence that today's update failed.
2. Publish and qualify the signed compatible update-helper release before
   publishing applications that require it. Pin that dependency and digest in
   their releases. On each host, upgrade the shared helper through its existing
   verified trust path and check both binary and running daemon versions.
3. Before changing legacy retention or each application, save a fresh standard
   full ZIP on the operator's computer. The runbook makes any legacy archive
   cleanup explicit before it can remove older recovery copies.
4. The authorized bridge accepts the exact downloaded ZIP, the original
   one-click authorization, registered application identity and exact target version.
   It constructs the same scoped receipt and submits the normal authenticated
   update protocol. It does not bypass signature, digest, backup or health
   validation, and it preserves the live environment and application data.
5. Transfer ZIP bytes without text conversion directly to process memory, or
   through an explicitly supported private verified tmpfs handoff with cleanup.
   No persistent application-host archive, manual signing-key copy or
   fingerprint preparation is introduced. The update executes on the host;
   a remote shell is only one possible transport for the saved bytes.
6. Retain the returned request/job ID and follow it to verified completion.
   On an uncertain transport result, inspect the existing job before submitting
   anything again. Check runtime health, public authenticated access, preserved
   settings and the service's primary function before advancing dependencies.
7. Subsequent updates use section 34 through the application UI.

An existing installation MUST NOT be passed through a destructive
first-install bootstrap or a legacy apply route that omits the backup gate.
A fresh installation has its own signed bootstrap flow in Part 04 and does not
pretend to migrate an absent old application.

Runbooks MUST label where each command executes (operator computer or host),
which shell syntax it uses, required privileges, binary-safe transfer and the
source/target version pair. Do not give a shell's continuation/redirection
syntax as if it worked in every terminal. Existing authenticated host access
must not be weakened to make the transport work.

If a current implementation does not yet satisfy sections 34–35 or the visual
ledger, record the exact deviation, affected versions and convergence test.
An implementation limitation or historical screenshot cannot silently redefine
the universal standard. The acceptance gate is
[Part 06 section 39.1](./PART_06_UNIFIED_ACCEPTANCE_CHECKLIST.md#391-universal-update-workflow-acceptance).
