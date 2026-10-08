# Part 09. Service Agents: Deployment, Initialization And Lifecycle

This document is the Exocortex-wide source of truth for deploying, enrolling,
operating and updating the Linux service agents **Neptune**, **Gryphon** and
**Wyvern**, including their consuming services and the base **Updater**. It
supplements the reusable deployment, backup, update and security Parts with
the concrete Exocortex topology. The dependency matrix and extension contract
are in [Part 13](./PART_13_HOST_DEPENDENCIES_AND_EXTENSION_GUIDE.md).

This Part supersedes every former direct-connection compatibility note. Gryphon
is the single Telegram gateway: consuming services MUST NOT embed their own
Telegram polling or webhook runtime and MUST NOT store an adapter token as an
application setting. Updater, Neptune, Gryphon and Wyvern ownership, trust and operator
flows are defined only in Parts 09 and 10.

In the Gryphon workflow, **adapter** means one Telegram integration registered
with Gryphon. Its Telegram API token and username are provider details, not a
separate per-service connection. A **service command adapter** is the authenticated
endpoint exposed by Chronos, Saturn or Mastermind for Gryphon to invoke; it is
distinct from the registered adapter selected in Settings. Existing API field
names such as `botId` remain protocol identifiers.

This Part is subordinate only to the [Part 00 documentation authority](./PART_00_SYSTEM_UNIFICATION_SPECIFICATION.md) and takes precedence over conflicting project-local documentation.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are
normative.

## 1. Scope And Ownership

### Service-owned schedule decision (2026-09-19)

The operator approved moving automatic schedule management from the central
panel into each owning service. Settings → Backup is now the sole operator
surface for that service's enable/interval controls. Manual snapshot download
remains local to the owning service; there is no new manual remote-run action.
This supersedes the former centralized-only schedule rule. Central storage
retains identity, quota, revocation and fleet observation responsibilities.
The handover contract in section 5 preserves existing policies and pending
work; documenting it does not claim that deployed software already implements it.

### Wyvern integration decision (2026-09-19)

The host operator split adopted on 2026-09-27 supersedes earlier service-card
lifecycle/update language: Wyvern Adapter administration and shared release
checks/updates run only through `sudo updater tui`. Laboratory and Mastermind
Settings select an allowed Adapter for their own functions without initiating
another release check or provider probe.

The approved Wyvern extension is a shared LLM gateway per host. A consuming
service installer MUST ensure/reuse the host Updater and a healthy signed local
Wyvern dependency during initial deployment. Direct Wyvern bootstrap and root
TUI installation work without a consumer or Kernel. Manual host administration,
Adapter management and shared release operations use `sudo updater tui`, not a
consuming service's Settings. A consuming installer may invoke a narrow
privileged ensure/connect operation during installation and link only its own
client. The TUI and that installer continue the same lifecycle; neither asks
for an operator Access Key to enroll Wyvern. Uninstalling a consumer MUST NOT remove
the shared gateway or another
consumer's binding. Default data-plane communication uses a local Unix socket;
a dedicated domain is not required. Cross-host HTTPS is an explicit placement
choice, not an automatic outage fallback.

Wyvern opens the outgoing provider request using its configured Adapter
credential. Its internal client identity is independently authenticated. The
Adapter is the complete configured API profile; Driver names the protocol
implementation. Provider keys live in Volt through Kernel, with scoped machine
grants that prevent ordinary consumers and the legacy shared token from
resolving Wyvern credentials or aliases to them. Reload MUST account for Volt
value revisions even when the Register reference revision does not change.

Implementation status and acceptance are tracked in the Wyvern repository.
This extension does not declare an unpublished image installable and does not
waive the existing signed release, update backup/receipt or recovery contracts.
The fixed Wyvern lifecycle uses externally authoritative Kernel/Volt state.
Updater MUST verify the signed image/API/config/capability contract, serialize
operations, drain accepted requests and journal activation/rollback/repair.
Runtime rollback restores only the prior deployment and admission state, never
global Register or Volt. This exception is specific to Wyvern: no caller may
supply a general backup exemption. Encrypted host recovery includes its private
identities and media metadata; executable deployment files are re-provisioned
from a trusted signed installer. Qualification is recorded separately from
production deployment.

| Component | Host ownership | Primary responsibility | Consuming modules |
| --- | --- | --- | --- |
| Updater | One root-owned daemon per Linux host | Performs allow-listed privileged installation, enrollment and verified update jobs; has its own Kernel release-source connection | All seven application services and all three shared agents |
| Neptune Linux | One unprivileged `neptuned` daemon per Linux host | Exports module-owned recovery archives and optional dedicated mirrors to Saturn | Kernel, Volt, Chronos, Saturn, Laboratory, Mastermind; future approved modules |
| Gryphon Linux | One shared gateway service/version per Linux host | Owns registered adapter credentials, webhooks, update deduplication, callbacks and service-scoped bindings | Chronos, Saturn and Mastermind |
| Wyvern | One shared unprivileged gateway per Linux host, or explicit remote HTTPS instance | Owns provider Adapters, keys, request transport and media handles; consumer domains retain prompts, jobs and commits | Mastermind, Laboratory |
| Saturn | Central control plane and storage gateway | Issues single-use setup codes, enforces storage identity/quotas, receives archives/mirrors and may relay service-owned policy/commands; no central schedule editor | All Neptune deployments |

An application web process MUST NOT receive `sudo`, a Docker socket, the Gryphon
administrative socket or arbitrary command execution. Service UI actions call
the application backend with its own scoped identity. Gryphon installation,
adapter registration and shared release checks/updates are root operator actions
through `sudo updater tui`; they are not service Settings actions.

## 2. Trust And Communication Topology

The host operator uses `sudo updater tui` for host-wide management. This console is bundled
with Updater and controls the current host's Updater, Neptune, Gryphon and
Wyvern. It uses a separate root-owned mode-`0600`
Unix socket at `/run/exocortex-admin/updater.sock`. That directory is not mounted
into consuming service containers. Linux peer credentials must additionally
identify UID 0. Shared agent release checks/updates and manual installation
require root operator dispatch; service tokens cannot turn their own Settings
route into a host-wide update. A consuming service installer may use a separate
allow-listed, privileged dependency-ensure operation during deployment. The
service socket and its per-head tokens retain their existing scope. Host-wide
install/check/update and Updater self-update do not select a registered head.
The facade validates a typed action and delegates
using the daemon-owned credential. It must not forward an
arbitrary path, shell command or executable supplied by the terminal.

The systemd runtime-directory declaration preserves both socket directories.
The console is a separate process from the daemon, holds no persistent secrets
or authoritative application state, and reconnects to durable job metadata
after a transport failure or daemon self-update. Read-only local diagnostics
remain available when the operator API is down. Enrollment codes and adapter tokens
are transient masked input. Schedule ownership, adapter/service/user trust
decisions, signed releases and rollback rules remain as specified below.

```text
browser
  -> authenticated module API
     -> /run/exocortex/updater.sock + per-head token for permitted Neptune work
     -> /run/gryphon/client.sock + service credential for adapter selection

root operator -> sudo updater tui -> /run/exocortex-admin/updater.sock
  -> Updater self-update; Neptune/Gryphon/Wyvern install/check/update
  -> component-specific fallback repository URLs and source status
  -> Gryphon adapter registration; Wyvern host connection
  -> /run/gryphon-admin/admin.sock for adapter registration/pairing

Updater -> Kernel Register using its own scoped host machine credential
  -> on connection outage, component-specific root TUI release URL
Updater -> Kernel Wyvern enrollment using a separate instance-bound machine right

module backup builder
  <- loopback/private export request from neptuned
neptuned
  -> Kernel Register (non-secret coordinates)
  -> Saturn HTTPS check-in, archive ingest and optional WebDAV mirror

Telegram
  -> public TLS webhook -> Gryphon
Gryphon
  -> authenticated Chronos/Saturn/Mastermind command adapter
Chronos/Saturn/Mastermind
  -> /run/gryphon/client.sock for status, linking and outbound notifications
```

The Updater socket is `/run/exocortex/updater.sock`. Each registered head has a
separate control token and exact service/profile match. Neptune uses
`/run/neptune/neptuned.sock` for local authenticated control. Gryphon exposes
`/run/gryphon/client.sock` to service containers and keeps
`/run/gryphon-admin/admin.sock` for root/local administration only.

Saturn never opens an inbound port on a Neptune host. `neptuned` polls Saturn
over outbound HTTPS, reports observed state and consumes monotonically revised
desired state and queued commands. A temporary Saturn outage does not erase the
last applied schedule.

## 3. Initial Deployment

### 3.1 Main modules and Updater

Each of the seven application installers installs or reuses the single host
Updater, registers only its own head with a dedicated token and synchronously
ensures the agents declared in the
[Part 13 matrix](./PART_13_HOST_DEPENDENCIES_AND_EXTENSION_GUIDE.md#2-current-consumption-matrix).
Its install result includes the verified local health and installed/reused
version of every required agent. A missing mandatory agent is an install
failure; an unavailable external connection is a distinct pending state.
Initial deployment MUST finish health verification before the UI offers
privileged component actions. Updater itself installs and self-updates via its
own exact-version bootstrap or root TUI without a registered head.

The active systemd unit MUST preserve the Updater runtime directory across
daemon restarts so existing container bind mounts continue to see the socket.
At startup the Updater also compares the host socket-directory identity with
the directory visible in each running registered container. When a stale bind
mount is detected, it recreates only the affected service container with its
existing Compose configuration. Healthy mounts are untouched; stopped or
uncreated containers are not started implicitly. An installation created by an
older unit may require one explicit container recreation before this protection
is active.

### 3.2 Neptune Linux

There is exactly one Neptune Linux daemon per host. It runs as a dedicated
unprivileged user. Its registry and durable journal live under
`/var/lib/neptune`; secret references and per-project credentials live under
`/etc/neptune` with restrictive ownership. Installation MUST verify the release
manifest and archive checksum and MUST NOT create a second daemon for another
module on the same host.

Neptune has its own exact-version bootstrap. It ensures Updater, installs and
health-checks the daemon without Kernel, Saturn, another agent or a registered
consumer. The root TUI offers the same standalone install/check/update path.
Missing Saturn setup code or project credentials leaves only the corresponding
enrollment pending. A consuming installer reuses the local daemon and completes
the authorized profile steps with known credentials.

Neptune releases use `neptune-vMAJOR.MINOR.PATCH` and publish platform- and
architecture-specific archives and manifests for supported targets. The
installer selects the host architecture, verifies the manifest-declared bytes,
installs the native service and proves `/run/neptune/neptuned.sock` health.

Each module exposes an authenticated local export endpoint backed by the same
logical archive builder used by manual download and restore. Neptune treats the
archive as exact bytes: it does not unpack, rename, re-encrypt or recompress a
recovery ZIP.

The privileged module CLI remains a profile repair and emergency fallback;
new module installation already ensures local Neptune:

```text
sudo kernel-install backup
sudo volt-install backup
sudo chronos-install backup
sudo saturn-install backup
```

For a new application deployment, its installer ensures a healthy Neptune
before completion. On an older or damaged host where Neptune is absent,
Settings may offer a scoped Initialize/repair through authenticated Updater;
it is not the normal first installation path. If a healthy instance already
exists it is reused without a download, restart or duplicate installation.
A setup code is never persisted by the web service. The operator sees a
durable terminal job result.

### 3.3 Gryphon Linux

Gryphon has its own exact-version bootstrap, which ensures Updater and installs
the local gateway without Kernel, another agent or a consumer. It can also be
installed through `sudo updater tui` on an empty host. Shared install, release
checks/updates and adapter registration never select a consuming service for
release source. The installer of Chronos, Saturn or Mastermind synchronously
ensures/reuses Gryphon and provisions only that consumer's scoped client. A
Kernel connection or bot configuration may remain pending after local health.

The root operator registers an adapter in the TUI with an alias and Telegram API
token. Updater forwards the token only to Gryphon's root-only admin socket;
Gryphon verifies its Telegram identity, registers the webhook and stores a
protected credential copy. The TUI shows a one-use `/link CODE`, valid for ten
minutes, for the owner to send in a private chat with that adapter. The adapter
list shows the verified pairing state. Connected domain services neither
receive nor store the token; their installers provision only their scoped
Gryphon client credential and mount the client socket. The old
`gryphon bot connect` and `gryphon link issue` CLI operations are retired.

Native releases use `gryphon-vMAJOR.MINOR.PATCH` with an
`exocortex.gryphon.release.v1` manifest. Initial installation extracts a
verified archive, runs `packaging/linux/install.sh` as root, configures
the protected Kernel connection when authorized coordinates are available, and starts
`gryphon.service`. The listener on port `18380` accepts only Telegram webhooks
and MUST be published behind HTTPS at that public origin. Persistent database
and protected secret copies under `GRYPHON_DATA_DIR` are operated and backed up
together.

### 3.4 Wyvern and its first Kernel enrollment

Wyvern's own exact-version bootstrap ensures Updater and installs one healthy
local runtime without Kernel, Volt, another agent or consumer. The root TUI can
install the same runtime on an empty host. Its Kernel connection, Adapter
configuration and consumer links are subsequent states. Laboratory and
Mastermind installers ensure/reuse the runtime, then advance only authorized
machine enrollment and their own client links using already available protected
context. Missing Kernel or authorization is reported as `configuration pending`
without repeating binary installation.

The first Kernel enrollment endpoint is a machine endpoint. It authenticates
Updater's own scoped machine credential and checks the requested Wyvern
instance, host and `wyvern.enroll` permission. It MUST NOT accept an operator
cookie/session or Access Key, including as a recovery route. The shared legacy
`KERNEL_SERVICE_TOKEN` has no enrollment right unless separately provisioned as
a scoped machine principal; it is never promoted implicitly. Kernel securely
issues the Updater credential during host setup or a dedicated machine
bootstrap; consuming installers pass only a protected reference to an already
authorized credential and Kernel URL. Enrollment is idempotent across retries
and lost responses and does not rotate existing Wyvern `manager/runtime`
credentials without an explicit authorized rotation. Updater's own credential
is not copied into Wyvern. TUI Connect asks for Kernel URL and, when necessary,
instance ID, not an operator Access Key.

### 3.5 Host release-source connection

Updater stores its own Kernel URL and scoped Register-read credential under
root ownership, separately from any consuming head. For Updater, Neptune,
Gryphon and Wyvern it queries validated `repositories.<component>.url` through
this connection first. Only when Kernel is unreachable does it use the
component's root TUI fallback URL. Each component's TUI section can set/change
its own HTTPS URL and shows the active source and outage reason. There is no
preinstalled catalog of all repository URLs. A reachable invalid/conflicting
Register response or failed release verification is an error, never a reason
to switch source. A signed exact-version bootstrap or pinned consuming bundle
can supply the artifact for first installation and may seed only its own
editable fallback URL. Host-wide release actions work with zero registered
heads and never read another service's `.env`.

## 4. Neptune Initialization

### 4.1 Operator workflow

1. In Saturn → **Synchronization**, create the required Linux pipeline identity
   and a single-use setup code. The code expires after 15 minutes.
2. On the target module host, open Settings → **Backup**.
3. When the panel reports `Detected · not linked`, select **Initialize**,
   then paste the code and confirm in the **Initialize Neptune** overlay.
4. The backend forwards only the setup code and its own registered service
   identity to Updater. The setup code MUST NOT be persisted by the module.
5. Updater validates the exact module profile, exchanges the code with Saturn,
   writes the scoped credentials, registers or repairs the project in Neptune
   and restarts only the required local service when necessary.
6. The UI polls the persisted initialization job through a service-authenticated
   status endpoint until a terminal state. A successful request is not a
   successful initialization.
7. After `COMPLETED`, the module reloads Neptune status and confirms the expected
   pipeline set. `FAILED` shows the sanitized terminal reason and a retry path.

The service entry is a card-local `Initialize` action, opening the common
[Part 01 section 10.9 overlay](./PART_01_INTERFACE_AND_INTERACTION_UNIFICATION.md#109-service-initialization-overlays).
Code creation remains identity/enrollment management and is not schedule
editing. Initialization reuses a compatible existing daemon and enrolls only
the requested service. Completion unlocks that service's schedule controls;
it does not enable a new schedule or run a backup implicitly. Transport
unavailability is not proof that installation is absent.

The initialization state vocabulary is `REQUESTED`, `INSTALLING`, `ENROLLING`,
`COMPLETED` and `FAILED`. Temporary loss of the module API while its container
is recreated is an expected reconnect state, not an automatic failure.

### 4.2 Per-module profiles

| Module | Required Neptune registration | Successful postcondition |
| --- | --- | --- |
| Kernel | Recovery archive only, namespace `kernel` | Kernel archive project exists and is linked |
| Chronos | Recovery archive only, namespace `chronos` | Chronos archive project exists and is linked |
| Saturn | Recovery archive only, namespace `saturn` | Saturn archive project exists and is linked |
| Laboratory | Recovery archive only, namespace `laboratory` | Laboratory archive project exists and is linked |
| Volt | Recovery archive plus dedicated `personal.volt` mirror | Both independent pipelines exist with the exact Volt profile |
| Mastermind | Recovery archive plus dedicated Vault tree mirror | Both independent pipelines exist with the exact Mastermind profile (`mirrorRoot=mastermind`, `mode=zip-tree`) |

Volt is deliberately not an archive-only special case. A single Volt setup code
provisions two credentials and two workers:

```text
recovery ZIP:  namespace=volt -> immutable Saturn backup archive
mirror:        mirrorRoot=volt, mode=single-file,
               targetFilename=personal.volt -> Saturn WebDAV /volt
```

The workers have independent execution state, retries and credentials and run
concurrently. Volt and Mastermind expose one enabled switch and one hourly
interval in their own Settings; a versioned `schedule-all` mutation commits the
same values to both pipelines atomically. The UI MUST wait for the Updater job
to finish, reload Neptune state and verify both rows. If one pipeline is absent
or has the wrong profile, the owning service reports partial configuration and
offers **Repair Neptune pipelines**; it MUST NOT claim that backup is ready.

## 5. Ongoing Neptune Interaction

### 5.1 Policy Ownership And Control

The owning application's Settings → Backup authors its schedule. Remove schedule
enable/interval editors and service backup-run
buttons from the central panel. Central inventory may display desired/applied
state, last success and health, and manage identities, quotas, enrollment and
revocation. Those storage security controls may block execution but cannot
silently rewrite the service's schedule.

One versioned policy record is authoritative for each service/deployment and
pipeline. Its physical persistence may remain in an existing control-plane
backend, but all operator writes originate from the owning service's
authenticated workflow and are restricted to that scope. A deployment profile
names this backend and its protocol; the application and agent must not each
maintain an independently writable schedule. The agent keeps applied execution
state, not an alternative operator policy.

The browser calls only its authenticated service backend. The backend resolves
required internal coordinates through the registry and uses a typed scoped
schedule operation via the authorized local agent or existing control-plane
transport. It cannot forward arbitrary command, path, identity or URL fields.
Server-derived service/pipeline identity, authorization and expected policy
revision prevent access to another service's schedule.

A policy update contains enabled state and interval hours plus its expected
revision; validation and commit are atomic. Return committed desired revision,
agent-applied revision, next due, last success and any pending/error state.
Use an idempotency key for mutations and reject stale concurrent revisions
rather than let the last browser overwrite an unrelated change. A saved policy
is shown as `Pending application` until the agent acknowledges it.

### 5.2 Scheduling And Execution Semantics

The archive and mirror paths remain separate:

- the module owns logical recovery format and restore semantics;
- Neptune spools exact archive bytes, records size and SHA-256, and uploads with
  a stable idempotency key;
- resumable upload continues from Saturn's accepted offset after restart;
- archive completion requires a Saturn receipt before spool deletion;
- disabling a schedule blocks new work but does not corrupt active work;
- a mirror compares content identity and updates only its dedicated root;
- producer credentials cannot write WebDAV mirrors, and mirror/device
  credentials cannot create recovery archives.

A genuinely new profile starts disabled with a 24-hour interval; the minimum
supported interval is one whole hour. Enforce finite integer hours and any
declared protocol maximum on client and server. Existing profiles keep their
actual enabled/interval values instead of receiving new-install defaults.

Enabling a schedule or committing a changed interval sets its next due relative
to the acknowledged policy activation time plus that interval. It does not
implicitly run a backup. After a scheduled run completes, the next due follows
the pipeline's documented fixed-delay policy; UTC timestamps avoid local DST
changes shifting intervals. Surface the computed next due instead of asking
the browser to predict it.

The service GUI no longer exposes a manual remote-run action, and service-facing
APIs reject new manual policy runs. A previously accepted run may finish without
changing enabled/interval or the existing scheduled next due. The daemon keeps
the single-project execution lock for already queued work and scheduled runs.

Disabling prevents new scheduled runs, while an accepted transfer finishes or
recovers to a safe terminal result under its retry policy. Network retries
preserve exact archive bytes, checksum, receipt and upload offset; a saved
schedule alone is never proof that a backup reached storage.

The agent executes without an open browser or live service Settings page.
Persist applied policy, current run and recovery state so a restart does not
erase the schedule or replay a backlog of missed intervals. At most one
coalesced overdue run per pipeline is considered on recovery, subject to
permission, backpressure and the existing project/host concurrency limits.
The UI distinguishes desired, applied, due, overdue, running, retrying and last
remote commitment; a remote outage leaves the last applied policy intact.
Archive and dedicated-mirror workers retain separate execution state. Volt and
Mastermind commit one shared enabled state and hourly interval to both policies
through `schedule-all`; basic profiles update only their archive policy.

### 5.3 Handover From Central Schedule Editing

1. Inventory each current service/deployment/pipeline policy, revision,
   enabled/interval, next due and active/queued run identity. Preserve this
   state in the supported backup/recovery boundary before migration.
2. Import or reuse the existing authoritative policy without new-install
   defaults. Each service initially reads the exact prior values.
3. Switch authoring for that scope atomically with an ownership revision/fence.
   Disable the former central editor and its write authorization before the
   new service workflow becomes the sole writer. If the record stays central,
   restrict that same record's write path instead of creating a second copy.
4. Reject stale central schedule commands/revisions after cutover. Dedupe or
   explicitly resolve old queued run commands; never replay them as new runs.
   An active archive/mirror transfer continues with its existing identity.
5. Verify the desired and agent-applied policy, next due, an automatic run and
   the local snapshot download from the service interface. Confirm that a new
   manual remote run cannot be submitted. Test an agent restart and central
   transport outage without resetting settings or duplicating work.
6. Rollback of the migration restores one writer and the preserved policy/
   queue boundary; it cannot leave both central and service editing active.

Service backup/restore includes schedule intent and reconciliation metadata.
These requirements describe the approved target contract, not an assertion
that an older deployment's UI or APIs already support it.

### 5.4 Scoped Neptune unlink

The **Unlink Neptune agent** action in Kernel, Volt, Chronos, Saturn,
Laboratory and Mastermind Settings starts a durable, service-scoped Updater job.
Updater prepares that project's Neptune registration for unlink, disables its
archive and mirror policies, and waits for accepted transfers to reach a safe
boundary. Saturn revokes the project's producer and mirror/reader credentials,
unused setup codes and pending commands while preserving stored archives and
the reusable service identity. Neptune then removes only that registration;
Updater invalidates only that client's local credential files.

If Saturn cannot confirm revocation, the project remains paused in `unlinking`
for a safe retry. The shared daemon, other service registrations and their
schedules remain active. Reconnection requires a new setup code. A local
success response alone does not establish completion; the UI follows the job
and reloads the observed binding state.

## 6. Gryphon Initialization And Binding

Gryphon has two operator surfaces with different scopes:

1. **Host TUI:** a root operator installs/updates Gryphon, registers an adapter,
   and pairs one Telegram account with it using the one-use `/link CODE`. Gryphon
   accepts the code only in a private chat. Pairing is global to that adapter,
   but does not itself connect any service.
2. **Service Settings:** the service owner selects a paired adapter with
   **Link <service> function**. The service backend uses its authenticated
   Gryphon client socket to create its own connection via
   `PUT /v1/service/connection`, with the existing `botId` field, fixed command
   prefix and service command-adapter URL. Gryphon copies the adapter's verified
   Telegram identity into that service's binding. No new `/link` is requested.
   The same adapter may be selected independently by several services.

Unlinking removes only this service's connection. Revoking its Telegram binding
removes only this service's authorization. **Link Telegram account** reattaches
the already verified adapter owner through `PUT /v1/service/binding`; it does
not issue another code. These actions never delete the shared adapter or alter
another service's binding. Gryphon continues to authorize commands by service
scope. The former service-scoped link-challenge endpoint returns `410`.

Existing service bindings remain in place during upgrade. If every existing
binding for an adapter has the same Telegram identity, Gryphon can create its
global pairing automatically. Conflicting identities require a new TUI pairing
before another service can select that adapter. Roll out Gryphon and Updater
before the updated service interfaces.

Gryphon invokes only authenticated, allow-listed command adapters. Chronos,
Saturn and Mastermind do not poll Telegram, register webhooks or deduplicate updates.
Outbound reminders, summaries and responses go back through the service-scoped
Gryphon client socket.

If Gryphon is absent or this service's client is not enrolled, Settings shows
the observed state and directs the operator to `sudo updater tui`. It does not
start Gryphon installation or adapter registration. The old `Bot connection`
card title is retired in favor of `Gryphon Connection`; this UI rename does not
rename socket/API identifiers.

## 7. Updates

The universal application/shared-component contract is
[Part 05 section 34](./PART_05_CI_RELEASES_AND_LOCAL_UPDATES.md#34-operator-update-ui).
The concrete protocol bindings below do not limit its applicability to a fixed
list of applications. Browser update interfaces follow the shared visual
references, exact-target confirmation and durable job lifecycle. Gryphon uses
the root TUI for release operations.

### 7.1 Main applications

Every application discovers and applies its own releases through the local
update-helper contract in [Part 05](./PART_05_CI_RELEASES_AND_LOCAL_UPDATES.md).
An exact standard full ZIP saved on the operator's computer and its scoped
receipt are verified before application mutation; health checks and rollback
determine the terminal result. Shared-component updates omit this application
backup gate, not release verification or state preservation.

### 7.2 Updater, Neptune, Gryphon and Wyvern

All four host-wide release paths use the source order in section 3.5 and work
with no registered consumer. Updater selects an exact compatible release,
verifies the manifest and checksum, stages the artifact, performs the
component-specific atomic replacement, restarts the component and verifies
local health. The web client cannot supply a URL, executable path or command.
The root TUI supports install/check/update for all three agents and
check/self-update for Updater. Service-facing Neptune release checks and
updates are rejected.

| Operation | Local Updater route |
| --- | --- |
| Initialize/repair Neptune profile | `POST /v1/components/neptune-linux/initialize` |
| Read Neptune initialization result | `GET /v1/components/neptune-linux/initializations/{id}` with the authenticated head identity |
| Check/update Neptune Linux | Root-only `sudo updater tui` host operation; service-facing routes reject release requests |
| Check/update Gryphon Linux | Root-only `sudo updater tui` → operator `POST /v1/check` / `POST /v1/actions`; no service selection |
| Check/update Wyvern | Root-only `sudo updater tui` → operator `POST /v1/check` / `POST /v1/actions`; no service selection |
| Install absent agent | Its own signed bootstrap, root TUI, or a consuming installer's narrow dependency ensure; local health is checked before optional enrollment |
| Updater self-update | Root TUI or explicit privileged command, using its own host source; no head required |

The Wyvern operator sequence is:

1. Install Wyvern through its bootstrap or root TUI, with no consumer required.
   The TUI uses Updater's own Kernel connection or the saved Wyvern fallback
   URL when Kernel is unavailable. The exact bootstrap uses its verified
   manifest. Installation establishes local health, not client readiness.
2. Connect Wyvern to Kernel using the scoped Updater machine credential in
   section 3.4; configure Adapter credentials/profiles and client grants in
   the root TUI when these external prerequisites become available. The TUI
   does not collect an operator Access Key for enrollment.
3. Link each Laboratory/Mastermind client with its own scope. When installation
   starts from either consumer, its installer automatically performs steps 1–3
   as far as authorized context allows, without duplicate input or runtime.
4. In Laboratory or Mastermind Settings, select an Adapter already granted to
   that client and bind the service's own functions. This does not install a
   release, perform another release check or send a provider probe.

These are daemon-local routes. Interactive Gryphon and Wyvern release
operations are available only through the root operator socket. Service-facing
interactive lifecycle and update requests for these gateways are denied; a
privileged installer has only the separate, allow-listed initial dependency
ensure contract. Browser-facing module endpoints do not proxy shared
check/update actions.

Shared-agent release policy and fleet observation may remain central. Updater,
Neptune, Gryphon and Wyvern release checks and updates use the root TUI. Their
service-facing APIs reject new release operations. Connection/status cards may
retain visual groups for layout compatibility and explain the TUI path, but
cannot check or install a release. Backup schedule authoring remains in the
owning service Settings; Saturn Synchronization is observation-only for it.

Updater self-update is a separate binary lifecycle. Updating the executable
does not by itself replace arbitrary packaging or systemd definitions. Unit or
package changes require the installer/package repair path unless the signed
Updater release contract explicitly carries and applies them.

## 8. Failure, Recovery And Audit

- Every accepted initialization, repair, link, unlink, update and remote-run
  request produces a durable identifier and an audit event without secrets.
- UI success is based on a terminal job plus refreshed observed state, never on
  HTTP acceptance alone.
- A setup code, service token, producer token, adapter token or `/link` code is
  never logged, returned in ordinary status, included in backup or stored in
  browser persistence.
- Timeouts preserve the job identifier and offer status reload; they do not
  encourage submitting duplicate jobs blindly.
- Retrying the same idempotent request returns or resumes the existing job.
- Revoked identities stop new work. Active archive/mirror operations terminate
  at a safe boundary and retain enough state for diagnosis.
- Manual CLI repair remains documented for an unavailable UI, absent agent,
  damaged packaging or an older deployment that predates the UI contract.

## 9. Required Evidence

An implementation is complete only when evidence covers:

- absent, detected/unlinked, initializing, linked, partial, failed, offline and
  update-available states;
- exact service/profile enforcement and cross-service setup-code rejection;
- final-state polling through the authenticated module proxy;
- module restart/reconnect during initialization;
- Volt archive and mirror workers running independently and concurrently;
- Saturn desired-state retention across temporary loss of connectivity;
- Gryphon adapter registration and one-time TUI pairing, then explicit service
  selection without a second `/link`; service revoke/unlink remain scoped;
- token redaction and inability of a service container to access Gryphon admin
  operations or another Updater/Neptune profile;
- clean-host bootstrap of Updater and each agent, root TUI install/check/update
  with zero heads, and both bottom-up and top-down consumer installation;
- Kernel release-source priority, component-specific TUI fallback on outage,
  and failure without fallback on invalid Kernel data or release verification;
- Wyvern enrollment with correct scoped Updater machine right, rejection of
  operator session/Access Key, legacy unscoped token and wrong instance, plus
  idempotent retry without rotating existing identities;
- verified component update, health failure and rollback/repair behavior.
