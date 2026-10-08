# Part 13. Host Dependencies And New Component Contract

This Part defines the installation graph for Linux hosts and the contract for
adding an application service or a shared host agent. It applies alongside
[Part 04](./PART_04_BOOTSTRAP_AND_DEPLOYMENT.md),
[Part 05](./PART_05_CI_RELEASES_AND_LOCAL_UPDATES.md) and the concrete agent
workflows in [Part 09](./PART_09_SERVICE_AGENTS_DEPLOYMENT_AND_LIFECYCLE.md).
The decisions in this Part describe the target implementation. Existing code
that still requires a consuming head or operator Access Key for a host-agent
release/enrollment is a migration gap, not an alternative contract.

## 1. Roles and ownership

| Layer | Current components | Host cardinality | Ownership |
| --- | --- | --- | --- |
| Base | Updater | Exactly one per Linux host | Owns privileged installation, verified release operations, host release-source settings and its own Kernel machine connection. It installs and self-updates with no application head. |
| Shared host agents | Neptune Linux, Gryphon, Wyvern, Window | At most one local instance of each per Linux host | Own their runtime, identities and host-level configuration. Each installs independently through its own exact-version bootstrap or Updater TUI. Its bootstrap ensures Updater. |
| Application services | Kernel, Volt, Chronos, Saturn, Laboratory, Perimetr, Mastermind | Independent service deployments | Own their application state and service head. Their installer ensures Updater and each declared host agent before reporting local installation success. |

Neptune Windows has a separate client lifecycle and is outside this Linux host
matrix. An explicitly configured remote Wyvern placement is a separate mode;
local Wyvern is the default dependency for its consumers. An application never
owns or uninstalls a shared host agent. Adding another consumer adds only that
consumer's scoped profile, socket mount and credentials. A newer shared release
requires one host-wide compatibility check and update job; an older pinned
bundle never downgrades a healthy instance.

## 2. Current consumption matrix

Every application below ensures Updater. A check mark declares an additional
mandatory local agent for its default placement; an empty cell means no such
dependency. This is an installation contract, not a claim that current
installers already satisfy it.

| Application service | Neptune Linux | Gryphon | Wyvern | Window |
| --- | :---: | :---: | :---: | :---: |
| Kernel | ✓ |  |  |  |
| Volt | ✓ |  |  |  |
| Chronos | ✓ | ✓ |  |  |
| Saturn | ✓ | ✓ |  |  |
| Laboratory | ✓ |  | ✓ |  |
| Perimetr |  |  |  |  |
| Mastermind | ✓ | ✓ | ✓ |  |

Window has no application consumer edges in its first release. Its paired
development-PC reader is an operator-granted diagnostic client, not an
application dependency or an installation prerequisite for another agent.
Window's storage view is read-only and grant-gated. Docker image inventory,
rollback retention and cleanup belong to Updater's privileged host operation;
Window never receives that mutation capability. The offline current/previous
image rule is specified in Part 05 and applies to application heads regardless
of which shared agents are installed.

Window's root bootstrap provisions a separate interactive `windowops` SSH
account and a narrow sudo entry for its own Updater TUI section, first key
pairing and bounded test capture. Login credentials are configured by the
operator; the dedicated `window` SSH account remains an MCP-only reader. A
reachable Kernel HTTP 403 for `repositories.window.url` is an authorization
failure under §3, even when Window's fallback repository is configured.

The machine-readable dependency map in Updater and each consuming release
bundle MUST agree with this matrix. A new service changes both through one
reviewed compatibility contract. A host agent's own release dependencies are
only Updater unless its approved architecture explicitly changes this Part;
an agent MUST NOT require a neighboring agent or application to install or
update its binary.

## 3. Release source, trust and authorization

1. For Updater self-update and every host-agent install/check/update, Updater
   first reads `repositories.<component>.url` from a validated Kernel Register
   through **Updater's own host machine connection**. It never chooses a
   consumer head as the release-source authority.
2. If that Kernel connection is unavailable, Updater uses the root-owned
   fallback URL entered for that component in `sudo updater tui`. The TUI
   presents source, provenance and connection/error state separately for each
   component; it does not demand all repository URLs during initial setup.
   Any private-repository access credential is stored separately from the URL
   and is never treated as a release-signing trust anchor.
3. A reachable Kernel response with invalid, contradictory or unauthorized
   data is an error. A signature, manifest, digest, compatibility or health
   failure after source selection is also an error. Neither case silently
   switches to the fallback URL. No hard-coded catalog of all repository URLs
   is shipped with Updater.
4. An exact-version bootstrap may use its own verified signed manifest/bundle
   for first installation and may seed its **own** editable TUI fallback URL.
   An application bundle may carry exact, signed, pinned agent installers for
   first installation when neither Kernel nor a TUI fallback is ready. Future
   release discovery still follows steps 1–3.

Each component has its own signing trust anchor. Repository coordinates and
credentials are separate: a URL is not proof of authority. Updater's Kernel
credential is stored under root ownership and has only the required independent
scopes, for example Register read and a host/instance-bound Wyvern enrollment
right. It is not the legacy shared `KERNEL_SERVICE_TOKEN`, a consumer head token,
or an operator browser session. Operator Access Key and cookie cannot authorize
Wyvern enrollment. Kernel issues or securely provisions the Updater machine
credential during host setup; a top-down installer passes a protected reference
to an already authorized credential, never a secret in argv, logs or another
service's `.env`. When that right is unavailable, local agent installation can
finish while enrollment remains pending.

## 4. One lifecycle in both installation orders

Use one idempotent state machine per host component and consumer binding:

```text
ABSENT → INSTALLED → UPSTREAM_CONFIGURED → CONSUMER_LINKED → FUNCTION_READY
```

`INSTALLED` requires signature/digest verification, exact component identity,
one local daemon and local health. `UPSTREAM_CONFIGURED` requires only the
upstream coordinates and machine authorization relevant to that agent.
`CONSUMER_LINKED` is scoped to one consuming service. `FUNCTION_READY` requires
the agent's external integration prerequisites, where applicable. Each step
records a terminal result or a precise pending reason. A missing Kernel,
Saturn setup code, Telegram bot/pairing or Wyvern Adapter never masquerades as
a failed binary installation or a ready function.

- **Bottom-up:** Updater bootstrap works alone. A host-agent bootstrap or TUI
  install ensures/reuses Updater, installs the agent, and stops at the last
  reachable state. A later consumer install reuses the same process and
  completes authorized connection and client steps without re-entering known
  values.
- **Top-down:** An application bootstrap prepares that application's verified
  release and pinned dependency bundles. Its installer synchronously ensures/reuses Updater
  and the agents in the matrix, waits for each local health result, then advances
  permitted upstream and consumer links with its available protected context.
  Background reconciliation is for later repair, not a substitute for the
  install result. External integration steps may remain visibly pending.

An installation is unsuccessful if a mandatory local agent is absent or
unhealthy. It may succeed with an explicit `connection pending` result when an
external system or authorization is unavailable. Repeated bootstrap/install,
concurrent consumers and lost responses do not create a second agent or rotate
credentials. A different Kernel/host binding or incompatible version requires
explicit migration or repair, not silent rebinding.

## 5. Example: add an application service at Volt's layer

`example-app` is an illustrative name and **not** an existing manifest schema
or CLI command. Suppose it needs backups through Neptune and no messaging or
LLM gateway. Its proposed dependency declaration is:

```yaml
component: example-app
role: application
host_dependencies:
  - updater
  - neptune-linux
```

The implementer MUST:

1. Add `example-app → Neptune` to this matrix and Updater's allow-listed
   capability map; document its Neptune profile, minimum compatible versions
   and any Kernel/Saturn enrollment scopes.
2. Publish its own exact-version bootstrap, signing key, signed manifest and
   bundle. Pin the tested Updater and Neptune installer artifacts by version and
   digest. Keep its own `.env`, rollback and application state separate.
3. During install, ensure/reuse one Updater, register only its own scoped head,
   ensure/reuse one healthy Neptune synchronously, create only its Neptune
   client profile and report installed/reused versions. A missing Saturn code
   leaves that profile pending, while the local installation remains valid.
4. Use its Settings card for its own backup configuration; use typed scoped
   Updater operations for its permitted client/profile actions. Host-wide
   release source and administrative agent updates belong to root TUI.
5. Test empty host, existing Updater/Neptune, second consumer, offline Kernel,
   pending setup code, incompatible agent, concurrent install, failed health and
   rollback. The application cannot edit fallback URLs or another profile.

If the new application also consumes Gryphon or Wyvern, declare that edge in
the same matrix. Ensure the local gateway during install; link only its own
client. Telegram token/pairing and Wyvern provider Adapter remain separate
external readiness steps. Wyvern's first Kernel enrollment uses Updater's
scoped machine credential, never the application's Access Key.

## 6. Example: add a shared agent at Gryphon's layer

`example-agent` is illustrative. It is shared by future applications and has
no required neighboring agent:

```yaml
component: example-agent
role: host-agent
host_dependencies:
  - updater
cardinality: one-per-linux-host
```

The implementer MUST:

1. Give it a distinct signing key/trust anchor, `example-agent-vMAJOR.MINOR.PATCH`
   release namespace, exact-version bootstrap, signed manifest, checked bundle,
   platform artifacts and explicit minimum Updater version. Bundle a pinned,
   verified Updater installer for its own clean-host bootstrap.
2. Add a root TUI section for its repository URL, source provenance,
   install/check/update/repair, local health and pending integration state.
   Implement one host-wide release operation that uses Updater's Kernel
   connection and per-component TUI fallback. It works with zero consumer
   heads and no other agents installed.
3. Define its own protected runtime data, local admin and client interfaces,
   scoped per-consumer credentials and explicit upstream enrollment if any.
   Separate daemon installation from upstream/client connection. Never copy a
   credential from an arbitrarily selected consumer head.
4. Add its consumer edges to this matrix and Updater's capability map. Each
   consumer's installer carries a compatible pinned first-install bundle and
   synchronously ensures the singleton, then provisions only its own profile.
5. Test both installation orders, zero-head TUI, source outage/fallback,
   invalid Kernel data, signature rejection, second consumer, no downgrade,
   scoped authorization, restart, rollback and removal of one consumer without
   deleting the shared instance.

This extension process is a design contract. Exact endpoint names, manifest
fields and on-disk paths are defined by the component's versioned protocol and
reviewed with Parts 04, 05, 07 and 09 before implementation.
