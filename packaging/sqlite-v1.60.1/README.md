# SQLite dependency notices

Pluto Copy and the inactive `internal/pluto/syncstate` foundation pin `modernc.org/sqlite`
v1.60.1 and its required `modernc.org/libc` v1.77.1. Go checksums are recorded in
`go.sum`; module downloads use the official Go proxy and checksum database.
The driver is CGO-free and supports the existing Linux amd64/arm64 targets.

These four notice files are copied without modification from the verified driver
module. `LICENSE-3RD-PARTY.md` contains the full transitively flattened notices,
including material transpiled into the driver. Upstream source and API:

- https://gitlab.com/cznic/sqlite/-/tree/v1.60.1
- https://pkg.go.dev/modernc.org/sqlite@v1.60.1

Copy's bounded ephemeral enumeration now links the SQLite runtime into the CLI.
`scripts/build-release.mjs` verifies these four exact upstream hashes, produces
the deterministic `pluto-runtime-notices.tar` asset, and records the modules
linked into both actual architecture binaries in `INVENTORY.json`. Full upstream
notices are retained, including optional/module-graph entries. No notice is
trimmed based on an inferred unused dependency.

The archive's size/SHA-256 and exact release URL are covered by the unchanged
RSA-PSS signature. Updated verification checks actual archive bytes and candidate
build info. Fresh installation and the new updater place readable files in
`/usr/local/bin/pluto.notices` beside the binary and transactionally replace/roll
back binary and notices together, retaining profile/state/pause/socket identity.

## Compatible embedded migration bridge

New qualified candidates use a signed schema-1 envelope plus the strict
`pluto-runtime-contract.v1` extension. The compiled policy boundary 0.1.5 is a
local signing/build rule. Genuine published 0.1.4 is stdlib-only and predates this
boundary. Its authenticated metadata and signed payload fingerprints are retained
as public regression fixtures in `testdata/releases/pluto-v0.1.4`.
New verifiers reject a stripped extension at/above that boundary and inspect the
actual linked Go module inventory, so a SQLite-linked binary cannot waive notices
by claiming an older version.

Every current Pluto CLI embeds the deterministic full notice archive at
`internal/pluto/runtime-notices.tar`. `pluto licenses --archive` emits its exact
bytes; `pluto licenses` prints its inventory. Both are bounded, read-only commands
that do not load profiles/state or start a daemon. `--version` has no notice writes.
Legacy schema-1 updaters ignore the extension but verify raw manifest/binary bytes,
therefore delivering notices inside the signed binary. Their first transition may
have no external sidecar. New updater/fresh bootstrap additionally validate the
external archive and candidate command before quiesce/install and place verified
files beside the binary; binary+sidecar rollback remains transactional.

Only genuine pre-boundary schema-1 manifests without runtime fields retain the
narrow binary-only branch; an actually SQLite-linked candidate is rejected by a
new updater even if signed metadata falsely names an old version. New schema-2
manifests remain readable but cannot waive the same post-boundary contract.
The historical local 0.1.3 CLI has been qualified against the new compatible
candidate, including failed-start and interrupted v1-journal rollback. This does
not identify the deployed production binary or replace real systemd/arm64 release
qualification. Fresh bootstrap still refuses an existing installation; use its
existing updater for the compatible bridge and retain configuration/state.

Release builds refuse stale embedded bytes or inventory. After an explicitly
reviewed dependency/notice update, run `node scripts/regenerate-runtime-notices.mjs`
with qualified Go 1.26.10 to regenerate only the source archive from actual CGO0
amd64/arm64 builds. Review its diff and dependency license coverage before signing;
normal release builds never silently regenerate it. All four upstream notice
files remain complete and byte-identical, including entries beyond current runtime.
