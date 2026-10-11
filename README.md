# Pluto

Pluto is the Linux outdoor file-backup agent for Exocortex. It runs independently of Updater and Neptune, has its own terminal UI, and appears separately in Saturn's Neptune fleet. One installation connects to one Pluto pipeline.

## Operator workflow

1. Install the generated `bootstrap.sh` from a signed Pluto release as root. It creates the `pluto` service account and enables `pluto.service`. Installer prerequisites: systemd, curl, OpenSSL and Python 3. The running agent is a single Go binary with no Python dependency.
2. In Kernel Register, configure `services.saturn.sni`, `services.saturn.port` and `repositories.pluto.url`. Follow Kernel's existing Volt reference workflow; these resolved values must be non-secret. The repository is an HTTPS GitHub repository containing Pluto releases.
3. In Kernel Settings → Security → Outdoor service tokens, create a token for this installation. Copy the one-time value into `sudo pluto tui` along with Kernel's HTTPS URL.
4. In TUI, open **Files and folders → Add files or folders** and enter only the new absolute paths, one per line; an empty line saves the additions. Existing sources are preserved and duplicates are ignored. An empty addition cancels. **Remove a source** removes only the selected entry from future copying, including a path that no longer exists; stored backups are kept. Removing the last source disables copying. Source changes are blocked while a copy is running: disable copying and wait for it to stop first. Set the interval (60 seconds to one year); the default is 24 hours. The `pluto` Unix account needs read access to these sources and traversal access to their parent directories. Grant only the required file permissions or ACLs.
5. In Saturn Synchronization, select **Pluto · Linux files and folders**, enter a connection name and create a setup code. There is no Host name field. Paste the code into Pluto TUI within 15 minutes.
6. Enable copying separately in TUI. Enrollment itself leaves copying disabled. TUI also supports **Copy now**, status, interval/source changes, disconnect, release checks and verified updates.

Navigate menus with **↑/↓**, select with **Enter** or **→**, and return with **Esc**, **←** or **q**. Number shortcuts still work. Source lists scroll as the selection moves. Text fields use ordinary line input; outdoor tokens and setup codes are hidden. TUI needs `stty` (coreutils) for interactive arrow navigation and restores the original terminal settings on exit or interruption. Piped input uses numbered menus.

`/etc/nginx/nginx.conf` is saved as `backups/pluto/<connection name>/etc/nginx/nginx.conf`. Selected directories retain their full path and child hierarchy, including empty directories. File contents are stored directly, without ZIP packaging or an archive passphrase. Unix ownership, permissions and timestamps are not restored as file metadata in this initial version.

Only changed contents create versions. Saturn retains at most **10 active versions per file, including the current file**; older archived bytes are removed. Source deletion does not delete a stored copy. An unreadable source does not block healthy sources; the run reports the partial failure and retries after 60 seconds while the regular interval is longer. Copy now also retries immediately. A verified temporary snapshot prevents transferring a file that changed while it was being read. Pluto checks space for that snapshot plus a 16 MiB reserve. Use completed database dump/backup files for consistent database recovery. Symbolic links to regular files copy the target's bytes at the link's original path, including targets outside the selected directory. Directory links, broken/cyclic links and special files are rejected and reported as partial failures; a file is limited to 256 MiB. A link retargeted during snapshotting is retried rather than uploaded under a stale path. Restored link contents are ordinary files; link metadata is not preserved.

### Let's Encrypt certificates

`/etc/letsencrypt/live/<domain>/*.pem` normally links to files in `/etc/letsencrypt/archive/<domain>`. Selecting `/etc/letsencrypt/live` copies those certificate/key bytes under `etc/letsencrypt/live/<domain>/`, and certificate renewal is picked up on the next copy. This behavior follows the operator's 2026-10-11 amendment to Pluto's source contract.

The daemon runs as **pluto**, even when TUI is launched with `sudo`. It needs traversal permission on the `letsencrypt`, `live`, `archive` and domain directories, directory-read permission for traversed source directories, and read permission on the target PEM files. A root-only private key or directory still produces a partial failure; TUI's **Error** shows the failing path and permission guidance. Apply narrowly scoped ACLs through the certificate deployment process and ensure newly renewed files retain the necessary access. Avoid making private keys world-readable. Pluto stores the selected key bytes as ordinary backup files in the assigned Saturn folder, so its storage access must match that sensitivity.

Saturn **Revoke** requires confirmation, invalidates access and preserves stored files and their retained versions. Pluto stops copying when Saturn rejects its credential. Replacement setup codes rotate the existing pipeline credential and preserve its assigned folder. A revoked pipeline is not automatically reactivated or adopted by a new connection of the same name.

## Trust and local operation

Outdoor tokens only permit Kernel `POST /api/v1/register/resolve` for the three keys above. They cannot access internal service APIs, Constitution, the full Register, secrets, operator functions or Wyvern enrollment. Rotation and revoke take effect immediately. This credential discovers Saturn; the separate Saturn capability authorizes only the assigned Pluto folder, with read/write access and no delete or move rights.

Configuration is `/etc/pluto/config.json` (0600), state is `/var/lib/pluto`, and administration uses `/run/pluto/control.sock` (0600). Directory permissions are 0700. Status and fleet reports contain no credentials. Bootstrap runs the daemon as the dedicated `pluto` account. Its protected configuration survives restart and updates. Saturn's discovered origin is retained, so a Kernel outage does not prevent already configured copying. A new enrollment or Kernel connection must pass discovery again.

Configuration updates sync the file and its directory before reporting success. Persistence errors appear in status and are retried. Operational actions are recorded in two bounded audit files (512 KiB rotation) with time, actor, outcome and correlation ID; tokens and file contents are excluded.

```sh
sudo pluto tui
sudo pluto status
sudo pluto update
systemctl status pluto.service
journalctl -u pluto.service
```

## Release preparation

The dedicated repository is `psewdon1m-exocortex/pluto`. Release signing requires the externally provisioned `PLUTO_RELEASE_PRIVATE_KEY` GitHub Actions repository secret; it is never generated or stored in this repository.

```sh
export PLUTO_VERSION=0.1.3
export PLUTO_REPOSITORY=https://github.com/OWNER/pluto
export PLUTO_RELEASE_KEY_FILE=/protected/pluto-release-key.pem
node scripts/build-release.mjs
```

Use an RSA key of at least 3072 bits with RSA-PSS-SHA256 and a 32-byte salt. The builder cross-compiles static Linux amd64/arm64 binaries, embeds the pinned public key, creates a SHA-256 manifest with the `exocortex.release-signature.v1` envelope in `pluto-release.json.sig.json` and generates the exact-version bootstrap. The `pluto-v*` GitHub workflow uses the `PLUTO_RELEASE_PRIVATE_KEY` secret. Keep the private key outside this repository.

Publication first stages the six exact assets as a visible prerelease. Anonymous verification checks the complete inventory, resolves the published tag to the tested commit and compares every downloaded byte (including the key and bootstrap) with the locally verified candidate. The final Part 12 gate must pass before attaching the qualification report, verifying it anonymously and promoting to a normal, latest release. Pluto's TUI discovers updates through `/releases/latest`; a failed candidate remains a prerelease and is not offered as an update. Concurrent runs for one tag are serialized, and published assets are never overwritten. A candidate can be reused only if its downloaded assets match exactly; rebuilding different bytes (including randomized signatures) under the same tag fails closed and requires a new qualified candidate. An existing final report is retained only when source/tag, policy identity and all qualification results match. Artifact names/downloads are scoped to the run and attempt. Each retry must rerun prerequisites and produce fresh receipts; rerunning publication alone cannot borrow artifacts from an earlier attempt. Conflicting reports block promotion. Receipts and reports are preserved as CI artifacts, including hidden evidence files, even when qualification fails.

Use Go 1.26.9 (`go.mod` pins this toolchain). A release build requires a Git checkout and records its source revision and toolchain in the signed manifest. CI pins Actions by SHA and blocks source/binary vulnerabilities and incomplete Part 12 evidence. Its plan includes the published 117 requirements and a checksum-bound local INT-16 supplement. The release workflow verifies the published Kernel 0.3.11 and Saturn 0.2.10 bytes against `.release`, installs the pinned Kernel dependency graph without lifecycle scripts, then records fresh receipts from the exact source commits: real Kernel outdoor-token discovery/rotation/revoke, Saturn HTTP and PostgreSQL isolation/retention/revoke, and install/start/status/restart/stop under systemd using the built amd64 candidate. Anonymous final asset verification binds bytes to the tested revision and the local pinned public key. Production key provisioning remains an operator input.

Updates are operator initiated. Pluto verifies the signed manifest, artifact repository/version, checksum, size and executable version before stopping the service. Systemctl commands have a 30-second deadline and version probes a 5-second deadline. Replacement hard-links the old executable and atomically renames the candidate over the installed path; file/parent fsync and a protected `.update-pending` journal preserve recovery intent until health proof. A failed start/health check restores the previous binary. An interrupted update is reconciled on the next `sudo pluto update`; the flock is released automatically on process exit. A leftover `.previous` without a pending journal requires operator reconciliation and is never overwritten silently. Sources, credentials and the enabled state are preserved. Updates require the bootstrap installation at `/usr/local/bin/pluto` and root privileges.

Bootstrap limits bytes while receiving (including responses without Content-Length), uses up to three bounded download attempts, verifies health/version after startup and removes a failed first-install binary/unit. Existing configuration/state and trust roots are retained. Native release qualification also waits up to 30 seconds for both systemd activation and the control socket before checking status, including after restart. These tests do not replace native systemd/power-loss qualification of the final signed amd64 and arm64 releases.

## Development

```sh
go test -race ./...
go vet ./...
go build ./cmd/pluto
```

No third-party Go modules are required. Supported development/runtime: Linux amd64/arm64. The API and retention tests reside in Saturn; Kernel tests cover outdoor-token restrictions, rotation and revoke. Unversioned local signing fixtures require `PLUTO_ALLOW_UNVERSIONED_TEST_BUILD=1`; their null source identity cannot qualify a production release.

Copy requests allow up to two minutes for response headers while Saturn waits for a storage lease and commits a file, within a five-minute total request deadline. A timeout is reported separately from an unreachable server; the enabled daemon retries a failed copy on its next attempt without revoking its pipeline or replacing the last committed file with partial bytes.
