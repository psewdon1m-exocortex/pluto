#!/bin/sh
set -eu
# The release builder embeds the pinned verification key and release URL.
REPOSITORY='@REPOSITORY@'
VERSION='@VERSION@'
PUBLIC_KEY='@PUBLIC_KEY@'
[ "$(id -u)" -eq 0 ] || { echo 'Run this bootstrap with sudo.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Pluto supports Linux only.' >&2; exit 1; }
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo 'Unsupported architecture.' >&2; exit 1;; esac
case "$REPOSITORY$VERSION$PUBLIC_KEY" in *@*) echo 'Use the generated bootstrap from a signed Pluto release.' >&2; exit 1;; esac
for command in curl openssl python3 systemctl useradd install timeout; do command -v "$command" >/dev/null || { echo "Required installer command: $command" >&2; exit 1; }; done
if [ -e /usr/local/bin/pluto ] || [ -e /etc/systemd/system/pluto.service ]; then echo 'Pluto is already installed. Use sudo pluto update.' >&2; exit 1; fi
WORK=$(mktemp -d)
INSTALLING=0
cleanup() {
  code=$?
  trap - EXIT HUP INT TERM
  if [ "$INSTALLING" -eq 1 ]; then
    timeout 30 systemctl disable --now pluto.service || true
    rm -f /usr/local/bin/pluto /etc/systemd/system/pluto.service
    timeout 30 systemctl daemon-reload || true
    echo 'Installation failed; binary/unit removed. Configuration and state retained.' >&2
  fi
  rm -rf -- "$WORK"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
# Enforce byte bounds while receiving, including chunked responses without Content-Length.
download() {
python3 - "$1" "$2" "$3" <<'PY'
import pathlib, subprocess, sys
url, target, maximum = sys.argv[1], pathlib.Path(sys.argv[2]), int(sys.argv[3])
for attempt in range(3):
    child = subprocess.Popen(['curl', '--fail', '--silent', '--show-error', '--location', '--connect-timeout', '10', '--max-time', '120', '--proto', '=https', '--proto-redir', '=https', url], stdout=subprocess.PIPE)
    try:
        size = 0
        with target.open('wb') as stream:
            while chunk := child.stdout.read(65536):
                size += len(chunk)
                if size > maximum: raise ValueError('Release download exceeds byte limit')
                stream.write(chunk)
        if child.wait(timeout=5) == 0: break
        target.unlink(missing_ok=True)
    except BaseException:
        child.kill(); child.wait(); target.unlink(missing_ok=True); raise
else:
    raise SystemExit('Release download failed after three bounded attempts')
PY
}
BASE="$REPOSITORY/releases/download/pluto-v$VERSION"
download "$BASE/pluto-release.json" "$WORK/manifest.json" 65536
download "$BASE/pluto-release.json.sig.json" "$WORK/signature.json" 4096
printf '%s' "$PUBLIC_KEY" | openssl base64 -d -A > "$WORK/public.pem"
openssl pkey -pubin -in "$WORK/public.pem" -outform DER -out "$WORK/public.der"
python3 - "$WORK" <<'PY'
import base64, hashlib, json, pathlib, sys
work = pathlib.Path(sys.argv[1])
assert (work / 'signature.json').stat().st_size <= 4096
envelope = json.loads((work / 'signature.json').read_text())
assert envelope['schema'] == 'exocortex.release-signature.v1' and envelope['algorithm'] == 'RSA-PSS-SHA256'
assert envelope['key_id'] == hashlib.sha256((work / 'public.der').read_bytes()).hexdigest()
(work / 'signature.bin').write_bytes(base64.b64decode(envelope['signature'], validate=True))
PY
openssl dgst -sha256 -verify "$WORK/public.pem" -signature "$WORK/signature.bin" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 "$WORK/manifest.json"
python3 - "$WORK" "$ARCH" "$BASE" "$VERSION" <<'PY'
import json, pathlib, re, sys
work, arch, base, version = sys.argv[1:]
manifest = json.loads(pathlib.Path(work, 'manifest.json').read_text())
assert manifest['schema'] == 1 and manifest['version'] == version
item = manifest['artifacts']['linux-' + arch]
assert item['url'] == base + '/pluto-linux-' + arch
assert re.fullmatch('[a-f0-9]{64}', item['sha256']) and 0 < item['size'] <= 64 * 1024 * 1024
pathlib.Path(work, 'download.url').write_text(item['url'])
PY
download "$(cat "$WORK/download.url")" "$WORK/pluto" 67108864
python3 - "$WORK" "$ARCH" <<'PY'
import hashlib, json, pathlib, sys
work, arch = sys.argv[1:]
item = json.loads(pathlib.Path(work, 'manifest.json').read_text())['artifacts']['linux-' + arch]
binary = pathlib.Path(work, 'pluto').read_bytes()
assert len(binary) == item['size'] and hashlib.sha256(binary).hexdigest() == item['sha256']
PY
chmod 0755 "$WORK/pluto"
[ "$(timeout 5 "$WORK/pluto" --version)" = "$VERSION" ]
install -d -m 0755 /etc/exocortex/release-trust
python3 - "$WORK/public.pem" <<'PY'
import os, pathlib, sys
target = '/etc/exocortex/release-trust/pluto.pem'
key = pathlib.Path(sys.argv[1]).read_bytes()
try:
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
except FileExistsError:
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as existing:
        assert existing.read() == key, 'Installed Pluto trust root differs; an explicit key migration is required'
else:
    with os.fdopen(fd, 'wb') as installed:
        installed.write(key); installed.flush(); os.fsync(installed.fileno())
    directory = os.open(os.path.dirname(target), os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
PY
id pluto >/dev/null 2>&1 || useradd --system --home-dir /var/lib/pluto --shell /usr/sbin/nologin pluto
install -d -o pluto -g pluto -m 0700 /etc/pluto /var/lib/pluto
INSTALLING=1
install -m 0755 "$WORK/pluto" /usr/local/bin/pluto
cat > /etc/systemd/system/pluto.service <<'UNIT'
@SYSTEMD_UNIT@
UNIT
python3 - <<'PY'
import os
for name in ['/usr/local/bin/pluto', '/etc/systemd/system/pluto.service']:
    fd = os.open(name, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)
    fd = os.open(os.path.dirname(name), os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
PY
timeout 30 systemctl daemon-reload
timeout 30 systemctl enable --now pluto.service
python3 - "$VERSION" <<'PY'
import json, subprocess, sys, time
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        value = subprocess.check_output(['/usr/local/bin/pluto', 'status'], timeout=2)
        assert json.loads(value)['version'] == sys.argv[1]
        break
    except (subprocess.SubprocessError, ValueError, AssertionError, KeyError):
        time.sleep(0.25)
else: raise SystemExit('Installed Pluto failed its health/version check')
PY
INSTALLING=0
echo 'Pluto installed. Run sudo pluto tui to configure it. Copying is disabled initially.'
