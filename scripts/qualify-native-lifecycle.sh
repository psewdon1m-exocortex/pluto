#!/usr/bin/env bash
set -euo pipefail

binary="$(realpath -- "${1:?Pluto binary path is required}")"
version="${2:?Pluto version is required}"
unit_source="$(realpath -- "${3:-packaging/pluto.service}")"
unit=/etc/systemd/system/pluto.service
installed=/usr/local/bin/pluto

test "$(id -u)" -eq 0
test -x "$binary"
test ! -e "$unit"
test ! -e "$installed"
test ! -e /etc/pluto
test ! -e /var/lib/pluto
test ! -e /run/pluto
! getent passwd pluto >/dev/null

cleanup() {
  systemctl stop pluto.service >/dev/null 2>&1 || true
  systemctl disable pluto.service >/dev/null 2>&1 || true
  rm -f -- "$unit" "$installed"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf -- /etc/pluto /var/lib/pluto /run/pluto
  userdel pluto >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

useradd --system --home-dir /var/lib/pluto --shell /usr/sbin/nologin pluto
install -d -o pluto -g pluto -m 0700 /etc/pluto
install -o root -g root -m 0755 "$binary" "$installed"
install -o root -g root -m 0644 "$unit_source" "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl enable --now pluto.service

check_status() {
  local output
  for _ in $(seq 1 30); do
    if ! systemctl is-active --quiet pluto.service; then
      sleep 1
      continue
    fi
    if ! output="$($installed status 2>/dev/null)"; then
      sleep 1
      continue
    fi
    if ! PLUTO_STATUS="$output" PLUTO_EXPECTED_VERSION="$version" python3 - <<'PY'
import json, os
status = json.loads(os.environ['PLUTO_STATUS'])
assert status['version'] == os.environ['PLUTO_EXPECTED_VERSION']
assert status['running'] is False
assert status['connected'] is False
PY
    then
      sleep 1
      continue
    fi
    return 0
  done
  systemctl status --no-pager pluto.service
  return 1
}

check_status
test "$(stat -c '%a' /etc/pluto)" = 700
test "$(stat -c '%a' /var/lib/pluto)" = 700
test "$(stat -c '%a' /run/pluto)" = 700
test "$(systemctl show -p User --value pluto.service)" = pluto
test "$(systemctl show -p Group --value pluto.service)" = pluto
test "$(systemctl show -p NoNewPrivileges --value pluto.service)" = yes
systemd-analyze security --no-pager pluto.service
systemctl restart pluto.service
check_status
systemctl stop pluto.service
test "$(systemctl is-active pluto.service)" = inactive
printf 'Qualified Pluto %s install, start, status, restart, stop and cleanup under systemd.\n' "$version"
