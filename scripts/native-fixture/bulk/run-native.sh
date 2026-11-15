#!/bin/sh
set -eu
umask 077
owner_sha="$1"
test_sha="$2"
cli_sha="$3"
run="$4"
scope="$5"
as_fixture() { /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs "$@"; }
cid="$(as_fixture cat /input-gate/cid)"
test "$(hostname)" = "$(printf '%s' "$cid" | cut -c 1-12)"
printf 'BULK_WAITING_FOR_HANDOFF\n'
ready=0
for tick in $(seq 1 1200); do if as_fixture test -r /handoff/client/clients.private.json && as_fixture test -r /handoff/client/checkpoint-token; then ready=1; break; fi; sleep 0.25; done
test "$ready" -eq 1 || exit 75
stage() { source=$1; destination=$2; transfer=$3; test ! -e "$destination"; if test -r "$source"; then install -m 0555 "$source" "$destination"; else as_fixture /bin/sh -ec 'cp "$1" "$2"; chmod 0444 "$2"' sh "$source" "$transfer"; install -m 0555 "$transfer" "$destination"; fi; }
stage /owner-input /pluto-native-owner /tmp/bulk-owner
stage /test-input /pluto-native-metadata.test /tmp/bulk-test
stage /cli-input /pluto-current /tmp/bulk-cli
for root in /retained /checkpoint; do test -d "$root" && test ! -L "$root"; test "$(stat -c %u:%g "$root")" = 0:0; test -z "$(ls -A "$root")"; case "$(stat -f -c %T "$root")" in tmpfs|ramfs) exit 75;; esac; done
test "$(df -PB1 /retained | awk 'NR==2{print $4}')" -ge 69793218560
chmod 1777 /retained /checkpoint
as_fixture mkdir -m 0700 /retained/endurance-bulk-current /checkpoint/native
as_fixture mkdir -m 0700 /retained/endurance-bulk-current/client-output
as_fixture install -m 0600 /handoff/client/clients.private.json /retained/endurance-bulk-current/client-output/clients.private.json
as_fixture install -m 0600 /handoff/client/checkpoint-token /retained/endurance-bulk-current/client-output/checkpoint-token
chmod 0755 /retained /checkpoint
pin="$(python3 -I -B /bulk-manifest-writer.py "$cid" "$owner_sha" "$test_sha" "$cli_sha" "$run" "$scope")"
printf 'BULK_MANIFEST_SHA=%s\n' "$pin"
status=0
python3 -I -B /bulk-root-control.py /bulk-manifest.json "$pin" || status=$?
as_fixture /bin/sh -ec '
 evidence=/retained/endurance-bulk-current/evidence
 if test -f "$evidence/a-000001/stdout-prefix.log"; then printf "BULK_GO_CHILD_BEGIN\n"; cat "$evidence/a-000001/stdout-prefix.log"; printf "BULK_GO_CHILD_END\n"; fi
 if test -f "$evidence/owner-final.json"; then printf "BULK_OWNER_FINAL "; cat "$evidence/owner-final.json"; fi
'
printf 'BULK_LAUNCHER_EXIT=%s\n' "$status"
exit "$status"
