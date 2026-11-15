#!/bin/sh
set -eu
umask 077
owner_sha="$1"; test_sha="$2"; cli_sha="$3"; run="$4"; scope="$5"; retained_root="$6"; checkpoint_root="$7"; case="$8"
IFS= read -r cid
as_fixture() { /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs "$@"; }
stage() { source=$1; destination=$2; transfer=$3; test ! -e "$destination" && test ! -L "$destination"; if test -r "$source"; then install -m 0555 "$source" "$destination"; else as_fixture /bin/sh -ec 'cp "$1" "$2"; chmod 0444 "$2"' sh "$source" "$transfer"; install -m 0555 "$transfer" "$destination"; fi; }
stage /owner-input /pluto-native-owner /tmp/owner-ci-owner
stage /test-input /pluto-native-metadata.test /tmp/owner-ci-test
stage /cli-input /pluto-current /tmp/owner-ci-cli
test -d /retained && test ! -L /retained && test "$(stat -c %u:%g /retained)" = 0:0 && test -z "$(ls -A /retained)"
case "$(stat -f -c %T /retained)" in tmpfs|ramfs) exit 75;; esac
test "$(df -PB1 /retained | awk 'NR==2{print $4}')" -ge 69793218560
chmod 1777 /retained
as_fixture mkdir -m 0700 "$retained_root"
chmod 0755 /retained
pin="$(python3 -I -B /native-prepared-manifest-writer.py "$cid" "$owner_sha" "$test_sha" "$cli_sha" "$run" "$scope" "$retained_root" "$case")"
printf 'NATIVE_OWNER_MANIFEST_SHA=%s\n' "$pin"
status=0
as_fixture /pluto-native-owner /native-owner-manifest.json "$pin" || status=$?
as_fixture /bin/sh -ec 'evidence="$1/evidence"; if test -f "$evidence/a-000001/stdout-prefix.log"; then cat "$evidence/a-000001/stdout-prefix.log"; fi; if test -f "$evidence/owner-final.json"; then cat "$evidence/owner-final.json"; fi' sh "$retained_root"
printf 'NATIVE_OWNER_LAUNCHER_EXIT=%s\n' "$status"
exit "$status"
