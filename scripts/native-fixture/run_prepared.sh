#!/bin/sh
set -eu
umask 077

owner_sha="${1:?owner SHA required}"
test_sha="${2:?test SHA required}"
cli_sha="${3:?CLI SHA required}"
run="${4:?run identifier required}"
scope="${5:?scope identifier required}"
retained_root="${6:?fresh retained root required}"
checkpoint_root="${7:?separate checkpoint root required}"
IFS= read -r cid

as_fixture() {
    /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs "$@"
}

stage() {
    source=$1
    destination=$2
    transfer=$3
    test ! -e "$destination"
    test ! -L "$destination"
    if test -r "$source"; then
        install -m 0555 "$source" "$destination"
    else
        as_fixture /bin/sh -ec 'cp "$1" "$2"; chmod 0444 "$2"' sh "$source" "$transfer"
        install -m 0555 "$transfer" "$destination"
    fi
}

stage /owner-input /pluto-native-owner /tmp/native-prepared-owner
stage /test-input /pluto-native-metadata.test /tmp/native-prepared-test
stage /cli-input /pluto-current /tmp/native-prepared-cli
stage /backup-worker-input /native-prepared-worker.py /tmp/native-prepared-worker
stage /backup-control-input /native-prepared-control.py /tmp/native-prepared-control
test -d /retained
test ! -L /retained
test "$(stat -c %u:%g /retained)" = "0:0"
test -z "$(ls -A /retained)"
filesystem="$(stat -f -c %T /retained)"
case "$filesystem" in tmpfs|ramfs) exit 75 ;; esac
available="$(df -PB1 /retained | awk 'NR == 2 { print $4 }')"
case "$available" in ""|*[!0-9]*) exit 75 ;; esac
printf 'NATIVE_PREPARED_DISK_FILESYSTEM=%s\nNATIVE_PREPARED_DISK_FREE_BYTES=%s\n' "$filesystem" "$available"
test "$available" -ge 69793218560 || exit 75
chmod 1777 /retained
as_fixture mkdir -m 0700 "$retained_root"
chmod 0755 /retained
test -d "$checkpoint_root" && test ! -L "$checkpoint_root"
test "$(stat -c %u:%g "$checkpoint_root")" = "0:0"
test -z "$(ls -A "$checkpoint_root")"
chmod 0700 "$checkpoint_root"
chown 10001:10001 "$checkpoint_root"
pin="$(python3 -I -B /native-prepared-manifest-writer.py "$cid" "$owner_sha" "$test_sha" "$cli_sha" "$run" "$scope" "$retained_root" "$checkpoint_root")"
printf 'NATIVE_PREPARED_MANIFEST_SHA=%s\n' "$pin"


status=0
/usr/bin/setpriv --bounding-set=-chown --inh-caps=-all --ambient-caps=-all --no-new-privs python3 -I -B /native-prepared-control.py /native-prepared-manifest.json "$pin" || status=$?
as_fixture /bin/sh -ec '
    evidence="$1/evidence"
    if test -f "$evidence/a-000001/stdout-prefix.log"; then
        printf "NATIVE_PREPARED_GO_CHILD_BEGIN\n"
        cat "$evidence/a-000001/stdout-prefix.log"
        printf "NATIVE_PREPARED_GO_CHILD_END\n"
    fi
    if test -f "$evidence/owner-final.json"; then
        printf "NATIVE_PREPARED_OWNER_FINAL "
        cat "$evidence/owner-final.json"
    fi
' sh "$retained_root"
printf 'NATIVE_PREPARED_LAUNCHER_EXIT=%s\n' "$status"
for pair in "/native-prepared-manifest.json:fixture-manifest.json" "/native-prepared-backup-receipt.json:fault-receipt.json"; do
    source=${pair%%:*}
    target="$retained_root/${pair#*:}"
    if test -f "$source"; then
        as_fixture /bin/sh -ec 'test ! -e "$2" && test ! -L "$2"; install -m 0444 "$1" "$2"' sh "$source" "$target"
    fi
done
exit "$status"
