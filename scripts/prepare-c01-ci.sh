#!/usr/bin/env bash
set -euo pipefail
umask 077
project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$project"
artifacts="${1:?fresh absolute artifact directory required}"
release_cli="${2:-}"
bulk_inputs="${PLUTO_GO_CI_BULK_INPUTS:?absolute immutable backend-inputs manifest is required for the fourth real bulk scope}"
[[ "$bulk_inputs" = /* && -f "$bulk_inputs" && ! -L "$bulk_inputs" ]]
[[ "$artifacts" = /* && ! -e "$artifacts" ]]
mkdir -m 700 -- "$artifacts"
[[ "$(go env GOVERSION)" = go1.26.10 ]]
python3 -I -B - "$project" "$artifacts" <<'C01_BUILD_ADMISSION'
import importlib.util,json,shutil,sys
from pathlib import Path
project=Path(sys.argv[1]);artifacts=Path(sys.argv[2])
spec=importlib.util.spec_from_file_location('c01_build_capacity',project/'scripts/run-c01-ci.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
ram=module.host_available_gib();disk=shutil.disk_usage(artifacts).free/2**30
if ram<14 or disk<85:raise SystemExit('C01 build admission requires14GiB free host RAM and85GiB free disk;8GiB RAM reserve is mandatory')
module.publish(artifacts/'build-admission.json',dict(hostRamGiB=ram,diskGiB=disk,reserveRamGiB=8,buildForecastAndMarginGiB=6))
C01_BUILD_ADMISSION
export GOMAXPROCS=2 GOMEMLIMIT=1GiB
python3 -I -B scripts/run-c01-ci.py --record-source "$artifacts/source-inputs.json"
go build -trimpath -p=2 -o "$artifacts/pluto-native-owner" ./internal/testsupport/cmd/pluto-native-owner
go test -race -p=2 -c -o "$artifacts/pluto.test" ./internal/pluto
go test -race -p=2 -c -o "$artifacts/syncstate.test" ./internal/pluto/syncstate
go test -race -p=2 -c -o "$artifacts/network.test" ./internal/network
go test -race -p=2 -c -o "$artifacts/syncproto.test" ./internal/syncproto
go test -race -p=2 -c -o "$artifacts/nativeprocess.test" ./internal/testsupport/nativeprocess
go test -race -p=2 -c -o "$artifacts/custody.test" ./internal/testsupport/nativeprocess/custody
python3 -I -B - "$artifacts" <<'TEST_BINARY_INPUTS'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]);packages={}
for package,name in [('pluto/internal/pluto','pluto'),('pluto/internal/pluto/syncstate','syncstate'),('pluto/internal/network','network'),('pluto/internal/syncproto','syncproto'),('pluto/internal/testsupport/nativeprocess','nativeprocess'),('pluto/internal/testsupport/nativeprocess/custody','custody')]:
 p=root/(name+'.test');p.chmod(0o555)
 with p.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
 packages[package]=dict(path=str(p),bytes=p.stat().st_size,sha256=sha)
with (root/'test-binaries.json').open('x') as f:
 json.dump(dict(schema='pluto.ci-test-binaries.v1',sourceInputsSHA256=hashlib.sha256((root/'source-inputs.json').read_bytes()).hexdigest(),packages=packages),f,indent=2);f.write('\n')
TEST_BINARY_INPUTS
CGO_ENABLED=0 go build -trimpath -p=2 -o "$artifacts/test2json" cmd/test2json
# The read-only collector runs as UID 10001. This compiler-produced public
# executable is a tool input, separate from all private retained test state.
chmod 0555 -- "$artifacts/test2json"
if [[ -z "$release_cli" ]]; then
  CGO_ENABLED=0 go build -trimpath -p=2 -o "$artifacts/pluto-ci" ./cmd/pluto
  release_cli="$artifacts/pluto-ci"
fi
[[ "$release_cli" = /* && -f "$release_cli" ]]
image_tag="pluto-c01-ci-runtime:${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
docker build --platform linux/amd64 --network none -f scripts/native-fixture/Dockerfile.ci -t "$image_tag" scripts/native-fixture
image_id="$(docker image inspect --format '{{.Id}}' "$image_tag")"
{
  printf 'PLUTO_GO_CI_BULK_INPUTS=%s\n' "$bulk_inputs"
  printf 'PLUTO_GO_CI_C01_IMAGE=%s\n' "$image_id"
  printf 'PLUTO_GO_CI_C01_SOURCE_INPUTS=%s\n' "$artifacts/source-inputs.json"
  printf 'PLUTO_GO_CI_C01_TEST_BINARY=%s\n' "$artifacts/pluto.test"
  printf 'PLUTO_GO_CI_SYNCSTATE_TEST_BINARY=%s\n' "$artifacts/syncstate.test"
  printf 'PLUTO_GO_CI_TEST_BINARIES=%s\n' "$artifacts/test-binaries.json"
  printf 'PLUTO_GO_CI_C01_OWNER=%s\n' "$artifacts/pluto-native-owner"
  printf 'PLUTO_GO_CI_C01_CONVERTER=%s\n' "$artifacts/test2json"
  printf 'STAGE3_PLUTO_BINARY=%s\n' "$release_cli"
  printf 'GOMAXPROCS=2\nGOMEMLIMIT=1GiB\n'
} > "$artifacts/c01.env"
