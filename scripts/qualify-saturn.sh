#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "${1:?Saturn checkout path is required}" && pwd -P)"
project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
expected_source="$(tr -d '[:space:]' < "$project/.release/saturn.source-sha")"
expected_version="$(tr -d '[:space:]' < "$project/.release/saturn.version")"

test "$(git -C "$root" rev-parse HEAD)" = "$expected_source"
test "$(node -p "require('$root/package.json').version")" = "$expected_version"
test -n "${PLUTO_TEST_DATABASE_URL:-}"

(
  cd -- "$root"
  corepack enable
  corepack prepare pnpm@11.24.0 --activate
  pnpm install --frozen-lockfile
  pnpm -r --filter @saturn/api... --filter @saturn/protection... build
  pnpm --filter @saturn/database migrate
  pnpm --filter @saturn/api exec vitest run src/pluto.integration.test.ts
)

printf 'Qualified Pluto HTTP, PostgreSQL, isolation, retention and revocation against Saturn %s (%s).\n' \
  "$expected_version" "$expected_source"
