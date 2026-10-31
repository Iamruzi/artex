#!/usr/bin/env bash
# CI-only: one fresh PostgreSQL database per Go package. Never use preview data.
set -euo pipefail
[ "${CI:-}" = "true" ] || { echo "Run this helper only in an ephemeral CI job" >&2; exit 1; }
: "${ARTEX_TEST_PG_BASE:?Set the ephemeral PostgreSQL URL without database/query}"
index=0
packages=$(go list ./...)
while IFS= read -r package; do
  index=$((index + 1))
  database="artex_ci_${index}"
  psql "${ARTEX_TEST_PG_BASE}/postgres?sslmode=disable" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${database}" >/dev/null
  ARTEX_TEST_PG_DSN="${ARTEX_TEST_PG_BASE}/${database}?sslmode=disable" go test -p 1 -count=1 -timeout 5m "$package"
done <<< "$packages"
