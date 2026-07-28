#!/usr/bin/env bash
set -euo pipefail

VERDIKT_BUILD_CONTEXT="${VERDIKT_BUILD_CONTEXT:-../Verdikt}"
VERDIKT_REPOSITORY="${VERDIKT_REPOSITORY:-https://github.com/gaurav-gs7/Verdikt.git}"

case "${VERDIKT_BUILD_CONTEXT}" in
  http://*|https://*|git://*)
    ;;
  *)
    if [[ ! -f "${VERDIKT_BUILD_CONTEXT}/pyproject.toml" ]]; then
      git clone "${VERDIKT_REPOSITORY}" "${VERDIKT_BUILD_CONTEXT}"
    fi
    ;;
esac

cp -n .env.example .env || true
echo "Environment initialized. Run: make up"
