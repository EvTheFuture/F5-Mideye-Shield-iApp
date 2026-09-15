#!/usr/bin/env bash
# The committed template must be exactly one patch level above the version on
# the upstream (public) master, which is where every change ends up as one PR.
# Usage: tools/check-version.sh [UPSTREAM_TEMPLATE_URL]
set -euo pipefail

TMPL="iApp/MIDEYE_SHIELD.tmpl"
UPSTREAM="${1:-${UPSTREAM_TEMPLATE_URL:-https://raw.githubusercontent.com/EvTheFuture/F5-Mideye-Shield-iApp/master/iApp/MIDEYE_SHIELD.tmpl}}"

version_of() { sed -n 's/^# IAPP_VERSION:[[:space:]]*//p' | head -1; }

OURS="$(version_of < "${TMPL}")"
THEIRS="$(curl -fsSL "${UPSTREAM}" | version_of)"
[ -n "${OURS}" ]   || { echo "check-version: no IAPP_VERSION in ${TMPL}" >&2; exit 1; }
[ -n "${THEIRS}" ] || { echo "check-version: no IAPP_VERSION at ${UPSTREAM}" >&2; exit 1; }

IFS=. read -r MAJ MIN PATCH <<< "${THEIRS}"
WANT="${MAJ}.${MIN}.$((PATCH + 1))"

if [ "${OURS}" != "${WANT}" ]; then
    echo "check-version: template is ${OURS}; upstream master is ${THEIRS}, so it must be ${WANT}. Run: make VERSION=${WANT}" >&2
    exit 1
fi
echo "Template version ${OURS} is one patch above upstream ${THEIRS}. ✔"
