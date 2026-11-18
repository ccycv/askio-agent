#!/usr/bin/env bash
# Fail if any Go file needs gofmt, except the files that were already
# unformatted when CI was added (scripts/gofmt-legacy.txt). New and changed
# code must be formatted; reformatting the legacy files is a separate change.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "${BASH_SOURCE[0]}")/.."

unformatted="$(gofmt -l . | sort)"
new="$(comm -23 <(printf '%s\n' "${unformatted}" | sed '/^$/d') <(sort scripts/gofmt-legacy.txt))"
if [[ -n "${new}" ]]; then
  echo "gofmt needed:" >&2
  printf '%s\n' "${new}" >&2
  exit 1
fi
fixed="$(comm -13 <(printf '%s\n' "${unformatted}" | sed '/^$/d') <(sort scripts/gofmt-legacy.txt))"
if [[ -n "${fixed}" ]]; then
  echo "note: now formatted, can be removed from scripts/gofmt-legacy.txt:"
  printf '%s\n' "${fixed}"
fi
echo "gofmt: ok ($(printf '%s\n' "${unformatted}" | sed '/^$/d' | wc -l | tr -d ' ') legacy files tolerated)"
