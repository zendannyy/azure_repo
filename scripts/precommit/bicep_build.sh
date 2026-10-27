#!/usr/bin/env bash
# Compile Bicep to ARM JSON to catch build failures early.
# Output is written to a temp file and discarded (source JSON is untouched).
set -euo pipefail

if ! command -v az >/dev/null 2>&1; then
  echo "az CLI is required for bicep build. Install Azure CLI and run: az bicep install" >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

failed=0
for file in "$@"; do
  [[ -f "$file" ]] || continue
  out="$tmpdir/$(basename "$file" .bicep).json"
  echo "az bicep build --file $file"
  if ! az bicep build --file "$file" --outfile "$out"; then
    echo "FAIL: bicep build failed for $file" >&2
    failed=1
  fi
done

exit "$failed"
