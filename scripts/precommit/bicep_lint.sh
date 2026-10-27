#!/usr/bin/env bash
# Lint staged/passed Bicep files with az bicep lint.
# Warnings (e.g. BCP174) do not fail; compiler/linter errors do.
set -euo pipefail

if ! command -v az >/dev/null 2>&1; then
  echo "az CLI is required for bicep lint. Install Azure CLI and run: az bicep install" >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  exit 0
fi

failed=0
for file in "$@"; do
  [[ -f "$file" ]] || continue
  echo "az bicep lint --file $file"
  if ! az bicep lint --file "$file"; then
    echo "FAIL: bicep lint errors in $file" >&2
    failed=1
  fi
done

exit "$failed"
