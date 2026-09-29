#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

files=()
if [[ "${1:-}" == --staged ]]; then
    while IFS= read -r -d '' file; do
        files+=("$file")
    done < <(git diff --cached --name-only --diff-filter=ACMR -z -- 'scripts/*.py' ruff.toml scripts/lint/python.sh)
    [[ ${#files[@]} -gt 0 ]] || exit 0
    command -v uv >/dev/null 2>&1 || exit 0
fi

uv tool run ruff@0.15.7 check scripts
uv tool run ruff@0.15.7 format --check scripts
