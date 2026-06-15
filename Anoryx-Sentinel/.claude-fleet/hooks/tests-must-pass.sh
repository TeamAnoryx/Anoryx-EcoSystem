#!/usr/bin/env bash
# Stop hook: agents may not declare done while tests are failing.
# Exit 2 = force keep working.  Exit 0 = tests green, may stop.

set -euo pipefail
CWD=$(pwd)

if echo "$CWD" | grep -q 'Anoryx-Sentinel'; then
  TEST_DIR="."
elif [ -d "Anoryx-Sentinel" ] && [ -f "Anoryx-Sentinel/pyproject.toml" ]; then
  TEST_DIR="Anoryx-Sentinel"
else
  exit 0  # Not in a configured subproject yet
fi

if command -v pytest &>/dev/null; then
  if ! (cd "$TEST_DIR" && pytest --tb=short -q 2>&1); then
    echo "Tests are failing. Fix them before stopping." >&2
    exit 2
  fi
fi
exit 0
