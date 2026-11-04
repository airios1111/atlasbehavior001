#!/usr/bin/env bash
# Branch 2 verification (Linux/macOS). Creates .venv if needed, installs the project, runs
# scripts/verify_branch2.py and compares the results with verification/branch2/expected/.
#   ./scripts/verify_branch2.sh            # full run
#   ./scripts/verify_branch2.sh --skip-pytest
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv
fi
.venv/bin/python -m pip install -q -U pip
.venv/bin/python -m pip install -q -e ".[dev]"
.venv/bin/python scripts/verify_branch2.py "$@"
echo
echo "Detailed output: reports/verify-branch2/report.txt"
echo "Diff with:       diff -u verification/branch2/expected/report.txt reports/verify-branch2/report.txt"
