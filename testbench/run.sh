#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs every scenario under testbench/scenarios/, each in its own
# unprivileged bwrap sandbox (see testbench/lib/sandbox.sh). Exits
# non-zero if any scenario fails.
set -uo pipefail
TESTBENCH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v bwrap >/dev/null 2>&1; then
    echo "bwrap (bubblewrap) is required and not on PATH" >&2
    exit 1
fi

echo "Building hunter (debug)..."
if ! (cd "$TESTBENCH_ROOT/.." && cargo build --quiet); then
    echo "build failed" >&2
    exit 1
fi

pass=0
fail=0
for scenario_dir in "$TESTBENCH_ROOT"/scenarios/*/; do
    name="$(basename "$scenario_dir")"
    printf '%-32s ' "$name"
    if output="$("$scenario_dir/run.sh" 2>&1)"; then
        echo "PASS"
        pass=$((pass + 1))
    else
        echo "FAIL"
        echo "$output" | sed 's/^/    /'
        fail=$((fail + 1))
    fi
done

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
