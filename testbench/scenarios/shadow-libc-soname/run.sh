#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBENCH_ROOT="$(cd "$SCENARIO_DIR/../.." && pwd)"
# shellcheck source=../../lib/sandbox.sh
source "$TESTBENCH_ROOT/lib/sandbox.sh"

FIXTURE="$(mktemp -d)"
JSON_OUT="$(mktemp)"
cleanup() { rm -rf "$FIXTURE" "$JSON_OUT"; }
trap cleanup EXIT

TARGET_DIR="$(pick_existing_library_dir)"
echo "fake libc smuggled in under a plausible but wrong soname" > "$FIXTURE/libc.so.5"

mapfile -t PLANT_ARGS < <(plant_fake_library_in_existing_dir "$TARGET_DIR" "$FIXTURE/libc.so.5" libc.so.5)

run_hunter_in_sandbox "${PLANT_ARGS[@]}" >"$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" libraries "soname versions of libc.so"
