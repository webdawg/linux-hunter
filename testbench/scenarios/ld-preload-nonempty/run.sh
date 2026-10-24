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

echo "/home/user/hoxha/libhide.so" > "$FIXTURE/ld.so.preload"

run_hunter_in_sandbox --bind "$FIXTURE/ld.so.preload" /etc/ld.so.preload > "$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" persistence "ld.so.preload is non-empty"
