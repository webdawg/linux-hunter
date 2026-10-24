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

mkdir -p "$FIXTURE/cron.d"
chmod 0777 "$FIXTURE/cron.d"

run_hunter_in_sandbox --bind "$FIXTURE/cron.d" /etc/cron.d > "$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" persistence "/etc/cron.d is world-writable"
