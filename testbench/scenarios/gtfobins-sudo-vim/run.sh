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

# A sysadmin trying to narrowly scope sudo access ("alice just needs to
# edit one config file") to a GTFOBins-listed editor.
echo 'alice ALL=(ALL) NOPASSWD: /usr/bin/vim' > "$FIXTURE/99-scoped-vim"

run_hunter_in_sandbox \
    --tmpfs /etc/sudoers.d \
    --bind "$FIXTURE/99-scoped-vim" /etc/sudoers.d/99-scoped-vim \
    >"$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" gtfobins "documented GTFOBins sudo technique"
