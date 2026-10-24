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

# Content is irrelevant -- the check reads filesystem metadata (the
# setuid bit), not the file -- but it needs to exist and be executable
# to look like a real binary.
printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/find"
chmod 4755 "$FIXTURE/find"

# /usr/local/bin replaced wholesale with a tmpfs: it's one of
# SUID_SCAN_DIRS, usually sparse/empty on a real host, and not needed for
# hunter's own dynamic linking, so this is safe and keeps the scenario
# deterministic regardless of what's really in /usr/local/bin here.
run_hunter_in_sandbox \
    --tmpfs /usr/local/bin \
    --bind "$FIXTURE/find" /usr/local/bin/find \
    >"$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" gtfobins "documented GTFOBins privilege-escalation technique"
