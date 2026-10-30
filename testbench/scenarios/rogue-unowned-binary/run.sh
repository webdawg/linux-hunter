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

printf '#!/bin/sh\nexit 0\n' > "$FIXTURE/rogue"
chmod 755 "$FIXTURE/rogue"

# Deliberately does NOT fake the package database: /var/lib/pacman/local
# (or /var/lib/dpkg/info) comes through from the real, read-only host
# bind in base_bwrap_args, same as any other real system path. /usr/local
# is overlaid (real contents preserved, writes go to a throwaway tmpfs
# upper) purely so we have somewhere writable to plant the rogue binary --
# no real package manager installs there, so it's naturally unowned
# without needing to touch the database at all.
run_hunter_in_sandbox \
    --overlay-src /usr/local/bin --tmp-overlay /usr/local/bin \
    --bind "$FIXTURE/rogue" /usr/local/bin/rogue \
    >"$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" baseline "is executable but not owned by any installed package"
