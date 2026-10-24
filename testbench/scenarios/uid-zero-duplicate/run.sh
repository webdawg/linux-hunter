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

cat > "$FIXTURE/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
evil:x:0:0:eviltwin:/home/evil:/bin/bash
EOF

# Overrides the base sandbox's real /etc/passwd ro-bind (applied first);
# this scenario's bind is supplied after, so it shadows at the same path.
run_hunter_in_sandbox --bind "$FIXTURE/passwd" /etc/passwd > "$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" accounts "more than one account has uid 0"
