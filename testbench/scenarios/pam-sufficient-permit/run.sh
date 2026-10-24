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

cat > "$FIXTURE/sshd" <<'EOF'
#%PAM-1.0
auth      sufficient  pam_permit.so
account   required    pam_unix.so
password  required    pam_unix.so
session   required    pam_unix.so
EOF

run_hunter_in_sandbox \
    --tmpfs /etc/pam.d \
    --bind "$FIXTURE/sshd" /etc/pam.d/sshd \
    >"$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" pam "sufficient module in the auth stack"
