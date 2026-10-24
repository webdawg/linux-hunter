#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBENCH_ROOT="$(cd "$SCENARIO_DIR/../.." && pwd)"
# shellcheck source=../../lib/sandbox.sh
source "$TESTBENCH_ROOT/lib/sandbox.sh"

if ! command -v gcc >/dev/null 2>&1; then
    echo "gcc is required to build this scenario's fixture and is not on PATH" >&2
    exit 1
fi

FIXTURE="$(mktemp -d)"
JSON_OUT="$(mktemp)"
cleanup() { rm -rf "$FIXTURE" "$JSON_OUT"; }
trap cleanup EXIT

gcc -O0 -o "$FIXTURE/masquerade" "$SCENARIO_DIR/masquerade.c"

cat > "$FIXTURE/go.sh" <<'EOF'
#!/bin/bash
set -e
/tmp/masquerade &
victim_pid=$!
sleep 0.2
"$HUNTER_BIN" --quiet scan --json > /tmp/output.json
kill "$victim_pid" 2>/dev/null || true
EOF
chmod +x "$FIXTURE/go.sh"

run_script_in_sandbox "$FIXTURE/go.sh" "$JSON_OUT" --ro-bind "$FIXTURE/masquerade" /tmp/masquerade

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" processes "matches kernel-thread prefix"
