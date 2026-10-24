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

# Quoted heredoc ('EOF', not EOF): nothing here is expanded by THIS
# (outer) shell -- $victim_pid, $! etc. all belong to the inner script
# that bwrap runs, not this one. $HUNTER_BIN reaches the inner script as
# a real environment variable via --setenv in run_script_in_sandbox, not
# through string interpolation here.
cat > "$FIXTURE/go.sh" <<'EOF'
#!/bin/bash
set -e
cp /bin/sleep /tmp/victim
/tmp/victim 300 &
victim_pid=$!
rm -f /tmp/victim
# Give /proc a moment to reflect the just-started process before hunter
# reads it.
sleep 0.2
"$HUNTER_BIN" --quiet scan --json > /tmp/output.json
# Not strictly required: when this script (pid 1 of the sandbox's own
# pid namespace) exits, the kernel tears down the whole namespace and
# every process in it, including the backgrounded victim. Explicit for
# clarity anyway.
kill "$victim_pid" 2>/dev/null || true
EOF
chmod +x "$FIXTURE/go.sh"

run_script_in_sandbox "$FIXTURE/go.sh" "$JSON_OUT"

python3 "$TESTBENCH_ROOT/lib/assert_finding.py" "$JSON_OUT" processes "deleted off disk"
