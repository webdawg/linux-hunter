#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared helpers for testbench scenarios. Sourced, not executed directly.
#
# Scenarios plant a technique and run `hunter` inside an unprivileged
# bubblewrap (bwrap) sandbox: a read-only bind of the real host
# filesystem, a fresh tmpfs /etc seeded with only the handful of files
# the checks actually read, and a fresh/empty pid and network namespace.
# Nothing a scenario does inside the sandbox can modify the real host --
# the real root is mounted read-only, and everything the scenario adds
# or overrides lives in the sandbox's private mount namespace, gone the
# moment bwrap exits. This satisfies CLAUDE.md's "isolated, disposable"
# rule for planting techniques without needing real VM infrastructure.
#
# Scope: this covers userland/filesystem techniques only -- anything a
# check reads via plain file I/O. It does NOT provide kernel isolation,
# so it is not suitable for kernel module, eBPF, or anything that needs
# its own kernel to be meaningfully tested; those need real VMs and
# aren't attempted here. See testbench/README.md.

set -uo pipefail

HUNTER_BIN="${HUNTER_BIN:-$TESTBENCH_ROOT/../target/debug/hunter}"

base_bwrap_args() {
    local args=(--ro-bind / / --dev /dev --proc /proc --unshare-all --die-with-parent --tmpfs /etc --tmpfs /tmp)
    local etc_file
    for etc_file in passwd group nsswitch.conf hostname resolv.conf ld.so.cache localtime; do
        args+=(--ro-bind-try "/etc/$etc_file" "/etc/$etc_file")
    done
    printf '%s\n' "${args[@]}"
}

# run_hunter_in_sandbox <extra bwrap arg>...
# Runs `hunter --quiet scan --json` inside the sandbox, base args first so
# scenario-supplied args can shadow them (e.g. overriding /etc/passwd),
# and prints the JSON report on stdout.
run_hunter_in_sandbox() {
    local extra=("$@")
    local base
    mapfile -t base < <(base_bwrap_args)
    bwrap "${base[@]}" "${extra[@]}" -- "$HUNTER_BIN" --quiet scan --json
}

# run_script_in_sandbox <script-file> <json-out-file> <extra bwrap arg>...
# For scenarios that need to plant a live *process* (not just files)
# before running hunter -- e.g. a backgrounded process with a deleted
# exe, or one that's renamed itself via prctl(PR_SET_NAME) -- rather than
# running hunter directly, this binds <script-file> into the sandbox and
# executes it with bash. The script runs in the sandbox's own pid
# namespace (clean and empty save for whatever it spawns itself, thanks
# to --unshare-all in base_bwrap_args), so anything it backgrounds is
# exactly what hunter will see when the script runs it. $HUNTER_BIN is
# available to the script as an environment variable (via --setenv, so
# it survives being embedded in a script written with a quoted heredoc --
# see the process scenarios for why that matters). The sandbox's tmpfs
# disappears when bwrap exits, so the script must write hunter's JSON
# report to /tmp/output.json, which is bound through to <json-out-file>
# on the real host so the caller can read it afterwards. (Bound under
# /tmp specifically, not directly at /, because the real root is
# read-only and /tmp is the one path base_bwrap_args already makes a
# writable tmpfs -- binding a brand-new path directly under / fails the
# same way planting a library directly under /usr/lib does; see
# plant_fake_library_in_existing_dir's comment.)
run_script_in_sandbox() {
    local script_file="$1" json_out="$2"
    shift 2
    local extra=("$@")
    local base
    mapfile -t base < <(base_bwrap_args)
    bwrap "${base[@]}" "${extra[@]}" \
        --setenv HUNTER_BIN "$HUNTER_BIN" \
        --bind "$script_file" /tmp/scenario-script.sh \
        --bind "$json_out" /tmp/output.json \
        -- bash /tmp/scenario-script.sh
}

# Library directories hunter's libraries.rs checks (kept in sync with
# LIBRARY_DIRS in src/checks/libraries.rs). Every Linux system has at
# least one of these for real -- /usr/lib at minimum -- so scenarios that
# need to plant a fake library pick a real, non-symlink one with
# pick_existing_library_dir rather than trying to invent a brand-new
# directory: on a merged-usr distro (Arch, Fedora, modern Debian) /lib is
# just a symlink to /usr/lib, which is part of the real read-only root
# bind, so there is no writable parent to create a new subdirectory
# under. Replacing an existing directory with a tmpfs and repopulating
# its real top-level contents (see plant_fake_library_in_existing_dir)
# works on any layout.
LIBRARY_DIR_CANDIDATES=(
    /usr/lib
    /lib
    /usr/lib64
    /lib64
    /lib/x86_64-linux-gnu
    /usr/lib/x86_64-linux-gnu
    /lib/aarch64-linux-gnu
    /usr/lib/aarch64-linux-gnu
)

pick_existing_library_dir() {
    local dir
    for dir in "${LIBRARY_DIR_CANDIDATES[@]}"; do
        if [ -d "$dir" ] && [ ! -L "$dir" ]; then
            echo "$dir"
            return 0
        fi
    done
    echo "no real (non-symlink) LIBRARY_DIRS directory found on this host -- tried: ${LIBRARY_DIR_CANDIDATES[*]}" >&2
    return 1
}

# plant_fake_library_in_existing_dir <target dir> <fake file> <fake basename>
# Prints bwrap args that overlay <target dir> (an actual overlayfs, real
# contents as the read-only lower layer, writes going to a throwaway
# tmpfs upper -- not binding every real entry individually, which breaks
# past bwrap's argument cap on a directory with thousands of entries like
# /usr/lib) and plant one extra file into it.
plant_fake_library_in_existing_dir() {
    local target_dir="$1" fake_file="$2" fake_basename="$3"
    printf '%s\n' --overlay-src "$target_dir" --tmp-overlay "$target_dir" --bind "$fake_file" "$target_dir/$fake_basename"
}
