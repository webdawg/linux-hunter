# Testbench

Regression tests that plant a real technique and assert `hunter` catches it, per
`CLAUDE.md`'s testing section and `docs/SPEC.md` §7's validation requirements.

```sh
./testbench/run.sh
```

## How isolation works here

`docs/SPEC.md` and `CLAUDE.md` describe the testbench as disposable VMs — "Only run
planted techniques or rootkit samples inside isolated, disposable, network-restricted
VMs." This environment has no VM infrastructure (no vagrant, no libvirt/virsh), so v1
uses unprivileged **bubblewrap** (`bwrap`) sandboxing instead: a fresh mount, pid, and
network namespace per scenario, with the real host filesystem bound in **read-only**
and only the specific files/directories a scenario needs to fake overlaid on top
(`--bind`, `--tmp-overlay`) in that sandbox's *private* mount namespace. Nothing a
scenario does can touch the real host — verified: the real system's `/etc/ld.so.preload`,
`/etc/passwd`, `/etc/sudoers.d/`, and library directories are provably untouched after
every scenario runs, with no root or sudo required. See `testbench/lib/sandbox.sh` for
the mechanics.

**This covers userland/filesystem techniques only.** A namespace sandbox shares the
host kernel — it provides no isolation for anything that needs its own kernel to be
meaningfully (and safely) tested: LKM rootkits, eBPF programs, ftrace hooks, anything
in `docs/SPEC.md` §3.2/§3.3. Every check that exists today (`src/checks/*.rs`) is
userland/filesystem-only, so this gap doesn't block anything yet — it will the moment a
kernel-level check gets written. At that point this testbench needs real VMs
(`qemu-system-x86_64` plus `/dev/kvm` are available in this environment even though
vagrant/libvirt aren't; that's the natural next step, not a from-scratch problem).

## Layout

```
testbench/
  run.sh              Runs every scenario, prints a pass/fail summary
  lib/
    sandbox.sh         Shared bwrap helpers: base sandbox args, library-dir overlay helper,
                       run_script_in_sandbox for scenarios that plant a live process
    assert_finding.py  Checks hunter's JSON report for an expected finding
  scenarios/
    <name>/
      run.sh           Self-contained: plant fixture(s), run hunter in the sandbox, assert
      README.md        What technique, which research doc it maps to, what's expected
```

Each scenario's `run.sh` can also be run standalone (`./testbench/scenarios/<name>/run.sh`)
for debugging one at a time; it's a plain shell script with `set -euo pipefail`, no
hidden framework state.

## Current scenarios

| Scenario | Technique | Check |
| --- | --- | --- |
| `ld-preload-nonempty` | Global `LD_PRELOAD` via `/etc/ld.so.preload` | `persistence.rs::check_ld_preload` |
| `world-writable-cron-d` | World-writable persistence directory | `persistence.rs::check_world_writable_dirs` |
| `shadow-libc-soname` | Fake-versioned library next to the real one | `libraries.rs::check_shadow_libraries` |
| `gtfobins-suid-find` | SUID binary with a documented GTFOBins technique | `gtfobins.rs::check_suid_binaries` |
| `gtfobins-sudo-vim` | Sudo access scoped to a GTFOBins-listed binary | `gtfobins.rs::check_sudoers_commands` |
| `uid-zero-duplicate` | Second root-equivalent (uid 0) account | `accounts.rs::check_uid_zero_duplicates` |
| `pam-sufficient-permit` | `sufficient pam_permit.so` auth bypass pattern | `pam.rs::check_pam_config` |
| `deleted-exe-process` | Process running from a binary deleted off disk | `processes.rs` (deleted-exe branch) |
| `kernel-thread-masquerade` | Userspace process renamed via `prctl` to look like a kernel thread | `processes.rs` (`KERNEL_THREAD_NAME_PREFIXES`) |
| `rogue-unowned-binary` | Dropped binary not owned by any installed package | `baseline.rs::check_unowned_executables` |

Each scenario's own `README.md` names the exact research-doc row it corresponds to.
`deleted-exe-process` and `kernel-thread-masquerade` are the first two that plant a live
*process* rather than just files — see `run_script_in_sandbox` in `testbench/lib/sandbox.sh`
for how that works (a script runs inside the sandbox's own pid namespace, backgrounds
whatever it needs to, then runs hunter against it; JSON output is bound back out to a real
file on the host so it survives the sandbox tearing down).

## Known gaps

- **No negative-control assertion per scenario.** Each scenario asserts the expected
  finding appears; none assert it's *absent* from a clean run (though a clean baseline
  run was checked by hand while building this — see commit history). Worth adding if a
  check's false-positive rate ever becomes a question.
- **No network scenario yet** (an SCTP listener, or a listening socket with no
  resolvable owner). `run_script_in_sandbox` already provides what this needs (plant a
  process that opens the socket before hunter runs) — same pattern as the process
  scenarios, just not built yet.
- **No DT_NEEDED-injection scenario.** The technique `libraries.rs::check_trust_critical_binaries`
  is built for (`patchelf --add-needed` producing a duplicate dependency entry) needs a
  hand-crafted ELF with a duplicate `DT_NEEDED` tag; `patchelf` isn't installed in this
  environment and wasn't worth blocking the rest of the testbench on. Tracked, not
  forgotten — this is the check most directly inspired by the 2600 article.
- **Coverage, not exhaustiveness.** Ten scenarios prove the harness works end-to-end and
  cover seven of the eight check modules (`persistence`, `libraries`, `gtfobins`,
  `accounts`, `pam`, `processes`, `baseline`); only `network` has zero scenarios now.

## Adding a scenario

1. `mkdir testbench/scenarios/<name>`
2. Write `run.sh`: build a fixture in `mktemp -d`, construct the bwrap args needed to
   plant it (reuse `testbench/lib/sandbox.sh` helpers where they fit), call
   `run_hunter_in_sandbox` with those args, assert on the JSON output with
   `testbench/lib/assert_finding.py`, clean up via `trap`.
3. Write `README.md`: the technique, which `docs/research/` row it maps to, what's
   planted, what finding is expected, which check is under test.
4. `chmod +x run.sh`, run it standalone first, then run the full suite.
