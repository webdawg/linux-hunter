# linux-hunter

A Linux compromise detection platform. It answers one question per host:
*has this machine been compromised, and how?*

Most "is this box hacked?" guides boil down to a list of manual commands
(`ps aux`, `netstat`, `ls -la /etc/cron.d`, ...) that you run once, by hand,
after you already suspect something is wrong — using tools a rootkit can
trivially lie to. `linux-hunter` is built the opposite way: never trust the
suspect host's own tools, collect every important fact at least two
independent ways, and treat disagreement between views as the strongest
signal there is. The full design is in [`docs/SPEC.md`](docs/SPEC.md); the
engineering rules every check must follow are in [`CLAUDE.md`](CLAUDE.md).

It ships as a single static-ish Rust binary with no interpreter or package
manager dependency on the target host, which matters when you don't
necessarily trust the target's userland.

## Philosophy: radical transparency

A security tool that tells you "trust me, it's clean" is asking for the
same blind trust that let the compromise happen in the first place.
`linux-hunter` is built to be read, not trusted blindly:

- **Free and open, AGPL-3.0-or-later.** Anyone can read every check, run
  it, fork it, and send a PR — including people checking whether *we'd*
  ever ship a backdoor.
- **Verbose by default, not opt-in.** Every file it opens, every `/proc`
  entry it walks, every permission bit it reads, and the verdict it drew
  from each one is narrated as it happens (`tracing` at `debug` level,
  on unless you pass `--quiet`). A clean scan on a busy host is routinely
  thousands of lines — that's the point. If you can't see what it looked
  at, you can't tell what it might have missed.
- **Coverage honesty.** A check that couldn't run (missing permission,
  missing kernel feature, timeout) must say so explicitly — it is never
  allowed to read as "clean" (CLAUDE.md rule #8).
- **Explainable findings.** Every finding carries its raw evidence and a
  plain-English reason, not just a severity label (CLAUDE.md rule #7).

## Status

Early Phase 1 (triage sweep, per the roadmap below). The check framework is
in place with a first batch of working checks, built before the fuller spec
in `docs/` existed — see `CLAUDE.md`'s "Current implementation status" for
exactly what's wired up versus still on the backlog.

## What it checks today

- **Processes** (`src/checks/processes.rs`)
  - Running binaries that have been deleted from disk since exec
    (`/proc/<pid>/exe` resolving to `... (deleted)`) — a classic sign of a
    dropped payload hiding from on-disk scanners.
  - Processes executing out of world-writable scratch space (`/tmp`,
    `/dev/shm`, `/var/tmp`, ...).
  - A process named like a kernel thread (`kworker/`, `ksoftirqd/`, ...)
    that nonetheless has a real `/proc/<pid>/exe` — genuine kernel threads
    never do; this is a one-line `prctl(PR_SET_NAME)` masquerade.
  - A `cmdline` that's empty, or — a stronger signal — non-empty but every
    byte is `\0` (argv recorded at exec time, then wiped in place).
  - Anonymous (no backing file, no `[heap]`/`[stack]`-style label) memory
    mapped both writable and executable at once: the shape a reflective
    shellcode loader leaves behind, flagged at medium confidence since
    libffi closures and some JITs produce the same shape legitimately.
- **Network** (`src/checks/network.rs`)
  - Listening TCP sockets (from `/proc/net/tcp{,6}`) *and* SCTP endpoints
    (from `/proc/net/sctp/eps`) cross-referenced against the process table
    via `/proc/*/fd`. SCTP specifically: it's invisible to `netstat`
    (deprecated since 2016) but not to `ss` or a raw `/proc` read, which
    makes it an appealing channel for a backdoor banking on old habits.
  - Listeners owned by a deleted or temp-dir binary.
  - Listening sockets with no resolvable owning process, which — when
    running as root and therefore able to enumerate everything — can
    indicate a hidden process.
- **Persistence** (`src/checks/persistence.rs`)
  - Non-empty `/etc/ld.so.preload` (global `LD_PRELOAD`, a common userland
    rootkit technique), plus its immutable (`chattr +i`) flag.
  - World-writable cron/systemd/ld.so.conf.d directories; existence of an
    executable `rc.local`.
  - Recently-modified-entry sweep across cron, systemd units, SysV init
    scripts, udev rules, kernel module autoload files, shell profile
    scripts, and NetworkManager dispatcher hooks (see `AUTOSTART_TREES`).
  - World-writable or recently modified `~/.ssh/authorized_keys` for every
    account in `/etc/passwd`.
  - Shell-history suppression (`HISTFILE=/dev/null`, etc.) in every
    account's shell rc files.
  - Recently modified XDG autostart entries, per-user and system-wide.
- **Accounts** (`src/checks/accounts.rs`)
  - UID 0 duplicates (a second root-equivalent account).
  - Service accounts (uid < 1000) with an interactive shell or an `~/.ssh`
    directory.
  - Empty password hashes in `/etc/shadow`.
  - Passwordless (`NOPASSWD:ALL`) entries in `/etc/sudoers` and
    `/etc/sudoers.d/*`.
  - Membership in root-equivalent groups (`root`/`wheel`/`sudo`/`docker`),
    listed for manual review.
- **Libraries** (`src/checks/libraries.rs`) — parses ELF64-LE directly, no
  `readelf`/`ldd`:
  - "Shadow" libraries: a second, differently-versioned soname for a core
    library (e.g. a fake `libc.so.5` next to the real `libc.so.6`) sitting
    in the same system library directory.
  - Duplicate `DT_NEEDED` entries and the presence of `DT_RPATH`/
    `DT_RUNPATH` on trust-critical binaries (`ps`, `pgrep`, `pkill`,
    `killall`, `pidof`, `cron`/`crontab`, `top`, `lsof`, `rkhunter`,
    `chkrootkit`) — the signature `patchelf --add-needed` leaves behind
    when a binary is patched to silently load a malicious `.so` without
    touching `LD_PRELOAD` at all.
- **GTFOBins** (`src/checks/gtfobins.rs`) — cross-references SUID/SGID
  binaries and sudoers-permitted commands against name lists derived from
  [GTFOBins](https://gtfobins.github.io/), the catalog of ordinary Unix
  binaries (`vim`, `find`, `python`, ...) that double as a root shell once
  they're SUID or sudo-permitted. Scoping `sudo` to "just one command" or
  setting a SUID bit for a narrow reason often hands out root without the
  admin realizing it's on this list.

Each finding carries a severity (`info` / `low` / `medium` / `high` /
`critical`), a one-line summary, and a detail string explaining *why* it
was flagged and how to look closer by hand — this tool is meant to point
you at the right place, not to replace your judgment.

Every scan also prints a **coverage** section: each check's status is
`ok`, `partial` (ran, but some part couldn't be inspected — e.g.
`/proc/<pid>/exe` denied for another user's process without root), or
`failed`. A clean report is only meaningful next to a clean coverage
section — see Philosophy above.

## Usage

```sh
cargo build --release

# One-shot scan. By default this also narrates everything it's inspecting
# to stderr (see Philosophy above) — expect a lot of output.
./target/release/hunter scan

# Same scan, findings only — no play-by-play narration
./target/release/hunter --quiet scan

# One-shot scan, JSON (for feeding into something else)
./target/release/hunter scan --json

# Run continuously, scanning every 300s (the daemon's default mode)
./target/release/hunter watch --interval 300
```

`RUST_LOG` overrides the default narration level if you want something
between "everything" and "--quiet", e.g. `RUST_LOG=hunter=info`.

Most checks need root to see every process's `/proc/<pid>/exe` and `fd`
entries; run unprivileged and you'll get a quieter, less complete picture.

## Architecture

Every check implements the `Check` trait (`src/checks/mod.rs`):

```rust
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self) -> Result<CheckOutput>;
}
```

`CheckOutput` carries both `findings: Vec<Finding>` and `skipped:
Vec<String>` — the latter is how a check admits it couldn't fully inspect
something (coverage honesty, see Philosophy). `checks::all_checks()`
returns the active set; `main.rs` runs them either once (`scan`) or on a
timer (`watch`), turns each `skipped` list into a `Coverage` entry, and
renders both. Adding a new detector means adding a new module and one
line in `all_checks()` — no other wiring required.

## Testing

```sh
cargo test              # unit tests (parsers, ELF reader, sudoers logic, ...)
./testbench/run.sh      # regression tests: plant a real technique, assert hunter catches it
```

The testbench plants techniques in an unprivileged
[bubblewrap](https://github.com/containers/bubblewrap) sandbox — a fresh mount/pid/network
namespace per scenario, real host filesystem mounted read-only, nothing it does can touch
the real system. See [`testbench/README.md`](testbench/README.md) for how that works and
its current scope (userland/filesystem techniques only; needs real VMs once a kernel-level
check exists).

## Documentation

- [`FUTURE_AVENUES.md`](FUTURE_AVENUES.md) — bigger/speculative directions
  (research-ingestion pipeline, GTFOBins-aware checks, a real network
  analysis tool, threat-intel integrations, optional Claude API use)
  that aren't yet scoped into `docs/SPEC.md`'s committed roadmap.
- [`docs/SPEC.md`](docs/SPEC.md) — full architecture, the 14 detection
  modules, anti-evasion design (why every fact needs 2+ independent
  views), scoring, and the four-phase roadmap.
- [`docs/research/persistence-techniques.md`](docs/research/persistence-techniques.md) —
  every known Linux autostart/persistence location; the detection backlog
  for `src/checks/persistence.rs`.
- [`docs/research/hiding-techniques.md`](docs/research/hiding-techniques.md) —
  how attackers hide processes, files, network traffic, modules, and logs,
  and the counter-view for each.
- [`docs/research/malware-case-studies.md`](docs/research/malware-case-studies.md) —
  real malware families (2014 → 2026) mapped to the techniques they used;
  each becomes a test-bench scenario.
- [`third_party/README.md`](third_party/README.md) — vendored upstream tools
  (currently: Lynis) kept for benchmarking only, each under its own
  original license; explains why they're not part of `hunter`'s code path.
- [`docs/research/sources.md`](docs/research/sources.md) — citations for
  all of the above.
- [`CLAUDE.md`](CLAUDE.md) — non-negotiable engineering rules (never shell
  out to host tools, cross-view everything, read-only by default, ...) and
  current implementation status.

## Roadmap

Phase 1 (triage sweep) continues with PAM module hashing, deeper udev
`RUN+=`/`PROGRAM=` attribution, BPF-program enumeration, and package-hash
attribution for persistence/SUID entries (today's checks flag by
heuristic — location, recency, permission bits — not "is this owned by a
package"). Full four-phase roadmap in `docs/SPEC.md` §7:

1. **Triage sweep** — persistence, accounts, process/socket cross-view,
   `ld.so.preload`/PAM/udev/BPF checks, JSON report with coverage honesty.
   *(in progress — see CLAUDE.md's "Current implementation status")*
2. **Deep forensics** — raw-disk parsing, memory capture (AVML/LiME +
   Volatility 3), io_uring/mmap-tamper detection, timeline, dead-box mode.
3. **Continuous** — eBPF/LSM + auditd sensor, baselining, collector,
   correlation, scoring.
4. **Root of trust** — firmware/boot verification, TPM attestation,
   hypervisor introspection, fleet hunting.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
