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
  - Processes with an empty `cmdline`, which is unusual outside of kernel
    threads.
- **Network** (`src/checks/network.rs`)
  - Listening TCP sockets (from `/proc/net/tcp{,6}`) cross-referenced
    against the process table via `/proc/*/fd`.
  - Listeners owned by a deleted or temp-dir binary.
  - Listening sockets with no resolvable owning process, which — when
    running as root and therefore able to enumerate everything — can
    indicate a hidden process.
- **Persistence** (`src/checks/persistence.rs`)
  - Non-empty `/etc/ld.so.preload` (global `LD_PRELOAD`, a common userland
    rootkit technique).
  - World-writable cron/systemd/ld.so.conf.d directories.
  - Recently modified cron entries.
  - World-writable or recently modified `~/.ssh/authorized_keys` for every
    account in `/etc/passwd`.

Each finding carries a severity (`info` / `low` / `medium` / `high` /
`critical`), a one-line summary, and a detail string explaining *why* it
was flagged and how to look closer by hand — this tool is meant to point
you at the right place, not to replace your judgment.

## Usage

```sh
cargo build --release

# One-shot scan, human-readable
./target/release/hunter scan

# One-shot scan, JSON (for feeding into something else)
./target/release/hunter scan --json

# Run continuously, scanning every 300s (the daemon's default mode)
./target/release/hunter watch --interval 300
```

Most checks need root to see every process's `/proc/<pid>/exe` and `fd`
entries; run unprivileged and you'll get a quieter, less complete picture.

## Architecture

Every check implements the `Check` trait (`src/checks/mod.rs`):

```rust
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self) -> Result<Vec<Finding>>;
}
```

`checks::all_checks()` returns the active set; `main.rs` runs them either
once (`scan`) or on a timer (`watch`) and renders the resulting
`Finding`s. Adding a new detector means adding a new module and one line
in `all_checks()` — no other wiring required.

## Documentation

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
- [`docs/research/sources.md`](docs/research/sources.md) — citations for
  all of the above.
- [`CLAUDE.md`](CLAUDE.md) — non-negotiable engineering rules (never shell
  out to host tools, cross-view everything, read-only by default, ...) and
  current implementation status.

## Roadmap

Phase 1 (triage sweep) continues with accounts, PAM/udev/BPF-program
checks, and a JSON report with explicit per-check coverage (ran / skipped /
failed — never silently "clean"). Full four-phase roadmap in
`docs/SPEC.md` §7:

1. **Triage sweep** — persistence, accounts, process/socket cross-view,
   `ld.so.preload`/PAM/udev/BPF checks, JSON report. *(in progress)*
2. **Deep forensics** — raw-disk parsing, memory capture (AVML/LiME +
   Volatility 3), io_uring/mmap-tamper detection, timeline, dead-box mode.
3. **Continuous** — eBPF/LSM + auditd sensor, baselining, collector,
   correlation, scoring.
4. **Root of trust** — firmware/boot verification, TPM attestation,
   hypervisor introspection, fleet hunting.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
