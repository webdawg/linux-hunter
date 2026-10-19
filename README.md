# linux-defense

A continuous compromise-detection daemon for Linux hosts, written in Rust.

Most "is this box hacked?" guides boil down to a list of manual commands
(`ps aux`, `netstat`, `ls -la /etc/cron.d`, ...) that you run once, by hand,
after you already suspect something is wrong. `linux-defense` turns that
checklist into a long-running daemon that watches continuously and flags
things worth a human look, so you find out *before* someone tells you.

It ships as a single static-ish binary with no interpreter or package
manager dependency on the target host, which matters when you don't
necessarily trust the target's userland.

## Status

Early scaffold. The check framework is in place with a first batch of
working checks; many more are planned (see Roadmap).

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
./target/release/linux-defensed scan

# One-shot scan, JSON (for feeding into something else)
./target/release/linux-defensed scan --json

# Run continuously, scanning every 300s (the daemon's default mode)
./target/release/linux-defensed watch --interval 300
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

## Roadmap

- Filesystem integrity: hash key system binaries against a stored
  baseline and flag drift.
- Kernel: enumerate loaded modules and flag unsigned/unknown ones.
- Auth logs: parse `journald`/`auth.log` for brute-force patterns, new
  sudoers, unexpected root logins.
- Baseline diffing: persist scan state so later runs report *changes*,
  not just the current snapshot.
- Alerting: webhook/syslog output for `high`/`critical` findings instead
  of (or in addition to) log lines.
- Config file for tuning watch paths, severities, and check selection.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
