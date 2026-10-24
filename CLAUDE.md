# Project: Linux Compromise Detection Platform ("linux-hunter")

You are helping build a **defensive** tool that answers one question per Linux host:
*has this machine been compromised, and how?* It inspects every layer from firmware to
application and is designed so a rootkit cannot simply lie to it.

## Read these first

| File | What it is |
| --- | --- |
| `docs/SPEC.md` | The product specification — architecture, modules, requirements, roadmap |
| `docs/research/persistence-techniques.md` | Catalog of known Linux autostart / persistence tricks: where they live, real-world users, how to detect them |
| `docs/research/hiding-techniques.md` | Catalog of how attackers hide processes, files, network traffic, modules, logs and the malware itself |
| `docs/research/malware-case-studies.md` | Real malware families (2014 → Oct 2026) mapped to the techniques they used |
| `docs/research/sources.md` | Every source the research draws on |

The research catalogs are the **detection backlog**: every row should eventually map to at
least one check in the codebase and one scenario in the test bench.

## Non-negotiable engineering rules

1. **Never trust the suspect host.** Do not shell out to `ps`, `ls`, `netstat`, `ss`, `lsmod`,
   `find`, `top`, `lsof`, `ldd`, `crontab` etc. for trusted results — those are exactly what
   rootkits hook or replace (perfctl shipped trojanized `top`, `ldd`, `lsof`, `crontab`).
   Parse `/proc`, `/sys`, raw files and raw block devices directly with our own code.
2. **Statically linked binary.** No dynamic libc dependency — `/etc/ld.so.preload` rootkits
   inject into every dynamically linked process. Preferred: Go (`CGO_ENABLED=0`) or Rust (`musl`).
3. **Cross-view everything.** Collect each important fact (processes, files, sockets, modules,
   BPF programs, ftrace hooks) at least two independent ways. A disagreement between views is a
   finding in its own right, usually the strongest one.
4. **Don't trust one telemetry pipe.** Modern rootkits (Singularity, SPiCa research) filter
   eBPF ring-buffer events and logs inside the kernel; io_uring (Curing, RingReaper) bypasses
   syscall tracing entirely. Pair eBPF/LSM sensing with auditd, raw reads, memory forensics and
   off-host views.
5. **Read-only by default.** Scanning must never modify the host. Response actions (kill,
   quarantine, isolate) are separate, explicitly approved commands.
6. **Evidence first.** Capture volatile data (memory, sockets, process state) before slow disk
   work; hash every artifact (SHA-256) at collection time.
7. **Explainable findings.** Every finding = check ID, severity, MITRE ATT&CK technique, raw
   evidence, and a plain-English "why this matters".
8. **Coverage honesty.** If a check could not run (permissions, kernel feature missing,
   timeout), report it as *not checked* — never as clean.
9. **Radical transparency.** This project is AGPL and built to be read, not trusted blindly.
   Every check should narrate what it's doing at `debug` level as it runs — every file opened,
   every entry enumerated, every verdict reached — not just emit findings at the end. Verbose
   is the default; `--quiet` (or `RUST_LOG`) is how a user opts *out*, never the reverse. When
   adding a check, add the narration in the same patch, not as a follow-up.

## Suggested repository layout

```
cmd/hunter/            CLI entrypoint (scan, collect, diff, report)
internal/collect/      raw collectors: proc, sysfs, bpf, ftrace, net, fs, raw-disk, memory
internal/checks/       one package per module in SPEC.md §3 (boot, kernel, ebpf, proc, persist, ...)
internal/crossview/    view-diffing engine
internal/baseline/     known-good snapshots + package-hash verification
internal/report/       JSON (OCSF / STIX 2.1) + HTML report
rules/                 YARA, Sigma, IOC lists (versioned)
testbench/             VM recipes that plant each technique for regression tests
docs/                  spec + research
```

## Build order (matches SPEC.md roadmap)

1. **Phase 1 — triage sweep.** Start with `persistence-techniques.md`: enumerate every location,
   attribute each entry to a package or flag it. Then accounts, process cross-view, socket
   cross-view, `ld.so.preload` / PAM / udev / BPF-program checks, JSON report.
2. **Phase 2 — deep forensics.** Raw-disk parse, memory capture hooks (AVML/LiME + Volatility 3),
   io_uring context enumeration, timeline.
3. **Phase 3 — continuous.** eBPF + auditd sensor, collector, correlation, scoring.
4. **Phase 4 — root of trust.** Firmware/boot verification, TPM attestation, hypervisor
   introspection.

## Testing

- Every check needs a unit test with fixture data **and** a test-bench scenario that plants the
  technique on a throwaway VM and asserts detection.
- Plant techniques with Elastic's open-source PANIX persistence tool and Atomic Red Team.
- Only run planted techniques or rootkit samples inside isolated, disposable, network-restricted VMs.

## Current implementation status

Language choice is settled: **Rust**. The "suggested repository layout" above is written in
Go idioms (`cmd/`, `internal/`); this repo instead uses a flat Cargo binary crate:

```
src/main.rs               CLI entrypoint (clap: scan, watch) — plays the role of cmd/hunter/
src/report.rs             Finding/Severity/CheckOutput/Coverage types — internal/report/
src/checks/mod.rs         Check trait + registry — plays the role of internal/checks/
src/checks/processes.rs   deleted-exe / temp-dir exec / permission-gap tracking / kernel-thread
                           name masquerade / all-null-byte argv wipe / anonymous RWX mappings
src/checks/network.rs     listening-socket cross-view (proc/net/tcp{,6} + proc/net/sctp/eps vs
                           /proc/*/fd), unit-tested against the real kernel field layouts
src/checks/persistence.rs ld.so.preload (+ immutable flag), world-writable dirs, rc.local,
                           cron/systemd/init.d/udev/modules-load.d/profile.d/NM-dispatcher
                           recency sweep, authorized_keys, shell history suppression, XDG
                           autostart — see AUTOSTART_TREES for the exact location list
src/checks/accounts.rs    uid-0 duplicates, service-account shell/.ssh posture, empty shadow
                           hashes, sudoers NOPASSWD:ALL, root-equivalent group membership
src/checks/libraries.rs   from-scratch ELF64-LE dynamic-section parser (no readelf/ldd);
                           duplicate-soname shadow libraries; duplicate DT_NEEDED / RPATH on
                           trust-critical binaries (ps/pgrep/pkill/killall/pidof/cron/rkhunter)
src/checks/gtfobins.rs    SUID/SGID binaries and sudoers-permitted commands cross-referenced
                           against embedded GTFOBins-derived name lists (308 SUID, 455 sudo
                           entries; see docs/research/sources.md for provenance/re-derivation)
src/checks/pam.rs         unrecognized PAM modules (curated allowlist, not a baseline);
                           pam_exec.so usage; dangerous `sufficient` control-flag entries in
                           /etc/pam.d/* -- allowlist tuned against a real host's full pam.d
                           (not just one file) after su/rlogin's standard pam_rootok.so/
                           pam_rhosts.so sufficient lines false-positived at High severity
```

Not yet started: `internal/collect` (shared raw collectors), `internal/crossview` (a real
diff engine — today's cross-view logic lives inline in `network.rs`), `internal/baseline`
(package-hash attribution — every persistence entry is currently flagged by recency/location
heuristics only, not "is this owned by a package"), YARA/Sigma `rules/`.
Binary is still dynamically linked against glibc; switching the release build to the
`x86_64-unknown-linux-musl` target (per rule #2 above) is outstanding. BPF-program
enumeration (§3.3 in SPEC.md) has no check yet. ELF parsing in `libraries.rs` only handles
ELF64 little-endian (x86_64/arm64, per SPEC.md §1 scope) — 32-bit and big-endian binaries are
skipped, not flagged as a gap, since they're out of scope.

The PAM `sufficient`-module check (`pam.rs`) is Medium, not High, for the same reason the
RWX-mapping check is Medium not Critical: real testing against a live host surfaced
legitimate uses (su/passwd-family "already root" shortcuts, SSO fallthrough,
service-internal stacks with no real auth by design) that would otherwise false-positive.
Don't re-raise severity or narrow the allowlist without testing against a real /etc/pam.d
again, not just the file used to write the parser's unit tests.

`testbench/` exists now (`./testbench/run.sh`): 7 scenarios, using unprivileged bubblewrap
sandboxing rather than real VMs since this environment has no vagrant/libvirt (qemu +
/dev/kvm are available if that changes). Covers userland/filesystem techniques only — see
`testbench/README.md` for exactly why that's the current boundary and what it'll take to
extend past it (real VMs, once a kernel/eBPF-level check exists to need one).

The anonymous-RWX-mapping check (`processes.rs`) is deliberately Medium, not Critical: it's the
same shape as libffi closure trampolines (ubiquitous in GTK/GObject-Introspection/Python ctypes
apps — small, zero-RSS-until-used) as well as a reflective shellcode loader. Verified by running
it on a live desktop before landing it; don't re-raise the severity without re-checking that.

Coverage honesty (rule #9) is implemented: `Check::run()` returns a `CheckOutput` with both
`findings` and `skipped` (concise reasons like "N pids: permission denied"); `main.rs` turns
`skipped` into a `Coverage` entry per check (`ran`/`partial`/`failed`) printed in every scan
report and JSON output — a clean non-root scan should show `network`/`processes`/`accounts` as
`PARTIAL`, never silently clean.

Phase 1 progress against the build order: persistence enumeration, socket cross-view, and
accounts now have a first pass. Still open: PAM module hashing, udev `RUN+=`/`PROGRAM=`
attribution beyond recency, BPF-program checks, and package-hash attribution for every
persistence/SUID entry (today's checks flag by heuristic, not by "is this owned by a
package").
