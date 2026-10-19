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
src/main.rs            CLI entrypoint (clap: scan, watch) — plays the role of cmd/hunter/
src/report.rs          Finding/Severity types — plays the role of internal/report/
src/checks/mod.rs       Check trait + registry — plays the role of internal/checks/
src/checks/processes.rs   deleted-exe / temp-dir exec / empty-cmdline detection
src/checks/network.rs     listening-socket cross-view (proc/net/tcp{,6} vs /proc/*/fd)
src/checks/persistence.rs ld.so.preload, world-writable cron/systemd dirs, authorized_keys
```

Not yet started: `internal/collect` (shared raw collectors), `internal/crossview` (a real
diff engine — today's cross-view logic lives inline in `network.rs`), `internal/baseline`,
YARA/Sigma `rules/`, and `testbench/`. Binary is still dynamically linked against glibc;
switching the release build to the `x86_64-unknown-linux-musl` target (per rule #2 above) is
outstanding.

Phase 1 progress against the build order: persistence enumeration and socket cross-view have
a first pass; accounts, PAM/udev/BPF-program checks, and the JSON report's coverage-honesty
field (rule #8) are not yet implemented.
