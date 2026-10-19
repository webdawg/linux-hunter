# Linux Compromise Detection Platform — Specification

*Version 0.2 · 2026-10-18*

## 1. Purpose and principles

The platform answers one question per Linux host — "has this machine been compromised, and how?" — by inspecting every layer from firmware to application, from a vantage point the attacker cannot control.

**On "exhaustive and perfect."** No detector is perfect: an attacker with firmware or hypervisor control can, in principle, lie to anything running above them. This spec therefore aims for *defence in depth of detection*: every layer is checked from at least two independent viewpoints, so an attacker must defeat all of them at once to stay hidden. The target is to make undetected persistence expensive, not to promise it is impossible.

**Scope.** Linux servers, workstations, VMs and container hosts (x86_64 and arm64; Debian/Ubuntu, RHEL/Fedora/Rocky/Alma, SUSE, Arch, Alpine). Network appliances running Linux (e.g. F5 BIG-IP) are in scope for agentless/offline analysis where the vendor permits. Out of scope for v1: Android, embedded RTOS.

**Design principles**

- **Never trust the suspect host.** The suspect kernel, binaries, libraries and logs are evidence, not tools. Analysis uses statically linked tooling brought in, ideally from a trusted boot or offline mount.
- **Cross-view everything.** Every fact is collected two or more ways and diffed. Disagreement is itself the strongest signal.
- **Preserve before you touch.** Volatile evidence is captured first, hashed, and stored read-only, following order of volatility (RFC 3227).
- **Known-good over known-bad.** Signatures catch yesterday's tools; deviation from a verified baseline catches novel ones. Both are used. Static signatures alone are known to miss trivially modified rootkits.
- **Explainable findings.** Every alert carries raw evidence, the check that produced it, why it matters, and its ATT&CK technique.
- **Read-only by default.** Containment and remediation are separate, explicitly approved actions.

## 2. Architecture

Three independent sources of truth feed a write-once evidence store; one analysis engine diffs them against each other before scoring and reporting.

```
 ┌──────────────────────────┐
 │ Suspect host             │  eBPF/auditd sensor, static scanner,
 │                          │  memory + disk capture
 └────────────┬─────────────┘
              │
 ┌────────────▼─────────────┐     ┌──────────────────┐     ┌────────────────────┐     ┌───────────────┐
 │ Independent views        │────▶│ Evidence store   │────▶│ Analysis engine    │──┬─▶│ Reports       │
 │ trusted boot, VM snapshot│     │ write-once,      │     │ cross-view diff    │  ├─▶│ SIEM / SOAR   │
 │ external scan, remote log│     │ SHA-256 hashed,  │     │ rules, YARA, Sigma │  └─▶│ Response      │
 └────────────▲─────────────┘     │ chain of custody │     │ ATT&CK correlation │     │ (opt-in)      │
              │                   └──────────────────┘     │ host scoring       │     └───────────────┘
 ┌────────────┴─────────────┐                              └────────────────────┘
 │ Known-good and intel     │  signed baselines, vendor hashes,
 │                          │  IOCs, YARA, Sigma
 └──────────────────────────┘
```

**Operating modes**

- **Live triage** — static scanner runs on the running host; fast, but the kernel may be lying.
- **Continuous** — eBPF/LSM + auditd sensor streams events to the collector in real time.
- **Dead-box** — host booted from trusted media, or VM disk and RAM snapshotted from the hypervisor; slowest, highest assurance.
- **Agentless** — collection over SSH with a pushed static binary, for hosts that cannot carry a sensor.

## 3. Detection modules

Fourteen modules cover the host from firmware up. The full technique-level backlog for modules 3.5 and the hiding aspects of 3.2–3.10 lives in `docs/research/`.

### 3.1 Firmware and boot chain
- UEFI Secure Boot state, enrolled keys (PK, KEK, db, dbx), MOK list; unknown keys or stale dbx (BlackLotus-class bootkits).
- Firmware image dump and hash vs vendor release (CHIPSEC, fwupd/LVFS); SPI flash write-protect and BIOS lock bits.
- TPM 2.0 PCRs and measured-boot event log vs expected; IMA measurement log.
- ESP contents: shim, GRUB, systemd-boot, UKIs — hashes and signatures; extra `.efi` files.
- GRUB config / kernel cmdline: `init=`, `rd.break`, `module.sig_enforce=0`, lockdown disabled, `selinux=0`.
- initramfs: unpack and diff every file against the package that built it.
- Appliance upgrade images: persistence that survives vendor upgrade (PoisonedRefresh, 2026).
- BMC/IPMI firmware version and accounts where reachable.

### 3.2 Kernel integrity and rootkits
- Modules: `/proc/modules` vs `/sys/module` vs memory carving; unsigned / out-of-tree modules; taint flags — **and** check whether the taint mask is being reset (Singularity normalizes it).
- Syscall table, IDT, ftrace hooks (`enabled_functions`, `touched_functions`), kprobes, kretprobes, live patches, `kallsyms` anomalies. Expect rootkits to filter these procfs/tracefs views; confirm from memory.
- Hidden-module techniques: list unlinking, kobject removal, `getdents64`/`filldir`/`tcp4_seq_show` hooks.
- Lockdown mode, `kexec`, `/dev/mem`, `kernel.modules_disabled`; attempts to block ftrace being disabled.
- Families: Diamorphine, Reptile, Suterusu, Adore-ng, Drovorub, PUMAKIT, Singularity, VoidLink LKM, SIXZUT, and successors.

### 3.3 eBPF, BPF and tracing abuse
- Enumerate every BPF program, map, link (`bpf()` syscall directly, plus `bpftool` as a second view); pinned objects in `/sys/fs/bpf`. LinkPro hooks `sys_bpf` to hide its own programs — so also count via memory and via `/proc/*/fdinfo` BPF fds.
- Flag tracepoint/kprobe programs on `getdents*`, `bpf`, `execve`; XDP/TC programs on interfaces; LSM programs; use of `bpf_probe_write_user`, `bpf_override_return`.
- Classic BPF socket filters on raw/packet sockets (BPFDoor) — inspect with `ss -0pb` equivalent and from `/proc/net/packet`.
- Hooking of `bpf_ringbuf_submit` / perf output that silently drops security telemetry.
- Diff against expected agents (Cilium, Falco, Tetragon, systemd, observability tools).

### 3.4 Processes and memory
- Process list from `/proc` readdir, from PID brute force, from scheduler/task list in memory; any disagreement = hidden process.
- Per process: `/proc/PID/exe` `(deleted)`, `memfd:` executables, `comm` vs `cmdline` vs exe mismatch, fake kernel-thread names with a userspace parent, deleted-inode execution.
- Memory maps: anonymous RWX, injected `.so`, `ptrace` attachment, `LD_PRELOAD` in `/proc/PID/environ`, **file-backed mappings whose in-memory content differs from disk** (PoisonedRefresh mmap tampering).
- **io_uring contexts** per process (`/proc/PID/fdinfo` for `anon_inode:[io_uring]`, memory walk of `io_ring_ctx`): flag processes doing network/file ops via io_uring that normally wouldn't.
- Parent/child anomalies: shells from web servers, DBs, cron, PAM-using daemons.
- Behaviour that pauses when users log in (perfctl), cryptominer signatures.

### 3.5 Persistence mechanisms
Every autostart location in `docs/research/persistence-techniques.md` is enumerated; each entry is attributed to a package or an approved change, otherwise it's a finding.

### 3.6 Accounts, authentication and privilege
- `passwd`/`shadow`/`group`: UID 0 duplicates, new accounts, interactive shells or `.ssh` dirs on service accounts, changed hashes.
- PAM stack and every module file vs package hashes (Plague, QLNX, perfctl hook PAM).
- sudoers, polkit rules, file capabilities, SUID/SGID inventory vs baseline.
- SSH: `authorized_keys` (all users incl. system accounts), `command=` options, `AuthorizedKeysCommand`, `sshd_config` `Match` blocks, host key changes.
- Login history from `wtmp`/`btmp`/`lastlog`/journald, compared to remote copies (PAM backdoors suppress local auth logs).
- Credential theft traces: reads of `shadow`, SSH keys, cloud credential files, `.git-credentials`, `.npmrc`, kubeconfig.

### 3.7 Filesystem integrity
- Verify every packaged file against the package DB **and** independent vendor repo hashes (the local DB can be edited).
- Non-package ELF anywhere, especially `/tmp`, `/dev/shm`, `/var/tmp`, `/run`, `/var/log`, `/lib/udev`, home dirs.
- Hidden names (dots, spaces, Unicode look-alikes); files hidden from `readdir` but present on raw-disk parse.
- `lsattr` immutable/append-only flags (Auto-color protects `ld.so.preload`); xattrs; bind mounts over `/proc/PID` or binaries.
- Timestomping: mtime vs ctime vs journal vs `crtime`.
- YARA on the whole filesystem; web roots for webshells.

### 3.8 Software supply chain
- Repos and signing keys; unknown repos or keys.
- Installed versions vs OSV / distro advisories, CISA KEV first.
- Language ecosystems and community repos (pip, npm, AUR, cargo, Go) — typosquats, known-malicious, ownership changes (AUR 2026 incident).
- Compromised-upstream checks (xz-utils-style): unexpected libraries linked into `sshd`, SBOM diffs.
- Presence of compilers on servers (QLNX compiles its rootkit on-host with `gcc`).

### 3.9 Network
- Listening sockets via `/proc/net/*`, via netlink `sock_diag`, via memory, and via an external port scan; diff all four.
- Raw/packet sockets with attached filters; promiscuous interfaces; XDP/TC programs.
- Firewall rules (nftables, iptables, eBPF), routing, `/etc/hosts`, `resolv.conf`, proxies.
- Tunnels/covert channels: unexpected tun/tap/WireGuard, DNS tunnelling, ICMP payloads, magic-packet patterns, beacon periodicity, anomalous TCP window values (LinkPro).
- Local Unix-socket shells with no TCP listener (PoisonedRefresh, perfctl).
- Outbound reputation: C2, Tor, mining pools, newly registered domains.

### 3.10 Logs and audit trail
- journald, syslog, auditd, app logs: gaps, truncation, out-of-order timestamps, FSS sealing.
- Log wiping: zeroed `wtmp` records, cleared histories, `HISTFILE=/dev/null`.
- Kernel log read-side filtering (`dmesg`/`journalctl` lying): compare against remote syslog and the raw ring buffer from memory.
- Remote copies are the authority; events missing locally but present remotely = strong indicator.

### 3.11 Containers and virtualisation
- Runtimes (Docker, containerd, Podman, CRI-O): containers, images (Trivy/Grype), privileged containers, host mounts, exposed `docker.sock`.
- Kubernetes: RBAC, service-account tokens, admission webhooks, DaemonSets, static pods, malicious images (LinkPro arrived via a Docker image on EKS).
- Escape traces: host-path writes, `nsenter`, cgroup `release_agent`, `core_pattern`.

### 3.12 Cloud and identity plane
- IMDS access patterns (IMDSv1, token theft), attached roles and their recent API activity.
- Cloud audit logs correlated with host events.

### 3.13 Memory forensics
- Full RAM capture (AVML or LiME), offline Volatility 3 with matching symbols.
- Hidden processes, syscall/ftrace hooks, injected code, io_uring contexts, BPF programs, bash history in memory, socket structures, module carving.

### 3.14 Threat intelligence and signatures
- IOCs (hashes, IPs, domains, paths) from MISP and vendor feeds.
- YARA + Sigma libraries, versioned and regression-tested; ATT&CK coverage tracked per technique.

## 4. Anti-evasion: not being lied to

| Fact | View A (live, user-space) | View B (live, kernel/raw) | View C (offline / external) |
| --- | --- | --- | --- |
| Processes | `/proc` readdir | PID brute force; task list via memory | Volatility on RAM image |
| Files | `readdir` | Raw block-device parse (Sleuth Kit) | Dead-box mount from trusted media |
| File contents in use | Read from disk | Read via `/proc/PID/map_files` / memory | Hash vs vendor repo |
| Open ports | `/proc/net` | netlink sock_diag; memory socket structs | External nmap |
| Kernel modules | `/proc/modules` | `/sys/module`, memory carving | Volatility module scan |
| BPF programs | `bpf()` enumeration | fdinfo BPF fds; memory | Volatility BPF plugins |
| ftrace hooks | `enabled_functions` | Memory walk of ftrace ops | Offline analysis |
| Logs | Local journald/syslog | auditd ring buffer | Remote SIEM copy |

**Rules for the scanner itself**
- Single statically linked binary with its own parsers; never call host tools for trusted results.
- Clear `LD_PRELOAD` and friends, run with a minimal environment, verify its own hash at start.
- Detect tampering of its own view: compare syscall results against raw reads; time syscalls for hook latency; verify ftrace can actually be toggled.
- Run from read-only media or a verified image; write results only to a remote collector or write-once storage.
- Highest assurance: dead-box analysis with the suspect OS not running.

**Residual blind spots** — firmware below measured boot, compromised hypervisor, hardware implants, compromised BMC/cloud control plane. Mitigations: measured boot + remote attestation, hypervisor introspection, out-of-band firmware verification.

## 5. Continuous monitoring and baselining

**Baseline** (at build time, refreshed on approved change): hashes of executables, libraries, configs, boot artifacts; expected services, ports, users, SUID set, modules, BPF programs, cron/systemd/udev/PAM entries; per-role behavioural profile.

**Runtime sensor** (eBPF + LSM hooks, with auditd as an independent second source): `execve`, `ptrace`, module load, BPF load, `memfd_create`, `io_uring_setup`/`io_uring_enter`, setuid/capability changes, mount, writes to persistence paths, outbound connects, DNS. Tamper alarms on sensor stop, unload, missed heartbeat, or event volume dropping.

| Check | Frequency |
| --- | --- |
| Runtime event stream | Continuous |
| Persistence and account diff | Every 15 minutes |
| Full filesystem integrity + YARA | Daily |
| Vulnerability and package audit | Daily, plus on new advisory |
| Memory capture + offline analysis | Weekly sample, and on any high-severity alert |
| Firmware, boot chain, attestation | Every boot, plus weekly |
| Dead-box audit from trusted media | Quarterly, and during incident response |
| External port scan | Daily |

## 6. Correlation, scoring and evidence

Findings are linked into attack chains by shared entities (PID, user, file, IP, session) and scored as chains. Cross-host correlation spots lateral movement.

| Level | Meaning | Example |
| --- | --- | --- |
| Critical | Confirmed compromise or anti-forensics | Hidden process/module/BPF program found by cross-view diff |
| High | Strong attacker behaviour | Unpackaged PAM module; web server spawning a shell |
| Medium | Suspicious, needs review | New cron job or udev rule not in change log |
| Low | Hygiene or exposure | Outdated package, weak SSH config |
| Info | Inventory | Drift explained by a change ticket |

Reports: per-host verdict with confidence; reconstructed timeline; JSON/STIX 2.1/OCSF for SIEM; HTML/PDF for humans; a coverage report listing every check that did not run. Evidence: memory → network → process → disk order, SHA-256 at capture, write-once storage, chain-of-custody export. Response hooks (isolate, kill, quarantine, disable account, snapshot) are opt-in and logged.

## 7. Requirements, building blocks, validation, roadmap

**Non-functional**
- Sensor overhead < 3% CPU and < 200 MB RAM at p95; full sweep throttled under 20% of one core.
- Full sweep of a 500 GB server in < 8 hours without service impact.
- 10,000+ hosts per collector cluster; agentless SSH mode.
- Mutual TLS everywhere; signed rules and binaries; RBAC on findings; air-gapped mode with signed bundles.

**Build on / benchmark against**

| Area | Tools |
| --- | --- |
| Rootkit and integrity | rkhunter, chkrootkit, AIDE, `rpm -Va` / `debsums`, unhide, LKRG |
| Runtime detection | Falco, Tetragon, Tracee, auditd, osquery |
| Memory forensics | AVML, LiME, Volatility 3 |
| Disk forensics | The Sleuth Kit, Plaso, UAC |
| Firmware and boot | CHIPSEC, fwupd, Keylime |
| Malware and IOCs | YARA, ClamAV, THOR/Loki, MISP |
| Vulnerabilities | Trivy, Grype, OpenSCAP, Lynis |
| Rules / adversary emulation | Sigma, Elastic detection-rules, MITRE ATT&CK, PANIX, Atomic Red Team |

Note: published research shows rkhunter/chkrootkit miss eBPF rootkits, and Curing evaded several popular eBPF-based EDRs — treat these tools as baselines to beat, not as coverage.

**Validation**
- Test bench of disposable VMs planting every technique in the research catalogs; each must be detected.
- Atomic Red Team / Caldera runs; publish an ATT&CK coverage matrix.
- False-positive budget on clean images of every supported distro.
- Tamper tests: kill, blind, or feed false data to the scanner; each must alarm.
- Regression suite on every rule and code change.

**Roadmap**
1. **Phase 1 — Triage sweep:** processes, persistence, accounts, file integrity, network, logs, BPF/PAM/udev/preload checks, cross-view diff, JSON report.
2. **Phase 2 — Deep forensics:** memory capture/analysis, raw-disk parsing, io_uring and mmap-tamper detection, timeline, dead-box mode.
3. **Phase 3 — Continuous:** eBPF/LSM + auditd sensor, baselining, collector, correlation, scoring.
4. **Phase 4 — Root of trust:** firmware/boot verification, TPM attestation, hypervisor introspection, fleet hunting.
