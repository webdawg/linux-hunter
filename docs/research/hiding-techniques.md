# Linux Hiding & Evasion Techniques — Detection Catalog

*Research compiled 2026-10-18.*

Rootkits exist to make the defender's tools see a clean system. Their techniques have moved
through generations, each a response to better defences:

| Era | Implementation model | Why attackers moved on | Examples |
| --- | --- | --- | --- |
| Late 1990s–2000s | Trojanized binaries (`ps`, `ls`, `netstat` replaced) | Package hash checks catch it | t0rn, lrk; perfctl still drops fake `top`, `ldd`, `lsof`, `crontab` in 2024 |
| 2000s–now | Userland shared-object rootkits via `LD_PRELOAD` / `/etc/ld.so.preload` | Static binaries and `/proc/PID/maps` inspection expose them | Jynx, Azazel, BEURK, Symbiote, Auto-color, perfctl, QLNX, LinkPro fallback |
| 2000s–now | Loadable kernel module (LKM) rootkits: syscall-table, then kprobe/ftrace hooks | Module signing, lockdown, LKRG, Secure Boot | Adore-ng, Reptile, Diamorphine, Suterusu, Drovorub, PUMAKIT, Singularity, VoidLink, SIXZUT |
| Late 2010s–now | eBPF rootkits: tracepoint/kprobe/LSM/XDP/TC programs | Not visible in `/proc/modules`; can work under Secure Boot | TripleCross, Boopkit, ebpfkit, BPFDoor (classic BPF), LinkPro, QLNX, AUR 2026 stealer, VoidLink |
| 2025–now | io_uring-based evasion (no syscalls to hook) | Most EDRs only watch syscalls | Curing (ARMO PoC), RingReaper |
| 2025–now | Attacking the telemetry pipeline itself | — | Singularity filtering eBPF ring-buffer events / logs; SPiCa research |
| 2026 | Memory-only content rewriting of legitimate files | — | PoisonedRefresh (PHP files modified only at `mmap()` time) |

Key insight for the design: **every hiding technique hides something from *one* view.** The
countermeasure is always a second view the hiding layer doesn't cover (SPEC §4).

---

## 1. Hiding processes

| Technique | How it works | Seen in | Counter-view / detection |
| --- | --- | --- | --- |
| Hook `getdents`/`getdents64` on `/proc` | Kernel or eBPF hook removes PID entries from directory listings | Diamorphine, Reptile, PUMAKIT, Singularity, LinkPro (`pids_to_hide` BPF map) | PID brute force: `stat`/`open` `/proc/<pid>` for every PID 1..pid_max; `kill(pid, 0)`; memory task list |
| libc `readdir` hook | `LD_PRELOAD` library filters results inside the process | Azazel, Jynx, Symbiote, Auto-color | Static scanner never uses libc; also check `/proc/*/maps` for unexpected `.so` |
| Trojanized `ps`/`top` | Replaced binaries filter output | perfctl | Hash vs repo; never use host tools |
| Process masquerading | Name the process like a kernel thread or daemon (`[kworker/0:1]`, `httpd`, `systemd-resolveld`, `perfctl`, `hpasmlited`) | perfctl, BPFDoor variants, LinkPro, QLNX | Kernel threads have no `exe`, PPID 2, empty `cmdline`; compare `comm`, `cmdline`, `exe`, and package ownership of `exe` |
| `argv[0]` / `prctl(PR_SET_NAME)` rewrite | Process rewrites its own name | Plague (self-renaming), BPFDoor | `exe` link vs claimed name |
| Fileless execution | Run from `memfd_create` (`/memfd:…`), deleted file, or `/dev/shm` | PUMAKIT (`/memfd:tgt`, `/memfd:wpn`), QLNX, VoidLink, BPFDoor (`/dev/shm/kdevtmpfls` then deleted) | `/proc/PID/exe` → `memfd:` or `(deleted)`; sensor on `memfd_create` + `execveat` |
| Lie low when watched | Pause activity when a user logs in or debugger attaches | perfctl (watches utmp/btmp), PUMAKIT/Plague anti-debug | Off-host sampling and memory capture don't trigger "user logged in" signals |
| PID-namespace / container tricks | Run in a separate PID namespace | Container-aware malware | Enumerate all namespaces from `/proc/*/ns/*` |

## 2. Hiding files and directories

| Technique | How it works | Seen in | Counter-view / detection |
| --- | --- | --- | --- |
| `getdents` hooks by prefix/magic string | Any name containing a keyword vanishes | sedexp (hides anything containing "sedexp"), Diamorphine, Reptile, Singularity | Raw block-device parse (Sleuth Kit / own ext4/xfs parser); dead-box mount |
| `stat`/`open` hooks | File exists but returns ENOENT | PUMAKIT, Singularity | Raw-disk read; inode scan |
| Content rewriting on read | `read` hook serves clean content for a modified file | Singularity, LinkPro (hides `ld.so.preload` contents) | Compare `read()` result vs raw-disk bytes |
| **In-memory content rewriting** | Hook `mmap` so the process sees a modified file while disk stays clean | PoisonedRefresh (prepends web shell to PHP scripts in Apache memory) | Hash file-backed mappings in process memory and compare with disk |
| Dot-files, odd names | `.`, `...`, `. ` (dot-space), Unicode look-alikes, names in `/dev`, `/var/log/cross/` | Auto-color (`/var/log/cross/auto-color`), perfctl (`/root/.config/cron/`) | Regex for suspicious names; ELF files in non-binary dirs |
| Immutable / append-only flags | `chattr +i` so admins can't delete or edit | Auto-color, miners | `ioctl(FS_IOC_GETFLAGS)` on all persistence paths |
| Bind / overlay mounts | Mount an empty dir over a malicious one, or over `/proc/PID` | Research, some miners | Parse `/proc/self/mountinfo` for mounts over `/proc/<pid>` or system dirs |
| Timestomping | Copy mtime/atime from a neighbouring file | BPFDoor variants, many | ctime and filesystem journal can't be set by `touch`; compare with `crtime` and package install time |
| Hiding in package-owned paths | Replace a file inside a package with same name | PoisonedRefresh (`httpd`), Ebury | Hash vs vendor repo (local package DB may be edited too) |

## 3. Hiding kernel modules and kernel hooks

| Technique | How it works | Seen in | Counter-view / detection |
| --- | --- | --- | --- |
| Unlink from module list | `list_del` on `THIS_MODULE->list` | Diamorphine, Reptile, most LKM rootkits | `/sys/module` vs `/proc/modules`; memory carving for `struct module` |
| Remove sysfs kobject | Hide from `/sys/module` too | Advanced LKMs | Memory carving; scan kernel memory for executable pages not owned by core kernel or a known module |
| ftrace-based syscall hooks | Uses kernel's own tracing to redirect functions — no syscall-table patch | PUMAKIT, Singularity (hooks installed for both 32- and 64-bit syscall paths) | `enabled_functions`/`touched_functions` — but Singularity filters these; confirm from memory ftrace ops |
| Block disabling ftrace | Intercept writes that would turn ftrace off | Singularity | Try to toggle a tracing control and verify it took effect |
| Taint-flag reset | Periodically clear `tainted_mask` so unsigned-module taint disappears | Singularity | Read taint via memory and via `/proc/sys/kernel/tainted` repeatedly; kernel log of the original taint event on remote syslog |
| kallsyms / kprobe filtering | Hide hook symbols from `/proc/kallsyms` and kprobe lists | Singularity | Memory-based symbol resolution |
| Syscall table / IDT patch | Classic hook | Older LKMs (Adore-ng, Suterusu) | Compare table entries with `System.map` addresses |
| Evade LKRG / detectors | Specific bypasses for Linux Kernel Runtime Guard, rkhunter, chkrootkit, unhide | Singularity | Don't rely on one integrity tool; dead-box + memory |
| Block further module loads | Prevent defenders loading forensic modules (e.g. LiME) | Singularity | Prefer AVML (userspace `/proc/kcore`/`/dev/crash`) or hypervisor-level memory capture |
| Kernel-version-specific builds | Rootkit compiled for the exact running kernel | VoidLink (server-side compilation), QLNX (on-host gcc for userland parts) | Hash-based IOCs fail; rely on behaviour and cross-view |

## 4. Hiding eBPF programs

| Technique | How it works | Seen in | Counter-view / detection |
| --- | --- | --- | --- |
| Hook `sys_bpf` | Filter `BPF_PROG_GET_NEXT_ID` / `BPF_MAP_GET_NEXT_ID` so `bpftool` lists nothing | LinkPro ("Hide" module) | Count BPF fds in `/proc/*/fdinfo`; pinned objects in `/sys/fs/bpf`; memory analysis of `prog_idr` |
| Hide BPF links in `/proc` | Filter `/proc/PID/fd` entries | LinkPro | Raw-memory view; compare fd counts (`/proc/PID/status` FDSize vs listed) |
| `bpf_probe_write_user` | Rewrite userspace buffers (e.g. `getdents` results, `sudoers` reads) | TripleCross, ebpfkit | Kernel logs a warning on first use — check remote syslog; enumerate programs using this helper |
| XDP/TC magic-packet listeners | Code only activates on a specific packet; nothing listens on a port | LinkPro ("Knock" module), Boopkit | `ip link` XDP attachments; `tc filter show` on every interface; BPF program types per interface |
| Telemetry-pipeline tampering | Drop events in `bpf_ringbuf_submit` before they reach the security agent | Singularity / SPiCa research | Heartbeat events with sequence numbers; compare eBPF-reported event counts with auditd counts |

## 5. Hiding network activity

| Technique | How it works | Seen in | Counter-view / detection |
| --- | --- | --- | --- |
| Hook `/proc/net/tcp*` readers | `tcp4_seq_show` hook, or libc `fopen` hook, drops lines | Reptile, Diamorphine, Symbiote, Singularity | netlink `sock_diag` view; memory socket structures; **external port scan** |
| Hook libpcap / inject BPF into captures | When admin runs `tcpdump`, extra BPF bytecode filters out malicious packets | Symbiote, perfctl (`pcap_loop` hook) | Capture on a span/mirror port or another host; static tcpdump |
| Classic BPF socket filter backdoor | Raw socket with a BPF filter wakes the implant on a magic value; no listening port; bypasses host firewall because filter runs before netfilter | BPFDoor (variants A–E grew from ~30 to 229 BPF instructions; magic values differ per protocol), Rapid7 2025 variants (httpShell, icmpShell) | Enumerate packet/raw sockets and attached filters (`/proc/net/packet`, `ss -0pb`); NDR for magic patterns |
| Port reuse / TCP header rewriting | Ride on an allowed port, rewrite headers so logs show legit traffic | LinkPro (TCP window value tricks, reverse/knock mode) | Flow anomalies; unusual TCP window values |
| Local Unix-socket shells | Interactive shell over a local socket — no TCP listener at all | PoisonedRefresh (password-protected local socket), perfctl (Unix sockets internally) | Enumerate Unix sockets and their owning processes; flag shells parented by web servers |
| Encrypted / covert C2 | TLS to hardcoded IPs, DNS/HTTP tunnelling, Tor, ICMP | Auto-color (TLS 443), LinkPro (DNS/HTTP), perfctl (Tor), BPFDoor icmpShell | DNS analytics, beacon periodicity, reputation, JA3/JA4 |
| io_uring network I/O | `IORING_OP_CONNECT`/`SENDMSG`/`RECVMSG` — no `connect`/`sendmsg` syscalls | Curing, RingReaper | Enumerate io_uring contexts per process; LSM/KRSI hooks (`socket_connect`) fire regardless of submission path |

## 6. Hiding from security tools and syscall monitoring

| Technique | How it works | Seen in | Counter-view / detection |
| --- | --- | --- | --- |
| io_uring instead of syscalls | Batch file, network and process operations through shared rings; syscall-tracing EDRs see almost nothing | Curing (bypassed Falco and Tetragon in default config), RingReaper (replaces read/write/connect/unlink) | Hook at LSM layer (works for io_uring ops), alert on `io_uring_setup` by unexpected processes, or disable io_uring (`kernel.io_uring_disabled=2`) where not needed |
| eBPF-based agent blinding | Rootkit filters the events security agents depend on | Singularity | Multi-source telemetry + tamper heartbeats |
| Anti-debugging | `ptrace(TRACEME)`, timing checks, `/proc/self/status` TracerPid | PUMAKIT, Plague, Gayfemboy | Memory capture instead of live debugging |
| Sandbox detection / long sleep | Detect timing irregularities, sleep for many hours | Gayfemboy (goes dormant ~27h if sandboxed) | Long-running test bench; don't rely on short sandbox runs |
| Environment keying | Only install if kernel version / distro / file matches | PUMAKIT (checks kernel symbols), VoidLink (adapts to installed EDR) | Test bench across many kernels |
| Static-signature evasion | Packing, string obfuscation (RC4 in PoisonedRefresh, layered obfuscation in Plague), per-victim compilation | Most 2024–26 families; Plague and QLNX had near-zero AV detections at discovery | Behavioural + cross-view, not hashes |
| Masquerading as security/system units | Service names one letter off from real ones | LinkPro (`systemd-resolveld`) | Edit-distance check against package unit names |

## 7. Hiding activity in logs and history

| Technique | How it works | Seen in | Counter-view / detection |
| --- | --- | --- | --- |
| Kernel log filtering | Filter `dmesg`, `journalctl`, `klogctl` reads in real time | Singularity | Remote syslog; kernel ring buffer from memory |
| Auth bypass that never logs | PAM backdoor short-circuits before logging | Plague (session traces erased, no standard auth log entries) | Network-level SSH session logs; `wtmp` vs remote; PAM module integrity |
| History wiping | `HISTFILE=/dev/null`, `unset HISTFILE`, truncate `~/.bash_history` | Plague, almost all operators | Zero-length history for active accounts; shell history from memory |
| wtmp/utmp/lastlog editing | Zero out records | Classic log cleaners | Record size/sequence checks; remote copies |
| Selective log deletion / journal rotation | Remove specific lines or vacuum journal | Many | Forward Secure Sealing; remote SIEM as authority |
| Timestomp | See §2 | — | — |
| SELinux / AppArmor tampering | Set permissive, add allow rules, relabel | PoisonedRefresh (modified SELinux config) | Baseline enforcement mode and policy modules |

## 8. Implications baked into the spec

1. Raw-disk parsing and memory forensics are **phase-2 must-haves**, not nice-to-haves — they
   are the only views several 2025–26 families can't fake.
2. The sensor must cover **io_uring** and use **LSM hooks**, not only syscall tracepoints.
3. BPF program enumeration must use at least three independent methods because LinkPro hides
   from the obvious one.
4. In-memory vs on-disk comparison of file-backed mappings is needed to catch
   PoisonedRefresh-style content rewriting.
5. Telemetry needs **heartbeat + sequence numbers** and a second source (auditd) so in-kernel
   event filtering shows up as a gap.
6. Hash IOCs are a bonus, never the backbone: per-victim compilation (QLNX, VoidLink) makes
   every sample unique.
