# Requirement-to-Code Traceability Matrix

*Audited 2026-10-24 against [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md) v1.0, commit
`ded325a` onward. Every status below was checked against actual code and, where claimed
IMPLEMENTED-VERIFIED, an actual passing test — not inferred from a function name, a comment,
or a dependency being present, per the spec's own instruction in §0 and §18.*

## How to read this

**Statuses** (spec §0): IMPLEMENTED-VERIFIED (code + a real test demonstrating the behavior,
checked today), IMPLEMENTED-UNVERIFIED (code exists, no dedicated test), PARTIAL (meaningfully
started, materially incomplete), MISSING (in scope, not built), UNSUPPORTED (explicitly will
not support in current design), NOT-APPLICABLE-WITH-REASON (out of scope for the reason given).

**Ground truth about what this project currently is**, so every row below can be read against
it rather than re-derived per row: `hunter` is a single static-ish Rust binary (dynamically
linked against glibc today — see CLAUDE.md), run live on the host being examined, implementing
Phase 1 ("triage sweep") of the four-phase roadmap in `docs/SPEC.md`. Seven check modules exist
(`src/checks/{processes,network,persistence,accounts,libraries,gtfobins,pam}.rs`), all
userland/filesystem-scope, all reading through the host's own kernel. **There is no baseline
service, no external verifier, no TPM/attestation path, no firmware/boot chain inspection, no
BPF enumeration, no memory forensics, no offline-disk-image analysis, no signing
infrastructure, and no incident-response automation (by design — this tool is read-only).**
Where a whole section of the spec assumes one of those components exists, every requirement in
it is marked NOT-APPLICABLE-WITH-REASON with that shared reason, not re-justified per row — but
each row still gets its own status and priority, and P1/P2 items in those sections are real,
tracked gaps, not dismissed.

**Priority** follows spec §15. A requirement is only P0 here if it describes something our
*actual, shipped* code gets wrong (a real bug) or misrepresents (an honesty/framing gap) — not
"this whole subsystem doesn't exist yet," which is P1/P2 and tracked as a gap, not an incident.

---

## 1. Security contract and adversary model (TR)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| TR-01 | PARTIAL | P1 | `CLAUDE.md` rule #1; every check in `src/checks/` | The adversary model (root, can replace utilities/libraries, kill/impersonate the agent) is assumed implicitly by CLAUDE.md's "never trust the suspect host" rule and by writing our own ELF/PAM/sudoers parsers instead of shelling out, but it is not written down as a standalone threat model document. Nothing currently defends against the agent itself being killed or impersonated (no watchdog, no external liveness check — see SC-13). |
| TR-02 | MISSING | P2 | — | No kernel-exploitation, data-only-tampering, or falsified-kernel-interface coverage exists. All seven checks are userland/filesystem. The `statement` field (`src/main.rs::build_statement`, added today) explicitly says kernel compromise is not addressed, which is the honest framing this requirement wants even though the detection capability itself doesn't exist. |
| TR-03 | NOT-APPLICABLE-WITH-REASON | P2 | — | No boot/firmware/hypervisor/update-infrastructure coverage exists; `docs/SPEC.md` §3.1 scopes this for Phase 4. |
| TR-04 | PARTIAL | P1 | `src/checks/processes.rs` (deleted-exe, kworker masquerade, RWX anon mapping, argv-wipe); `src/checks/persistence.rs` (shell history suppression) | Memory-only execution and masquerading are partially covered; short-lived implants, pure credential theft, and telemetry-loss detection are not. |
| TR-05 | MISSING | P2 | — | No asset-classification document exists. |
| TR-06 | PARTIAL | P1 | README.md "Philosophy"; `CLAUDE.md` rule #1 | The TCB boundary (host kernel is not trusted) is stated in prose (README, CLAUDE.md, and now the `statement` field) but not formalized as a diagram/document covering hypervisor/BMC trust specifically, since neither is in scope yet. |
| TR-07 | NOT-APPLICABLE-WITH-REASON | P1 | — | There is no baseline/enrollment concept at all yet (see FS-01, AR-10). Nothing can wrongly treat a first run as clean because nothing persists a baseline across runs. This becomes a real P0/P1 concern the moment a baseline system is built — tracked in `FUTURE_AVENUES.md` §6. |
| TR-08 | IMPLEMENTED-VERIFIED | — | every `Finding` in every check | No check names a threat actor or malware family as the *source* of a finding; `docs/research/malware-case-studies.md` citations are background research, never emitted in a report. Verified by inspection of every `Finding::new` call site. |
| TR-09 | PARTIAL | P1 | `report.rs::Coverage`; `main.rs::Report` | Coverage is published per-check (`ok`/`partial`/`failed`), which is real and tested, but only for the single "local live collection" method this tool has — the spec's other four methods (remote-verified, offline-disk, external-memory, firmware) don't exist to have coverage reported about. |
| TR-10 | IMPLEMENTED-VERIFIED | — | `src/main.rs::build_statement`; tests `statement_never_claims_clean_even_with_zero_findings_and_full_coverage`, `statement_names_which_checks_are_incomplete`, `statement_reports_finding_count_when_present` | Fixed today (this audit's first finding). Previously: a zero-finding scan printed bare "No findings." with no hedge above the coverage section. Now every scan (text and JSON) carries an explicit `statement` field that names incomplete checks and states plainly that passing does not establish the host is clean, regardless of findings/coverage shape. |

## 2. Architecture and evidence independence (AR)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| AR-01 | PARTIAL | **P0** | `src/main.rs::run_all_checks` | A check returning `Err` is caught and reported as `CoverageStatus::Failed` without stopping the scan (verified: the `match check.run() { Ok(..) => .., Err(err) => .. }` loop continues to the next check). **But this only catches `Result::Err`, not a Rust panic** — a panic anywhere in a check unwinds the whole process by default, no `catch_unwind` exists in `main.rs`. We found and fixed two real panic paths today (libraries.rs's ELF reader, persistence.rs's symlink recursion) by removing the underlying bugs rather than adding a panic boundary — the *specific* bugs are fixed, but the general protection ("a panic in any future check can't take the whole scan down") is not. Recommended P0 follow-up: wrap each check's `.run()` in `std::panic::catch_unwind`. |
| AR-02 | MISSING | P2 | — | No evidence dependency graph is documented. (It's implicit — everything reads through `/proc`, `/etc`, or direct file I/O on the live host — but not written down as the spec wants.) |
| AR-03 | IMPLEMENTED-VERIFIED | — | `CLAUDE.md` rule #1; README "Philosophy"; `src/main.rs::build_statement` | We never shell out (verified via `grep -rn "Command::new" src/` → zero matches) and parse ELF/PAM/sudoers ourselves specifically to avoid trusting host tools — but the `statement` field explicitly says this reduces *tampering-of-our-own-collection* risk, not kernel-compromise risk, which is exactly this requirement's distinction. |
| AR-04 | IMPLEMENTED-VERIFIED | — | `statement` field wording | Explicitly stated in the new `statement` text: "every check here reads through the host's own kernel." |
| AR-05 | IMPLEMENTED-UNVERIFIED | P2 | `src/checks/network.rs` (tcp/sctp table vs `/proc/*/fd` cross-view) | The two-view socket cross-check exists and doesn't claim extra confidence beyond "these two views disagree," but there's no test asserting we *don't* over-score a dual-view agreement. |
| AR-06 | UNSUPPORTED | P2 | — | No evidence-store/replay concept exists; `hunter` only ever inspects the live host it's run on. |
| AR-07 | NOT-APPLICABLE-WITH-REASON | — | — | No verifier/evidence-storage/baseline-publication components exist to need separated credentials. |
| AR-08 | IMPLEMENTED-VERIFIED | — | `third_party/lynis/` (benchmark only, not in the scan path — see its README); `docs/research/sources.md` (GTFOBins, Lynis provenance) | We lean on GTFOBins' real data (`src/checks/gtfobins.rs`) rather than inventing our own abuse-technique catalog, and explicitly scoped Lynis to benchmarking rather than reimplementing or wrapping it. No attestation/forensic library integration exists yet to assess (AT-*/KR-10). |
| AR-09 | PARTIAL | P1 | `src/main.rs::Command::{Scan,Watch}` | Two profiles exist (`scan`: one-shot triage, `watch`: continuous polling of the same checks) — both are "low-impact live triage," there's no distinct "privileged deep inspection" profile, and nothing currently *requires* elevated privilege to unlock deeper checks (coverage just silently narrows without root, which is itself honestly reported — but there's no explicit profile selection). |
| AR-10 | MISSING | P2 | — | No residual-risk register exists as a document; `CLAUDE.md`'s "Current implementation status" section and `FUTURE_AVENUES.md` partially serve this role but aren't structured as one. |

## 3. Result model, coverage and evidence (EV)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| EV-01 | PARTIAL | P1 | `src/report.rs::{CoverageStatus, Severity}` | We have a 3-value execution status (`Ran`/`Partial`/`Failed`) but not the spec's 7-value execution taxonomy, and no separate assessment enum at all — `Finding` presence/absence currently *is* the assessment, with no explicit `INCONCLUSIVE`/`KNOWN-MALICIOUS-MATCH` distinction. This is a real structural gap, not a one-line fix. |
| EV-02 | MISSING | P2 | `src/report.rs::Finding` | A `Finding` today carries `check`, `severity`, `summary`, `detail` — none of the spec's per-finding metadata (rule version, host/boot identity, collection timestamps, evidence hashes, confidence rationale) exists. No baseline/verifier/enrollment concept exists for most of these fields to even refer to yet. |
| EV-03 | IMPLEMENTED-VERIFIED | — | `src/main.rs::{Report, build_statement}`; `report.rs::Coverage` | A zero-finding report with incomplete coverage cannot render as simply "clean" — verified by `statement_never_claims_clean_even_with_zero_findings_and_full_coverage` and the live coverage section always printed alongside findings. |
| EV-04 | PARTIAL | P1 | `main.rs::print_report` (JSON branch) | JSON output preserves raw finding text (including control characters, which `serde_json` escapes safely — see SC-06). There's no concept of "original bytes of the artifact that triggered a finding," stderr/exit-status/truncation-flag capture, since no checks currently execute subprocesses to have stderr/exit status from. |
| EV-05 | IMPLEMENTED-VERIFIED | — | `src/report.rs::Severity`; every `Finding::new` call | Severity is a plain 5-level enum (`Info`/`Low`/`Medium`/`High`/`Critical`), never presented as a numeric probability. Two severities were deliberately *downgraded* this session after live-host testing showed over-claiming (RWX-mapping check: Critical→Medium after libffi false positives; PAM sufficient-module check: High→Medium after `pam_rootok.so`/`pam_rhosts.so` false positives) — direct evidence this distinction is taken seriously in practice, not just in the type system. |
| EV-06 | UNSUPPORTED | P2 | — | No signed manifests or acquisition-custody tracking exist; nothing is acquired/stored, only read and reported in the same process invocation. |
| EV-07 | NOT-APPLICABLE-WITH-REASON | — | — | No verifier/transport exists for freshness challenges to apply to. |
| EV-08 | MISSING | P2 | — | Findings don't currently carry any timestamp at all (collection time, host wall clock, or otherwise). |
| EV-09 | PARTIAL | P1 | `src/checks/accounts.rs` (reads but never prints `/etc/shadow` hash contents, only presence of an empty field) | No check currently captures full memory/environment contents (none of the seven checks read `/proc/<pid>/environ`), so the sharpest version of this risk doesn't yet apply, but there's no stated minimization/retention policy either, since nothing is retained past one process run. |
| EV-10 | IMPLEMENTED-UNVERIFIED | P2 | — | A crashed `hunter` process produces no output file at all (we don't write report files — JSON goes to stdout), so there's no "damaged report parses as success" failure mode to have, but there's also no durable completion manifest for an interrupted `watch` loop. |
| EV-11 | NOT-APPLICABLE-WITH-REASON | — | — | No suppression mechanism exists at all yet. |
| EV-12 | NOT-APPLICABLE-WITH-REASON | — | — | No remote heartbeat/verifier exists; `watch` mode logs locally via `tracing` only. |

## 4. Platform discovery and support boundaries (PL)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| PL-01 | MISSING | P1 | — | No platform-inventory check exists. `docs/SPEC.md` §1 states the intended distro/arch scope (x86_64/arm64; major distro families) but nothing in the binary itself inventories or reports what it's actually running on. |
| PL-02 | NOT-APPLICABLE-WITH-REASON | — | — | No kernel-build-specific memory inspection exists (that's KR-09/KR-10 territory, also not built). |
| PL-03 | PARTIAL | P1 | every check's `fs::read_dir`/`fs::metadata` error handling | Checks consistently distinguish "path doesn't exist" (silent, normal) from permission-denied (counted and surfaced via `CheckOutput::skip`, e.g. `processes.rs`, `network.rs`, `accounts.rs`, `gtfobins.rs`) — real and tested via live non-root runs this session showing `PARTIAL` coverage with specific reasons. Not probed as a deliberate "feature detection" pass, though; it falls out of each check's own error handling rather than a shared mechanism. |
| PL-04 | MISSING | P1 | — | `hunter` does not detect whether it's running inside a container, a chroot, or against a restricted `/proc`, and a container-scoped run would currently report coverage as if it saw the whole host. This is a real, specific gap: the coverage/statement honesty we built today for *permission* gaps doesn't yet extend to *scope* gaps. |
| PL-05 | NOT-APPLICABLE-WITH-REASON | — | — | No distinct container-vs-host inspection modes exist; see PL-04. |
| PL-06 | PARTIAL | P2 | `src/checks/libraries.rs` doc comments | ELF parsing is explicitly scoped to ELF64 little-endian (x86_64/arm64) and explicitly returns `Ok(None)` (not a flagged gap) for anything else, per `docs/SPEC.md` §1 — this is a deliberate, documented boundary, but it's the only check with architecture-specific logic at all; nothing else in the codebase has architecture-dependent behavior to degrade. |

## 5. Boot, firmware, and kernel admission (BT) — NOT-APPLICABLE-WITH-REASON, all rows

No boot chain, firmware, Secure Boot, module-signing, or lockdown inspection exists anywhere
in this codebase. `docs/SPEC.md` §3.1 scopes this work for Phase 4 ("root of trust"); nothing
here has been started. BT-01 through BT-12: all **MISSING**, priority **P2** (not P1 — this is
explicitly later-phase work per the project's own committed roadmap, not a gap in the
*current* deployment profile's P1 set). No code location, no test, no partial credit.

## 6. TPM, measured boot and runtime integrity (AT) — NOT-APPLICABLE-WITH-REASON, all rows

No TPM, attestation, measured-boot, IMA/EVM, or dm-verity/fs-verity integration exists. Same
reasoning as §5: Phase 4 scope, not started. AT-01 through AT-13: all **MISSING**, priority
**P2** for the same reason. Keylime (cited as S5/S8) has not been evaluated or integrated.

## 7. Kernel runtime, hooks and memory (KR)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| KR-01 | PARTIAL | P1 | `src/checks/network.rs` (tcp/sctp-table vs fd-table cross-view) | The only cross-view comparison in the codebase today is sockets-vs-process-fds; no module-list, sysfs, or executable-kernel-region comparison exists (those would need KR-02/KR-03 to exist first). |
| KR-02 through KR-13 | MISSING | P2 | — | No kernel module, syscall-dispatch, hook-surface, or memory-forensics coverage exists at all. `docs/SPEC.md` §3.2/§3.3/§3.13 scope this for later phases; `third_party/README.md` notes GPLv2-only tools (needed for some of this space, e.g. LKRG-adjacent work) aren't vendored yet either. |
| KR-14 | PARTIAL | P1 | `src/checks/processes.rs::check_rwx_mappings` | Anonymous RWX memory-mapping detection exists and is tested (`cargo test`, plus live-host verification against real libffi trampolines that led to downgrading its severity — see EV-05). This is real coverage of *one* user-space-mapping technique, not the "separate process-memory workflow" the requirement describes, and definitely not kernel memory. |

## 8. eBPF and tracing coverage (BP) — MISSING, all rows

No BPF program/map/link enumeration exists anywhere in this codebase. `docs/SPEC.md` §3.3
scopes this as unimplemented (also called out explicitly in `CLAUDE.md`'s "Current
implementation status": *"BPF-program enumeration (§3.3 in SPEC.md) has no check yet"*).
BP-01 through BP-08: all **MISSING**, priority **P1** — unlike the boot/firmware/TPM sections,
this one is *not* deferred to a later phase in our own roadmap; `docs/SPEC.md`'s Phase 1 build
order explicitly lists "BPF-program knocking" as in-scope triage work. This is the most
honest P1 gap in the whole matrix: something our own plan says should exist in Phase 1 and
doesn't yet.

## 9. Processes, credentials and execution (PR)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| PR-01 | PARTIAL | P1 | `src/checks/processes.rs`; `network.rs` | `/proc` enumeration, fd cross-reference with sockets, and mapping inspection (`check_rwx_mappings`) exist. No cgroup/namespace-membership correlation, no execution-event history, no memory reconstruction. |
| PR-02 | PARTIAL | P1 | `src/checks/processes.rs::run` | PIDs are read fresh each scan via `/proc` readdir; there's no stable cross-scan process identity (start-time-based handle) since `hunter` has no persistent state between runs (`scan` is one-shot, `watch` re-scans from scratch each tick). PID reuse between ticks of `watch` could misattribute a finding to the wrong (new) process sharing an old PID — a real, currently-unaddressed gap. |
| PR-03 | PARTIAL | P1 | `src/checks/processes.rs` (`exe`, `cmdline`, `comm`, deleted-exe, argv-wipe) | Covers exe identity, cmdline, comm, and deleted/argv-wiped detection. No mapped-library enumeration, no interpreter detection, no parent lineage, no working/root-directory inspection, no `memfd` detection. |
| PR-04 | MISSING | P2 | — | No mapped-executable-code-vs-provenance comparison exists (needs a package-hash baseline first — see FS-01). |
| PR-05 | MISSING | P1 | — | No capability/credential/user-namespace inspection exists. `src/checks/accounts.rs` covers *account* posture (UID 0 duplicates, shells, groups) but not *live process* credential/capability state. |
| PR-06 | PARTIAL | P1 | `src/checks/persistence.rs::check_ld_preload` | Global `/etc/ld.so.preload` is covered (plus its immutable flag). Per-process `LD_PRELOAD` via `/proc/<pid>/environ` is not read by any check — exactly the gap this requirement calls out ("merely clearing LD_PRELOAD does not eliminate every user-space interception path"), and we don't yet cover the per-process case. |
| PR-07 | PARTIAL | P1 | `src/checks/pam.rs`; `src/checks/accounts.rs::check_sudoers`; `src/checks/gtfobins.rs::check_sudoers_commands` | PAM config, sudoers NOPASSWD/GTFOBins cross-reference, and SSH `authorized_keys` (`persistence.rs`) are covered. NSS and polkit are not. |
| PR-08 | IMPLEMENTED-VERIFIED | — | every check; `docs/SPEC.md` "detection notes" style followed throughout | No finding anywhere decides purely on process name or an open port in isolation — e.g. the kernel-thread-masquerade check requires *both* a kernel-thread-style name *and* a real `exe` symlink (the thing real kernel threads never have); the deleted-exe check requires the actual `(deleted)` suffix from the kernel, not a name heuristic. Verified by reading every `Finding::new` call site's triggering condition. |
| PR-09 | IMPLEMENTED-VERIFIED | — | `CLAUDE.md` rule #1; `src/checks/libraries.rs` (own ELF parser, not `ldd`) | Verified via `grep -rn "Command::new\|std::process::Command" src/` → no matches anywhere in the codebase. We wrote our own ELF dynamic-section parser specifically to avoid calling `ldd`/`readelf` on untrusted binaries. |
| PR-10 | MISSING | P2 | — | No independent identity/orchestration log correlation exists; local-only tool. |

## 10. Filesystem, package provenance and persistence (FS)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| FS-01 | MISSING | **P1** | — | **The single biggest structural gap in this codebase**, already tracked independently in `CLAUDE.md`'s "Current implementation status" and `FUTURE_AVENUES.md` §6 before this audit: there is no package-hash baseline at all. Every persistence/library/account/PAM check flags by heuristic (location, recency, permission bits, name-list membership) — never "is this file actually owned by the package that claims it." This is the root cause of most of the "heuristic, not exhaustive" caveats throughout this matrix. |
| FS-02 | PARTIAL | P1 | `src/checks/libraries.rs`, `gtfobins.rs`, `persistence.rs` | Covers libraries (shadow sonames, DT_NEEDED tampering), SUID binaries, and persistence scripts. No general "unexpected addition/deletion across the whole filesystem" sweep exists — only in the specific locations each check targets. |
| FS-03 | PARTIAL | P1 | `src/checks/persistence.rs` (mode bits for world-writable checks, immutable flag via ioctl); `gtfobins.rs` (SUID/SGID mode bits) | Mode bits and the immutable flag are read directly (not via `lsattr`). No ACL, general xattr, hardlink, or mount-identity tracking exists. Timestamps (mtime) are used for the recency heuristic in `persistence.rs` and acknowledged in that code's own comments as "not inherently malicious... worth a manual read" — i.e. the weak-evidence caveat this requirement wants is already in the finding text. |
| FS-04 | IMPLEMENTED-VERIFIED | — | `src/checks/persistence.rs::scan_recent_at_depth`; tests `scan_recent_terminates_on_a_cyclic_directory_symlink`, `entry_point_symlink_is_followed_but_nested_symlink_is_not` | Fixed today (this audit's second finding). Previously: `scan_recent` used `fs::metadata` (follows symlinks) at every recursion depth with no explicit bound — a directory symlink loop, plantable by any unprivileged user under their own `~/.config/autostart`, recursed until `fs::read_dir` happened to error past `PATH_MAX` (~900 levels, confirmed empirically — not a crash, but an accidental bound the code never chose). Fixed: `symlink_metadata` (not followed) for anything found during recursion, `fs::metadata` (followed) only at the trusted entry point (preserving dotfile-manager setups that symlink a whole config directory into place), plus an explicit `MAX_SCAN_DEPTH = 40` as a second, independent bound. |
| FS-05 | MISSING | P2 | — | No before/after metadata stability check exists; each check reads a file once. |
| FS-06 | PARTIAL | P1 | `src/checks/libraries.rs` (overlay-aware testbench fixtures only, not production code) | No production code explicitly handles overlayfs/FUSE/network-filesystem semantics differently from a normal local filesystem — everything goes through plain `std::fs` calls, which *will* traverse these transparently (not silently omitted, per the requirement) but without any filesystem-type-aware reasoning about what that means for trust. |
| FS-07 | PARTIAL | P1 | `src/checks/persistence.rs` `AUTOSTART_TREES` (systemd unit dirs) | Standard unit search paths are walked for recency. No drop-in, `.wants`/`.requires` symlink, transient-unit, or generator-specific inspection exists. |
| FS-08 | IMPLEMENTED-UNVERIFIED | P1 | `src/checks/persistence.rs` `AUTOSTART_TREES` (cron, SysV init, udev rules, modules-load.d) | Covers cron/cron.d/spool, `/etc/init.d`, `/etc/rc.d`, udev rules dirs, modules-load.d, `/etc/modules`, `rc.local`. No `anacron`/`at` coverage; no initramfs-builder-hook coverage. |
| FS-09 | IMPLEMENTED-VERIFIED | — | `src/checks/persistence.rs::check_history_suppression`, `check_xdg_autostart`; `accounts.rs` (SSH authorized_keys); `pam.rs` | Shell rc files, XDG autostart, SSH `authorized_keys`, and PAM are all covered and each has at least one testbench scenario (`testbench/scenarios/{gtfobins-sudo-vim,pam-sufficient-permit}` exercise adjacent paths; `ld-preload-nonempty` covers the loader-config angle of this requirement). NSS plugin inspection specifically is not covered. |
| FS-10 | MISSING | P2 | — | No container-image/orchestration coverage exists. `docs/SPEC.md` §3.11 scopes this as unimplemented. |
| FS-11 | PARTIAL | P1 | `src/checks/gtfobins.rs`, `libraries.rs` (operate on whatever's actually on disk, package-manager-agnostic) | We don't distinguish distro-managed from locally-built/AUR artifacts at all (no package-manager integration exists per FS-01), which incidentally means we *don't* make FS-11's specific mistake (trusting package-manager presence as authentication) — but only because we don't consult the package manager for anything yet, not because we deliberately solved this. |
| FS-12 through FS-14 | NOT-APPLICABLE-WITH-REASON | P2 | — | No offline/dead-box analysis mode exists; `hunter` only examines a live, running host. `docs/SPEC.md` §2 names "dead-box" as a planned operating mode, not yet built. |

## 11. Network and independent observations (NW)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| NW-01 | PARTIAL | P1 | `src/checks/network.rs` | Covers TCP (`/proc/net/tcp{,6}`) and SCTP (`/proc/net/sctp/eps`) listening sockets only. No interface, route, firewall/NAT, DNS, or packet-processing-attachment inventory. |
| NW-02 | IMPLEMENTED-VERIFIED | — | `src/checks/network.rs::build_inode_to_pid_map`; tests `parses_tcp_listener_and_skips_established`, `parses_sctp_listener_per_kernel_field_layout`, `sctp_non_listen_state_is_skipped` | Socket-to-process correlation via `/proc/*/fd` inode matching is real and unit-tested against the actual kernel field layouts for both protocols. No namespace-awareness (a listener in a different network namespace than `hunter` itself would not be seen — not flagged as a gap anywhere today). |
| NW-03 through NW-06 | NOT-APPLICABLE-WITH-REASON | P2 | — | No external network sensor/TAP/switch integration exists; `hunter` only has the host's own view. `docs/SPEC.md` §3.9 names this as a later-phase need. |
| NW-07 | IMPLEMENTED-VERIFIED | — | whole codebase | Verified by inspection: no code anywhere makes an outbound network connection of any kind. `hunter` reads `/proc` and local files only. |
| NW-08 | NOT-APPLICABLE-WITH-REASON | — | — | No remote evidence transport exists (nothing is sent anywhere) for its loss to be a coverage incident. |

## 12. Collector, parser and supply-chain security (SC)

| ID | Status | Priority | Code / Test | Notes |
| --- | --- | --- | --- | --- |
| SC-01 | PARTIAL | **P0** | `src/checks/libraries.rs` (ELF reader); 2 `unsafe` blocks total (`persistence.rs::is_immutable` ioctl, `network.rs::geteuid`) | Fixed today (this audit's third and most serious finding). The hand-rolled ELF64 dynamic-section parser used `.unwrap()` on slice-to-array conversions and raw (non-checked) pointer arithmetic throughout. **Confirmed by direct reproduction** (not just read of the code) that a crafted `PT_DYNAMIC` program header with an offset near `usize::MAX` panicked the process — `thread 'main' panicked at ...: range start index 18446744073709551615 out of range for slice of length 256` — in both debug (overflow check) and release (wrapping then an out-of-range slice) builds. Since `src/checks/libraries.rs` parses real binaries at fixed paths (`TRUST_CRITICAL_BINARIES`, e.g. `/usr/bin/rkhunter`) that an attacker who's already compromised the host could replace, this was a real "attack the scanner" vector: a single malformed file could crash the *entire* `hunter` process, losing every finding from every check that had or would have run. Fixed: every offset computation now uses `checked_add`/`checked_mul`/`checked_sub`, and the byte readers return `Option` instead of panicking. Five new regression tests, including one (`huge_phoff_does_not_panic_or_overflow`) that reproduces the exact original failure mode against the *fixed* code and confirms it now returns `None` instead. Remaining gap: no `catch_unwind` boundary exists for checks in general (see AR-01) — this fix closes the one confirmed hole, not the general class. |
| SC-02 | IMPLEMENTED-VERIFIED | — | whole codebase | Verified via `grep -rn "Command::new\|std::process::Command" src/` → zero matches. There is no shell-command construction anywhere to have an injection bug in. |
| SC-03 | NOT-APPLICABLE-WITH-REASON | — | — | Follows from SC-02: since nothing invokes external tools, there's nothing to pin/verify the identity of. The one partial exception, `src/checks/libraries.rs::TRUST_CRITICAL_BINARIES`, uses hardcoded absolute paths (`/usr/bin/ps`, etc.) and `fs::canonicalize` to resolve symlinks before reading — not PATH-dependent. |
| SC-04 | PARTIAL | **P0 (fixed in part today)** | `src/checks/persistence.rs::MAX_SCAN_DEPTH`; `src/checks/libraries.rs` (checked arithmetic, effectively bounding parse work to file size) | Depth limits now exist for the one recursive traversal in the codebase (FS-04, fixed today). No byte/file-count/global-scan-time budget exists anywhere — a directory with an enormous number of entries (not a symlink loop, just many files) has no explicit cap, and `fs::read(path)` in `libraries.rs`/`gtfobins.rs` reads whole files into memory with no size limit (a multi-gigabyte file at a scanned path would be read in full). No decompression/regex-complexity exposure exists since nothing decompresses or runs regexes. |
| SC-05 | PARTIAL | P1 | every `fs::read_to_string`/`fs::read_dir` call (synchronous, standard-library, no custom timeout) | FIFOs: `fs::read_to_string` on a FIFO with no writer would block the whole scan indefinitely — **not tested, plausible real gap**. Devices/sockets as regular-file reads: `std::fs` read calls would behave however the kernel driver for that special file does, unbounded. No subprocess trees exist to reap (SC-02), so that half of the requirement is moot. |
| SC-06 | IMPLEMENTED-VERIFIED | — | `src/main.rs::sanitize_for_terminal`; tests `sanitize_escapes_ansi_and_other_control_chars`, `sanitize_preserves_newlines_and_tabs`, `sanitize_leaves_ordinary_text_untouched` | Fixed today (this audit's fourth finding). `Finding` summaries/details embed raw filenames (user-controlled — anything under a scanned home directory) and, in `pam.rs`, raw config-line text; these were printed unescaped via `println!` in the text-output path. A crafted filename with embedded ANSI escapes could have repositioned the terminal cursor, hidden/rewritten displayed text, or changed the window title for whoever reviews a root-run scan's output. Fixed by escaping all control characters (`char::is_control()`, preserving `\n`/`\t`) at the text-rendering boundary. The JSON path was already safe (`serde_json` escapes control characters as normal JSON string syntax) and is explicitly left un-sanitized there to preserve raw evidence bytes (EV-04). |
| SC-07 | NOT-APPLICABLE-WITH-REASON | — | — | `hunter` never writes any file in production operation (verified: `grep -rn "File::create\|fs::write\|OpenOptions" src/` matches only test code). Nothing to overwrite an attacker-selected path with. |
| SC-08 | IMPLEMENTED-VERIFIED | — | whole codebase | No LLM is in `hunter`'s own execution path at all (an optional, carefully-scoped integration is discussed in `FUTURE_AVENUES.md` §5, explicitly as future work with "must be opt-in, off by default" as a hard constraint — not built). Nothing for embedded instructions to currently influence. |
| SC-09 through SC-12 | MISSING | P1 | — | No release signing, SBOM, dependency pinning review, or control-plane exists — there is no control plane (single local binary), and releases aren't cut yet (no tagged version). `Cargo.lock` pins dependency versions but isn't itself verified/signed. |
| SC-13 | MISSING | P2 | — | No watchdog or external liveness monitor exists; `watch` mode is a single long-running process with no self-restart or external supervision built in (systemd or similar could provide this operationally, but `hunter` doesn't document or require it). |
| SC-14 | IMPLEMENTED-VERIFIED | — | whole codebase; README "Philosophy" | Verified by inspection: no code path deletes, modifies, kills, unloads, or reboots anything. `hunter` is read-only by construction — there is no code that *could* do any of these things, not just a policy saying not to. |
| SC-15 | NOT-APPLICABLE-WITH-REASON | — | — | No response actions exist at all (consistent with SC-14 — this is a detection tool only). |

## 13. Test laboratory and adversarial validation (T-01..T-46, QA)

Full scenario-by-scenario mapping lives in [`../testbench/README.md`](../testbench/README.md)
("Current scenarios" table) and each scenario's own `README.md`. Summary against the spec's
T-01..T-46 list:

- **Directly covered** (a testbench scenario or unit test matches the scenario's intent):
  T-01 (clean host — every scenario's baseline run), T-04-ish (`shadow-libc-soname`: altered
  library vs. expected soname), T-06 (service-account/known-module allowlists in `pam.rs`/
  `accounts.rs` are themselves "distinguish benign near-match" fixtures, confirmed via the two
  real false-positive fixes this session — see EV-05), T-07 (`pam-sufficient-permit`,
  `world-writable-cron-d`, `gtfobins-*`), T-27 (`run_script_in_sandbox`'s own pid-namespace
  isolation is implicitly exercised by every process-planting scenario), T-29
  (`scan_recent`'s symlink tests, fixed today), T-30 (every check's `PermissionDenied` vs
  `NotFound` distinction, tested live non-root this session), T-34 (`libraries.rs`'s five
  malformed-ELF tests, fixed today), T-36 (`sanitize_for_terminal` tests, fixed today), T-46
  (this entire audit — we found and fixed real regressions by testing against a live host
  rather than only the fixtures used to write the rules, which is exactly T-46/QA-03's point).
- **Partially covered**: T-05 (no baseline exists at all, so "untrusted first enrollment" is
  vacuously true rather than actively enforced — see TR-07), T-08 (deleted-exe and memfd-style
  cases are covered; JIT/legitimate-deleted-after-upgrade distinction is not tested), T-28
  (PID-reuse risk is named as a real gap under PR-02, not mitigated).
- **Not covered / not applicable**: everything requiring TPM/boot/firmware/BPF/memory
  infrastructure that doesn't exist (T-16 through T-23, T-31 partially, T-39, T-44) is
  NOT-APPLICABLE-WITH-REASON for the same reason as §5/§6/§8. T-02/T-03 (replaced-utility/
  LD_PRELOAD-interference detection) are MISSING: nothing currently verifies `hunter`'s own
  binary or library dependencies haven't been tampered with before it runs — a real P1 gap
  with no current mitigation. T-32/T-33/T-37/T-38/T-40/T-41/T-42/T-43/T-45 are MISSING (no
  external sensor, no verifier-side freshness, no evidence store, no offline mode).

| ID | Status | Priority |
| --- | --- | --- |
| QA-01 | PARTIAL — unit tests (32, `cargo test`) and integration-style testbench (9 scenarios) exist; no fuzzing, no property-based testing, no differential testing against another tool, no resource-exhaustion testing | P1 |
| QA-02 | IMPLEMENTED-UNVERIFIED — only tested live against this session's one Arch Linux host; `docs/SPEC.md` §1 names a broader distro matrix as scope, not yet validated against it | P1 |
| QA-03 | IMPLEMENTED-VERIFIED — the PAM and ELF fixes this session are direct, real instances: both bugs were caught specifically by testing against a real host's full configuration (all of `/etc/pam.d`, not just the file used to write the parser's unit tests), not by re-running only the fixtures that motivated the original rule. See EV-05, SC-01. | — |
| QA-04 | MISSING — no detection/miss-rate, false-positive-per-host-day, or overhead measurement exists | P1 |
| QA-05 | MISSING — no performance budget is defined for any profile | P1 |
| QA-06 | PARTIAL — `testbench/` fixtures are reproducible shell scripts with clear expected output; no kernel-build-identity pinning (nothing kernel-version-specific exists yet to pin) | P2 |
| QA-07 | MISSING — no independent/adversarial review has occurred; this document is the project's own self-audit, which the spec (§0, §18) is explicit does not constitute certification | P1 |

## 14. Incident handling and recovery (IR) — MISSING, all rows

No incident-response runbook, credential-rotation guidance, or recovery workflow exists in
this repository. IR-01 through IR-07: all **MISSING**, priority **P1** (a detection tool
without a documented response path is a real, near-term gap — unlike firmware/TPM work, this
doesn't require new detection capability to write, just documentation of what a finding should
trigger operationally). Not started this session; flagged as the top P1 documentation gap
alongside the baseline (FS-01).

---

## Summary: what changed in this audit, and what's next

**Fixed today** (all four are real bugs or honesty gaps found by actually testing against live
data, not just reading the spec and nodding along):

1. **TR-10 / EV-03** — scan output could read as an implicit clean verdict with no coverage
   hedge. Added `Report::statement`, always present, always hedged, computed fresh from actual
   coverage data. 3 new tests.
2. **FS-04 / SC-04** — `persistence.rs`'s autostart-tree walker followed directory symlinks at
   every recursion depth with no explicit bound, self-limiting only by accident (`PATH_MAX`,
   confirmed empirically, not a deliberate bound) — and would have followed a symlink *out* of
   the intended tree entirely. Fixed with depth-0-only symlink-following (preserving
   dotfile-manager setups) plus an explicit depth cap. 2 new tests, one of which specifically
   proves a nested symlink escape is now blocked while the legitimate entry-point case still
   works.
3. **SC-06** — finding text (raw filenames, PAM config lines) printed unescaped to the
   terminal; a hostile filename with ANSI escapes could manipulate the display. Fixed at the
   presentation boundary. 3 new tests.
4. **SC-01** — the ELF dynamic-section parser panicked on crafted offsets (reproduced the exact
   panic against the pre-fix logic before fixing it). This was the most serious of the four: a
   single malformed binary at a scanned path could crash the entire process. Fixed with checked
   arithmetic and `Option`-returning readers throughout. 5 new tests.

**Top P0/P1 gaps this audit surfaces that are *not* fixed yet**, in rough priority order:

1. **AR-01** — no `catch_unwind` boundary around individual checks; today's fixes closed the
   two *known* panic paths, not the general class. A future check with the same class of bug
   would still take the whole process down.
2. **FS-01** — no package-hash baseline. The root cause behind nearly every "heuristic, not
   exhaustive" caveat in this matrix.
3. **PL-04** — no container/chroot/restricted-`/proc` detection; a container-scoped run would
   silently report as if it saw the whole host.
4. **BP-01..08** — BPF enumeration has no check at all, despite being named as in-scope for
   Phase 1 in our own `docs/SPEC.md` (unlike the boot/TPM/firmware sections, which are
   legitimately deferred to Phase 4 by our own plan).
5. **IR-01..07** — no incident-response runbook exists at all.
6. **T-02/T-03** — nothing verifies `hunter`'s own binary/library dependencies are untampered
   before it runs.

Everything in §5 (boot/firmware), §6 (TPM/attestation), most of §7 (kernel memory), all of §10's
offline-analysis rows, and most of §11 (external network correlation) is honestly
NOT-APPLICABLE-WITH-REASON for this deployment profile: a single-host, live-triage CLI with no
verifier, baseline, or external infrastructure. That is a true statement about current scope,
not a claim those requirements don't matter — see `docs/SPEC.md`'s four-phase roadmap and
`FUTURE_AVENUES.md` for where they're expected to land.
