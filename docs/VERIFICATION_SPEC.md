# Linux Anti-Rootkit Engineering and Verification Specification

*Version 1.0 | Research checked: 2026-10-24 | Audience: implementation agent, reviewers, defenders*

*Supplied by the project owner on 2026-10-24 as the audit contract this codebase is now
measured against. Reproduced verbatim below; see
[`VERIFICATION_MATRIX.md`](VERIFICATION_MATRIX.md) for the requirement-to-code
traceability audit and [`CLAUDE.md`](../CLAUDE.md) for how it relates to the engineering
rules already in force. This document itself establishes nothing about the current
implementation — every status claim lives in the matrix, derived from actual code and
tests, not from this document's requirement language.*

---

## 0. Assignment to the coding agent

Audit the existing implementation against this specification before adding more detection
rules. Build a defensible Linux compromise detection and integrity verification system for
environments facing highly capable adversaries. Preserve existing working behavior and user
changes. Do not claim nation-state immunity, exhaustive detection, attribution, or universal
proof of cleanliness.

This is a comprehensive review baseline, not evidence that the existing product meets any
requirement. No repository or current implementation was provided when this specification was
written. Every implementation status begins UNASSESSED. Requirements below are proposed
engineering requirements; sources establish relevant mechanisms and limits, not certification of
this design.

For every requirement ID, produce a traceability row containing: implementation status, exact
code location, evidence source, privilege requirement, supported environments, trust
dependencies, failure behavior, tests, remaining limitation, and priority. Use
IMPLEMENTED-VERIFIED, IMPLEMENTED-UNVERIFIED, PARTIAL, MISSING, UNSUPPORTED, or
NOT-APPLICABLE-WITH-REASON. Never infer implementation from a function name, comment,
dependency, or empty test.

Deliver: a threat model; architecture and trust-boundary document; requirement-to-code matrix;
prioritized gaps; code fixes; meaningful tests; reproducible validation results;
machine-readable report schema; operator response runbook; explicit unsupported-environment
list. Work in small reviewable changes. Do not silently replace the architecture or weaken
existing protections to make a check work.

## 1. Security contract and adversary model

- TR-01: Model an attacker who already has host root, can replace utilities and libraries,
  alter files and package databases, change namespaces, and kill or impersonate the agent.
- TR-02: Separately model arbitrary kernel execution, including malicious modules, kernel
  exploitation without modules, data-only manipulation, and falsified kernel interfaces. A clean
  module list does not address all these threats.
- TR-03: Include bootloader/initramfs compromise, firmware/BMC compromise, malicious
  hypervisors, compromised update infrastructure, and signing-key theft. State which are
  detectable, preventable, externally assessable, or outside coverage.
- TR-04: Include short-lived implants, memory-only execution, legitimate tools used
  maliciously, credential theft, persistence without a rootkit, and attacker-induced telemetry
  loss. Rootkit detection is a subset of compromise detection.
- TR-05: Define protected assets: code, credentials, data, boot state, workload identity,
  evidence, policy, baselines, collector and verifier availability.
- TR-06: Define the trusted computing base for every deployment. An in-guest verifier cannot
  establish a hostile hypervisor's honesty. A BMC is not automatically a trustworthy independent
  observer.
- TR-07: Treat first enrollment on an unknown host as an untrusted observation, never as an
  approved clean baseline.
- TR-08: Treat attacker attribution as out of scope for automated verdicts. Similarity to a
  known implant is not actor attribution.
- TR-09: Publish coverage separately for local live collection, remotely verified measurements,
  offline disk examination, externally acquired memory, and platform firmware assessment.
- TR-10: Never produce an unconditional CLEAN or NOT-HIJACKED verdict. Use scoped conclusions
  with time, measurement coverage, unavailable checks, and assumptions.

Threat rationale: NSA/FBI documented Drovorub as a Linux implant paired with a kernel rootkit
[S1]. ESET's Bootkitty analysis demonstrates Linux boot-path tampering, but its updated report
identifies that sample as a limited proof of concept, not an established nation-state deployment
[S2]. Neither family defines the full threat model.

## 2. Architecture and evidence independence

| Component | Required responsibility | Trust limit |
| --- | --- | --- |
| Minimal privileged collector | Bounded acquisition using explicit interfaces | Host kernel can falsify results |
| Unprivileged analysis workers | Parse and correlate hostile artifacts | Input is untrusted; workers must be isolated |
| External verifier | Validate evidence freshness, identity, signatures and policy | Depends on its own infrastructure and measurement roots |
| Trusted baseline service | Store signed approved artifacts and policy history | Compromised publisher/signing authority can poison trust |
| External telemetry collectors | Supply network, identity, orchestration and platform observations | Their visibility and administrative independence must be established |
| Offline analysis environment | Examine acquired storage and memory with trusted tools | Acquisition and underlying hardware still impose limits |

- AR-01: Separate collection, parsing, assessment, attestation, reporting, and response. A
  parser failure must not crash the entire scan or grant a pass.
- AR-02: Record an evidence dependency graph. `ps` and `/proc`, `lsmod` and `/proc/modules`, and
  `ss` and kernel netlink are not independent of the host kernel.
- AR-03: A direct syscall collector or trusted static binary may reduce user-space interception;
  it does not bypass a compromised kernel. Preserve this distinction in UI and scoring.
- AR-04: Hashing files from the suspect host, even with trusted hash code, still depends on the
  host's read path. Raw-device reads through that kernel also remain host-mediated.
- AR-05: Correlate local checks without multiplying confidence for common dependencies.
  Different interfaces can expose discrepancies without proving kernel integrity.
- AR-06: Permit fully offline analysis and deterministic re-analysis from saved evidence. Report
  differences between acquisition-time facts and later interpretation.
- AR-07: Establish separate administrative credentials and access boundaries for verifier,
  evidence storage, baseline publication, and endpoint administration.
- AR-08: Prefer established attestation, cryptographic, and forensic components over inventing
  replacements. Pin supported versions and verify their actual APIs.
- AR-09: Provide explicit scan profiles: low-impact live triage, continuous monitoring,
  privileged deep inspection, offline storage analysis, and external memory/platform analysis.
  Do not silently escalate profiles.
- AR-10: Maintain a residual-risk register. More checks within one trust boundary do not
  substitute for another trust boundary.

## 3. Result model, coverage and evidence

- EV-01: Separate execution status from assessment. Execution: COMPLETE, PARTIAL, UNSUPPORTED,
  DENIED, TIMEOUT, ERROR, NOT-APPLICABLE. Assessment: NO-ANOMALY-OBSERVED, ANOMALY,
  POLICY-VIOLATION, KNOWN-MALICIOUS-MATCH, INCONCLUSIVE. Only completed eligible checks can
  report no anomaly.
- EV-02: Every finding includes stable check ID and rule version; host enrollment identity and
  claimed boot ID; collection start/end; verifier receipt time; collector build; collection
  method; namespace context; artifact identity; evidence hashes; trust dependencies; expected
  versus observed state; severity; confidence rationale; alternatives; and next action.
- EV-03: Every report includes the policy-defined check denominator, completed checks, partial
  checks, blind spots, excluded scopes, inaccessible paths, missing privileges and stale
  measurements. A zero-finding report with missing critical checks must remain incomplete.
- EV-04: Store original bytes or a bounded evidence reference where permitted. Preserve stderr,
  exit status, parser version, truncation flags, and acquisition errors. Empty output is not a
  successful negative finding.
- EV-05: Keep severity, confidence and coverage separate. Do not label arbitrary scores as
  probabilities. A high-confidence configuration weakness is not automatically a confirmed
  infection.
- EV-06: Use signed manifests and content hashes for acquired artifacts; preserve acquisition
  identity and custody events. Hashes prove subsequent byte consistency, not that the original
  acquisition was honest.
- EV-07: Use verifier-generated freshness challenges where appropriate, sequence numbers,
  authenticated transport and durable remote acknowledgments. Detect gaps, duplicate sequences,
  replay, clock rollback and restarted sessions.
- EV-08: Record host wall time, monotonic timing and external receipt time separately.
  Host-provided time and boot identifiers are claims, not independent trust anchors.
- EV-09: Protect evidence with access controls, encryption, retention policies and explicit
  sensitive-data handling. Memory and process environments can contain secrets; collection must
  be minimized and auditable.
- EV-10: Preserve findings across interrupted runs and crashes. A damaged report must not parse
  as successful completion. Define stable exit codes separately from full machine-readable
  results.
- EV-11: Suppressions must identify exact rule, artifact or narrowly scoped behavior, owner,
  justification, expiry and policy signature. Keep suppressed findings auditable. Broad path or
  process-name exclusions require explicit review.
- EV-12: Remote heartbeat loss means loss of visibility, with possible tampering, not automatic
  confirmed compromise and never continued health.

Example summary contract:

```json
{
  "schema_version": "1.0",
  "verdict": "INCONCLUSIVE",
  "scope": "live-host",
  "kernel_integrity_independently_established": false,
  "coverage": {"required": 120, "complete": 107, "partial": 3, "unavailable": 10},
  "findings": [],
  "critical_blind_spots": ["external-memory-acquisition-unavailable"],
  "statement": "No anomalies observed in completed checks; kernel compromise is not excluded."
}
```

The numbers are illustrative, not measured product coverage. Applicable-check rules must be
signed/versioned so the collector cannot quietly shrink the denominator.

## 4. Platform discovery and support boundaries

- PL-01: Inventory architecture, kernel build identity/configuration, distribution, libc, init
  system, filesystem types, mounts, virtualization, container runtime, cgroup version and
  namespace context. Treat local inventory as untrusted claims until corroborated.
- PL-02: Maintain a tested matrix for supported kernel builds and architectures. Do not reuse
  struct offsets across kernels or assume BTF/symbols prove memory authenticity.
- PL-03: Probe features and permissions rather than relying only on version numbers.
  Distinguish kernel-disabled, permission-denied, absent mount, unsupported ABI and actual empty
  inventory.
- PL-04: Detect restricted `/proc`, user namespaces, containers, chroots, bind-mounted
  substitute trees, masked paths, missing host mounts, and inaccessible namespaces. A container
  scan must not claim full-host coverage.
- PL-05: Cover rootless and privileged workloads explicitly. State whether host, container and
  nested namespace inspection is implemented or only planned.
- PL-06: Document architecture-specific kernel inspection separately, including x86-64 and
  arm64 support. Unsupported low-level checks must degrade explicitly.

## 5. Boot, firmware, and kernel admission

- BT-01: Inventory the effective boot chain: firmware identity, boot entries/order, EFI system
  partitions, fallback boot paths, shim/bootloader, kernel or UKI, initramfs, embedded/external
  command line and relevant early-boot configuration.
- BT-02: Verify artifacts against independently approved signed manifests, including generated
  initramfs/UKI artifacts and their authorized creation pipeline. Hash mismatch is evidence of
  change, not by itself proof of malice.
- BT-03: Record Secure Boot state, Setup Mode, authorized key databases, revocations,
  shim/MOK state where applicable, and policy changes. Inspect effective validation boundaries;
  a single enabled flag is insufficient.
- BT-04: Check rollback exposure for approved but vulnerable boot components and firmware
  against maintained vendor policy. Signed is not synonymous with current, authorized for this
  host, or safe.
- BT-05: Check module signature enforcement separately from the capability to verify
  signatures. Inventory trusted signing keys, unexpected key enrollment and effective admission
  policy [S3].
- BT-06: Record lockdown and relevant runtime enforcement state, kernel command-line changes,
  kexec policy, module-load policy and debug interfaces. Distinguish hardening gaps from
  observed compromise.
- BT-07: Inventory installed modules, built-in module metadata, DKMS outputs, module loading
  configuration, blacklists and dependencies. Associate them with expected kernel builds and
  approved provenance.
- BT-08: Include legacy BIOS/boot sectors when supported. Mark UEFI-specific checks not
  applicable rather than assuming all hosts use UEFI.
- BT-09: Treat firmware, option ROMs, BMC, storage/NIC firmware and management-plane access as
  separate coverage domains. Record what was measured, inventoried, independently read, or not
  assessed.
- BT-10: Do not claim firmware integrity from vendor strings, an OS firmware version, or a clean
  EFI partition alone. External verification/recovery may require vendor tooling and
  hardware-specific procedures.
- BT-11: Assess IOMMU/DMA protection and virtualization trust where applicable; do not claim
  these settings prove absence of device or physical compromise.
- BT-12: Provide platform recovery requirements, including authenticated firmware recovery and
  compromised management credentials. Follow the protect/detect/recover structure of NIST SP
  800-193 without claiming compliance from a checklist [S4].

## 6. TPM, measured boot and runtime integrity

- AT-01: Bind enrollment to the intended machine and attestation key using a validated
  provisioning process. Evaluate relay/cuckoo risks and identity substitution; a valid quote
  from some TPM is insufficient.
- AT-02: Verify quote signatures, nonce freshness, selected PCRs, banks, algorithm policy, key
  identity and evidence consistency using established libraries. Reject malformed, stale or
  unexpected evidence.
- AT-03: Replay boot measurement logs to the quoted PCR state and separately evaluate the events
  against an approved semantic boot policy. Internal consistency is not authorization.
- AT-04: Explicitly configure PCR selections per platform and boot stack. Do not hard-code a
  universal mapping or ignore runtime-extended PCRs without documenting why [S5].
- AT-05: Reject permissive accept-all behavior for production policy enforcement. Negative tests
  must prove that a cryptographically valid but unauthorized boot fails policy.
- AT-06: Validate IMA measurement logs against relevant attested state and approved file policy;
  distinguish measurement, appraisal, audit and enforcement. Record policy scope and the
  beginning of measurement coverage.
- AT-07: Document exclusions: unmeasured paths, interpreters and scripts, dynamic
  configuration, JIT/memory-only code, data-only changes and workloads outside the measurement
  policy. Passing attestation does not establish all runtime memory is clean.
- AT-08: Validate EVM or equivalent metadata protection where deployed. Do not silently assume
  measuring file content protects all ownership, capability, label or other metadata changes.
- AT-09: Record authenticated roots/digests and effective enforcement for dm-verity/fs-verity. A
  locally supplied root hash without trusted provenance does not establish authenticity [S6,
  S7].
- AT-10: Define policy transitions for package, kernel, firmware and authorized configuration
  updates, including rollback controls. Never auto-approve observed drift after attestation
  failure.
- AT-11: Treat vTPM trust as dependent on the virtualization platform and provisioning model.
  Hardware presence, a TPM quote, and trusted measurement generation are distinct concepts.
- AT-12: Expire attestation decisions and bind them to intended authorization scope. A
  successful measurement at time T is not an indefinite health token.
- AT-13: Test verifier compromise containment, key rotation/revocation, enrollment recovery,
  policy rollback, unavailable TPMs and disconnected hosts.

Keylime explicitly describes dependence on the measuring environment and verifier deployment
[S8]. Adopt that distinction: hardware certification of measurements does not magically make
compromised measurement producers truthful.

## 7. Kernel runtime, hooks and memory

- KR-01: Compare available loaded-module views, sysfs representation, executable kernel regions
  and acquired-memory results. Explain which all share kernel mediation and which came from
  external acquisition.
- KR-02: Validate module identity, build compatibility, signatures, executable range ownership
  and expected provenance. An unexpected module is a finding requiring context; an approved name
  is not authentication.
- KR-03: Where supported, inspect syscall dispatch and other security-relevant function
  pointers against expected executable regions and version-correct ownership. Do not assume
  syscall-table inspection covers modern implants.
- KR-04: Cover tracing hooks, kprobes, ftrace, livepatch, LSM-related state, relevant
  filesystem and networking callbacks, and other supported hook surfaces. Specify exact
  per-kernel coverage instead of claiming all hooks.
- KR-05: Normalize legitimate kernel text changes from relocations, alternatives, jump labels,
  static calls, ftrace, livepatch and architecture-specific transformations before comparison. A
  raw on-disk versus RAM hash comparison is not sufficient.
- KR-06: Authenticate approved patches/instrumentation by build, origin and policy. Do not
  broadly exempt all livepatch or tracing changes. Linux legitimately supports runtime function
  redirection [S9, S10].
- KR-07: Look for executable memory without expected ownership and suspicious
  mapping/protection relationships where visibility permits. Report BPF JIT, legitimate
  trampolines and supported exceptions explicitly.
- KR-08: Add data-only integrity checks where supported: credential relationships, process/module
  membership inconsistencies, security state changes and selected invariant violations. Document
  incomplete coverage and valid shared structures.
- KR-09: Use correct build symbols and validate memory-image compatibility before analysis.
  Wrong symbols must produce an error or inconclusive assessment, not empty results.
- KR-10: Integrate established memory-analysis plugins with exact version and symbol
  requirements; do not reimplement complex reconstruction without justification [S11].
- KR-11: Mark locally obtained memory dumps as potentially attacker-mediated. Prefer trusted
  external acquisition where available, with a stated hypervisor/platform trust model.
- KR-12: Never disable lockdown or load an unsigned module automatically just to inspect
  memory. Additional acquisition tooling must have an explicit integrity and perturbation
  assessment.
- KR-13: Account for acquisition smear and live races. Externally obtained memory can still be
  incomplete or inconsistent unless acquisition semantics establish a coherent snapshot.
- KR-14: Cover suspicious user-space mappings and injected code through a separate
  process-memory workflow; do not treat every executable anonymous mapping as a rootkit.

## 8. eBPF and tracing coverage

- BP-01: Enumerate accessible BPF programs, maps, links, attachment points and pinned objects,
  including objects not represented by a simple pinned-file walk.
- BP-02: Cover applicable XDP, TC, cgroup, socket, tracing, perf and BPF LSM attachment
  mechanisms. Enumerate legacy/non-link attachment paths as required by the supported kernel.
- BP-03: Record type, tag, available bytecode digest, attachment context, ownership/provenance
  and load-time evidence. Names and program tags alone are not cryptographic authorization.
- BP-04: Evaluate relevant mutable map contents and program-array relationships, not just
  immutable program identity. Bound collection and avoid indiscriminate capture of sensitive map
  data.
- BP-05: Discover bpffs mounts in the relevant mount namespaces. Do not assume `/sys/fs/bpf` is
  the only mount or that all objects are pinned.
- BP-06: Model permitted observability agents, networking systems and security tools using
  precise policies. Legitimate BPF activity must have benign regression fixtures.
- BP-07: Monitor changes when the deployment supports continuous collection; report missed
  events, buffer drops and start-time gaps. A snapshot can miss transient programs.
- BP-08: Treat BPF telemetry as host-kernel-dependent. BPF instrumentation must not be
  advertised as an independent root of trust against kernel compromise.

Linux BPF documentation and bpftool distinguish programs, maps, links and pinning; pin
inspection alone is not a complete inventory [S12, S13].

## 9. Processes, credentials and execution

- PR-01: Correlate process/task enumeration, per-process inspection, open descriptors, cgroups,
  namespace membership, execution events and external memory reconstruction where available.
- PR-02: Identify processes using boot/session context, namespace, PID and start time; use
  stable handles where supported. Handle PID reuse, exit, zombie tasks and short-lived
  processes.
- PR-03: Inspect executable identity, mapped libraries, interpreter, command line, parent
  lineage, working/root directories and deleted/memfd executable artifacts within collection
  policy.
- PR-04: Compare mapped executable code with approved provenance where technically valid.
  Account for relocations, COW changes, JIT runtimes, instrumentation and legitimate deleted
  binaries after upgrades.
- PR-05: Inspect effective credentials, capabilities, user-namespace mappings, security labels
  and unexpected privilege transitions. Container root and host root are not equivalent.
- PR-06: Include loader configuration, preload/audit mechanisms and suspicious library search
  paths. Merely clearing `LD_PRELOAD` does not eliminate every user-space interception path.
- PR-07: Examine authentication and access policy drift: PAM, NSS, SSH includes and key
  authorization mechanisms, sudo/polkit, privileged accounts and service identities.
- PR-08: Distinguish known malicious executable evidence, unexpected execution, weak
  configuration and normal administration. Never decide based only on process name, filename or
  an open port.
- PR-09: Do not execute suspect files or invoke `ldd` on untrusted binaries as an inspection
  technique. Parse binary metadata with bounded non-executing tools.
- PR-10: Detect unexplained credential/policy changes using independent identity or
  orchestration logs where available. Local audit records alone can be deleted or forged after
  compromise.

## 10. Filesystem, package provenance and persistence

- FS-01: Compare file content and relevant metadata with independently authenticated package
  artifacts or signed organization manifests. A local package database is evidence, not a trust
  anchor.
- FS-02: Cover executables, libraries, kernel artifacts, interpreters, security configuration,
  service definitions and privileged scripts. Include unexpected additions and deletions, not
  just changed known files.
- FS-03: Track ownership, modes, capabilities, ACLs, relevant extended attributes, security
  labels, hardlinks, symlinks, mount identity and immutable flags. Timestamps are weak evidence.
- FS-04: Use descriptor-relative traversal and safe resolution policies. Prevent symlink/path
  substitution, mount escape and TOCTOU confusion; record whether a coherent snapshot was
  available.
- FS-05: Check metadata before and after content acquisition, flag unstable files and use
  snapshots where practical. Stat stability does not prove absence of adversarial kernel
  manipulation.
- FS-06: Handle overlayfs layers/whiteouts, bind mounts, FUSE, network filesystems, encrypted
  volumes, sparse files and storage snapshots according to explicit support profiles. Never
  silently omit a filesystem.
- FS-07: Enumerate systemd system/user units, drop-ins, symlinks, timers, sockets, paths,
  transient units, generators and environment generators. Inspect configuration without
  executing suspect generators [S14, S15].
- FS-08: Include applicable cron/anacron/at jobs, SysV/OpenRC startup, rc.local, udev rules,
  module-loading configuration, boot hooks and initramfs builders.
- FS-09: Include shell startup, desktop autostart, SSH authorization changes, PAM/NSS plugins,
  dynamic-loader configuration and interpreter/runtime startup hooks within the selected
  profile.
- FS-10: Include container image provenance, writable layers, runtime configuration/hooks,
  orchestration manifests, privileged mounts, device plugins and host-side workload persistence.
- FS-11: Distinguish distribution-managed, locally built and unmanaged artifacts. For Arch/AUR
  and other local-build workflows, require separate build provenance/manifests rather than
  pretending package-manager presence authenticates upstream code.
- FS-12: Examine offline filesystem images on a trusted analysis host with read-only semantics
  and no journal replay where supported. Prefer isolated parsers for hostile filesystem
  metadata; mounting it exposes an analysis kernel to parser risk.
- FS-13: Document unmounted partitions, inaccessible encrypted data and unsupported filesystems
  as gaps. Offline scanning does not recover volatile-only implants lost at shutdown.
- FS-14: Do not describe container image digest approval as proof of host or runtime integrity.
  Runtime changes and stolen workload credentials remain separate concerns.

## 11. Network and independent observations

- NW-01: Inventory interfaces, namespaces, routes/rules, listeners, sockets, tunnels,
  firewall/NAT policy, proxies, DNS settings and relevant packet-processing attachments.
- NW-02: Correlate sockets with owning processes, credentials, cgroups and namespaces; handle
  shared descriptors, short-lived sockets and races explicitly.
- NW-03: Compare host claims with independent switch/TAP/firewall/flow/DNS/proxy observations
  where available. Record network topology, NAT, attribution uncertainty, sampling and missing
  visibility.
- NW-04: Distinguish unexplained traffic from confirmed command-and-control. Legitimate
  encryption and uncommon destinations are not infection proof.
- NW-05: Validate external sensor coverage using controlled traffic. Host packet capture shares
  the compromised kernel's trust boundary and may miss filtered activity.
- NW-06: Identify local policy drift that redirects traffic or bypasses monitoring. Do not
  assume all traffic traverses one interface or the default network namespace.
- NW-07: The scanner must not contact suspected command-and-control infrastructure to test it.
  Use existing evidence and controlled analysis environments.
- NW-08: Treat loss of remote evidence transport as a coverage incident. Store bounded local
  evidence, report backlog and use an independent control plane for containment when available.

## 12. Collector, parser and supply-chain security

- SC-01: Minimize privileged code and isolate parsers. Prefer memory-safe implementations for
  new hostile-input parsing; audit any unsafe/FFI boundary and bound all allocations.
- SC-02: Never concatenate untrusted paths, process arguments or artifact text into shell
  commands. Use fixed executables, argument vectors, sanitized environment and explicit working
  directory.
- SC-03: Pin and verify tools before trusting their output. Absolute paths alone do not
  authenticate binaries; do not depend on suspect shell profiles, aliases or PATH.
- SC-04: Enforce timeouts, byte/file/object/depth limits, decompression ratios, regex
  complexity limits and global scan budgets. Treat truncation as incomplete evidence.
- SC-05: Handle FIFOs, devices, sockets, unreadable files and hostile pseudo-files without
  indefinite blocking. Bound subprocess trees and ensure cancellation/reaping works.
- SC-06: Escape control characters and markup in logs/UI. Preserve raw bytes separately; test
  invalid UTF-8, embedded newlines, terminal escapes and hostile filenames.
- SC-07: Use private temporary directories, no-follow creation, restrictive permissions,
  atomic commits and durable completion manifests. Never overwrite an attacker-selected path.
- SC-08: Treat evidence as data, including when summarized by an LLM. Embedded instructions
  must not alter policy, trigger tools, suppress findings or authorize response actions.
- SC-09: Sign releases, policies and detection content; protect update roots; prevent
  rollback/freeze according to deployment policy; support revocation and recovery.
- SC-10: Generate SBOM and build provenance, pin dependencies, review build scripts and CI
  permissions, and test release artifact reproducibility where feasible. Reproducibility is not
  by itself proof against a compromised toolchain.
- SC-11: Keep signing secrets away from scanned hosts. Local agent signing can authenticate
  possession of a key but does not prove measurement truth after host compromise.
- SC-12: Authenticate control-plane requests, authorize per operation, prevent replay, separate
  operator roles and audit policy changes. An attacker-controlled collector must not attack the
  verifier through oversized evidence.
- SC-13: Add external watchdogs and update/rollback monitoring. Local self-checks and process
  restarts cannot ensure survival against arbitrary kernel control.
- SC-14: Default to observation. Never automatically delete files, unload modules, kill tasks,
  detach BPF, reboot, reflash firmware or rewrite boot state during scanning.
- SC-15: Make response actions separate, authenticated and idempotent with explicit deployment
  policy, evidence preservation and bounded scope. Strong containment may be performed
  externally rather than trusting the host.

## 13. Test laboratory and adversarial validation

Use isolated disposable VMs and dedicated firmware-capable lab hardware as appropriate. No
production deployment of rootkits or destructive persistence. Prefer controlled benign fixtures
and recorded forensic images; malware samples, if used by authorized researchers, require
separate lab procedures. Tests must measure the detector, not merely mirror its branches.

For every supported detector require: a positive fixture, a realistic benign near-match,
unavailable evidence, malformed evidence, privilege restriction and relevant race/truncation
case. Every fixture has an expected execution status, assessment, required evidence and
prohibited overclaim.

| ID | Scenario | Required result |
| --- | --- | --- |
| T-01 | Clean approved host | No unexpected findings; exact coverage shown |
| T-02 | Replaced local utility producing clean-looking output | Trusted collection comparison detects discrepancy or declares trust limitation |
| T-03 | User-space preload interference | Detection/collection integrity failure without claiming kernel independence |
| T-04 | Approved file altered while local package metadata is also altered | Independent manifest comparison catches drift |
| T-05 | Unknown first-run host | Baseline untrusted; no automatic enrollment as clean |
| T-06 | Authorized upgrade and deleted mapped executable | Correct benign explanation; no unsupported malware verdict |
| T-07 | Unauthorized startup entry, including user service or generator | Evidence identifies effective persistence path |
| T-08 | Memfd/JIT/deleted executable corpus | Suspicious and legitimate cases distinguished by context |
| T-09 | Controlled process/module view mismatch in forensic fixtures | Discrepancy detected; acquisition limits retained |
| T-10 | Approved versus unapproved hook/livepatch fixtures | Correct normalization and policy distinction |
| T-11 | Data-only tampering fixture | Relevant invariant failure or explicit documented coverage gap |
| T-12 | Approved BPF networking/observability deployment | No blanket BPF-as-malware verdict |
| T-13 | Unexpected BPF program/link/map relationship | Attachment and provenance finding with supporting evidence |
| T-14 | Changed map with unchanged program identity | State-sensitive policy notices relevant drift |
| T-15 | Unpinned or legacy BPF attachment fixture | Not missed solely because bpffs is empty |
| T-16 | Modified kernel/initramfs/EFI artifact | Independent artifact validation fails |
| T-17 | Signature valid but artifact unauthorized or rolled back | Policy rejects despite cryptographic validity |
| T-18 | Secure Boot enabled but changed trust enrollment | Unauthorized trust change reported |
| T-19 | Valid TPM signature with stale nonce or wrong identity | Attestation rejected |
| T-20 | Quote/log mismatch or missing measurement segment | Invalid/incomplete attestation, never pass |
| T-21 | Log consistent with quote but unauthorized boot | Semantic policy fails |
| T-22 | Measurement policy omits target artifact | Coverage gap explicitly demonstrated |
| T-23 | vTPM or hypervisor trust changed | Assurance model changes; no hardware-independence claim |
| T-24 | Agent killed, stalled, replayed or disconnected | External visibility alarm with last-valid time |
| T-25 | Event flood and ring-buffer drops | Loss counters/gaps surfaced; scan cannot silently pass |
| T-26 | Container-only collector | Scope constrained; missing host visibility recorded |
| T-27 | PID/network/mount namespace differences | Correct context-aware correlation |
| T-28 | PID reuse, process exit and rapid socket churn | No identity conflation; bounded retry/inconclusive behavior |
| T-29 | File changes, symlink swaps, bind mounts during scan | No traversal escape; unstable acquisition reported |
| T-30 | Permission denied, hidden procfs, absent tracefs, lockdown | Specific unavailable reason, no empty-list pass |
| T-31 | Wrong symbols, truncated memory image, unsupported kernel | Analysis rejected or explicitly partial |
| T-32 | Forged local network view versus lab TAP evidence | Independent discrepancy surfaced |
| T-33 | Clock rollback, reboot, sequence replay and reordering | Freshness/session checks fail appropriately |
| T-34 | Malformed ELF, archive, TPM log, netlink and filesystem metadata | No crash, code execution, unbounded resource use or false pass |
| T-35 | FIFO/device path, compression bomb, extreme object count | Bounded termination and partial/error result |
| T-36 | Hostile filename, terminal escape, HTML and prompt injection | Safe rendering; content never becomes instructions |
| T-37 | Evidence store full, permission failure, partial report | Failure durable and visible; no success marker |
| T-38 | Unauthorized policy suppression or baseline rollback | Rejected and audited |
| T-39 | Verifier/API evidence flood and malformed requests | Bounded resource use and tenant/host isolation |
| T-40 | Normal DKMS, livepatch, containers, FUSE, overlayfs and local builds | Valid variations handled or explicitly unsupported |
| T-41 | Shutdown/offline analysis loses memory-only fixture | Report acknowledges volatile evidence loss |
| T-42 | Compromised-kernel fixture supplies mutually consistent false views | No claim that local consistency proves integrity |
| T-43 | Interrupted scan and restart | No mixed-host/mixed-boot evidence or fabricated completion |
| T-44 | Signing key revoked, expired policy or failed update | Defined degraded state and recovery path |
| T-45 | Configuration weakness without active implant | Hardening finding, not fabricated confirmed compromise |
| T-46 | Detection removed/disabled deliberately in test build | Suite catches regression; demonstrates meaningful assertions |

- QA-01: Run unit, integration, parser fuzz, property/invariant, differential, end-to-end and
  resource-exhaustion tests according to risk. Include parser failures in the end-to-end report
  path.
- QA-02: Test supported distributions/kernel builds and realistic benign workloads, including
  security tools, orchestration, livepatch and package updates. Publish matrix-specific results.
- QA-03: Separate training/tuning fixtures from held-out evaluation cases. Do not report
  success against only artifacts used to write the rules.
- QA-04: Measure per-scenario detection and miss rates, false positives per host-day, time to
  detection, sensor-loss detection time, CPU/RAM/I/O overhead and event loss under load. Report
  sample sizes and conditions, not a single marketing accuracy percentage.
- QA-05: Define numeric performance/latency budgets before release for each profile. If target
  hardware/workload is unspecified, leave the release gate unfulfilled rather than inventing
  success thresholds.
- QA-06: Retain fixture provenance, expected outputs, tool/kernel build identities and
  reproducible test commands. Re-run affected suites after kernel, parser, policy or detection
  changes.
- QA-07: Obtain independent security review and authorized adversarial evaluation before making
  high-assurance claims. Internal checklist completion is not certification.

## 14. Incident handling and recovery

- IR-01: Provide a finding-specific response path: confirm evidence, preserve volatile data
  where feasible, contain externally when needed, acquire storage/memory, assess identity and
  firmware scope, and rebuild from trusted sources.
- IR-02: Explain the containment-versus-volatile-evidence tradeoff. Do not automatically reboot
  or power off a suspect host before an operator considers evidence loss and active harm.
- IR-03: Treat confirmed kernel compromise as loss of trust in host outputs and credentials
  accessible during compromise. Cleaning one observed artifact does not re-establish trust.
- IR-04: Rotate affected credentials from a trusted environment after containment, including
  workload, SSH, management-plane and signing credentials as applicable. Avoid exposing
  replacement secrets to the suspect host.
- IR-05: Rebuild/recover using authenticated sources, close the entry path, validate
  boot/platform state, re-enroll identities and establish a new approved baseline through an
  external process.
- IR-06: If firmware or hypervisor integrity remains uncertain, escalate to platform-specific
  verification/recovery or replacement. A disk reinstall is not a universal firmware-remediation
  procedure.
- IR-07: Preserve audit history, old policy/baselines, evidence hashes and uncertainty through
  closure. Distinguish remediated observed compromise from unassessed residual risk.

## 15. Priority and release gates

**P0, fix first**: false-clean paths; fabricated completeness; parser/code-execution hazards;
hostile path handling; trust-boundary misstatements; unauthorized baseline/policy changes;
missing telemetry-loss alarms; incorrect attestation identity/freshness; unintended destructive
actions.

**P1, required for the intended high-assurance deployment**: independently authenticated
baselines; external verifier and evidence retention; boot/runtime integrity policy; supported
process, kernel, BPF, persistence and network coverage; tested offline/external investigation
route; controlled release/signing pipeline; operator recovery workflow.

**P2, expand after the trust contract works**: additional architectures/filesystems/kernels,
deeper platform-specific memory invariants, more external sensor integrations, broader behavior
analytics and threat intelligence enrichment. Advanced checks needed by a selected deployment
move to P1; unavailable features remain visible.

Release is blocked until:

1. Every applicable requirement has code/test evidence or an explicit gap; P0 gaps are closed.
2. The selected deployment profile's P1 requirements are fulfilled. Deferred P1 features
   prevent advertising that profile.
3. Mandatory positive, benign, unavailable and hostile-input tests pass on the published support
   matrix.
4. No incomplete/unsupported/error result can become a clean summary through parsing,
   aggregation, exit code or UI rendering.
5. Attestation negative tests prove that authentic but unauthorized state is rejected.
6. External loss-of-visibility detection and evidence-integrity checks work under interruption
   and load.
7. Signed policy/baseline/update rollback and revocation controls are tested.
8. Performance and false-positive budgets are defined and met on representative workloads.
9. Independent review findings are resolved or explicitly accepted by the accountable owner.
10. Documentation states residual risks, source trust, acquisition limits and exactly what a
    passing result establishes.

## 16. Mandatory questions during code review

For every check ask:

1. What precise attacker action or system inconsistency does this detect?
2. Which source supplies the evidence, and who can falsify it?
3. Is a supposedly independent comparison actually the same kernel interface underneath?
4. What happens on empty output, permission denial, timeout, unsupported ABI, parser failure,
   process exit or truncated input?
5. Can the attacker alter the baseline, policy, exclusions, clock or report denominator?
6. What benign system behavior produces the same symptom?
7. What does the test prove beyond successful execution of the implementation?
8. What remains invisible when all local sources agree?
9. Does the finding preserve enough raw evidence for another analyst to reproduce it?
10. Is the stated conclusion narrower than or equal to the evidence?

Reject these shortcuts: root means trusted; static binary means kernel-independent; signed
means safe; Secure Boot flag means runtime clean; matching PCRs mean all memory clean; no
modules means no kernel compromise; empty bpffs means no BPF; missing telemetry means no
activity; a local package database is an external baseline; reboot/reinstall always removes
firmware compromise.

## 17. Research sources and their role

These are primary documentation or original research. They support mechanisms and limitations;
all MUST/requirement language above is this specification's proposed design. Versioned behavior
must be rechecked against the actual deployment. URLs were consulted or located through web
research on 2026-10-24.

- S1: NSA/FBI Drovorub advisory announcement, 2020-08-13. Real Linux kernel-rootkit threat
  context; linked detailed advisory.
- S2: ESET Bootkitty original analysis, 2024-11-27, updated 2024-12-02. Linux bootkit mechanism
  and important proof-of-concept/Secure Boot limitations.
- S3: Linux kernel module signing. Signing support versus enforced admission and trusted keys.
- S4: NIST SP 800-193, Platform Firmware Resiliency Guidelines. Protect, detect and recover for
  platform firmware.
- S5: Keylime measured boot guide. Boot-event reconstruction and policy evaluation.
- S6: Linux dm-verity. Block-device integrity and authenticated root requirements.
- S7: Linux fs-verity. File integrity versus authentication of approved digests.
- S8: Keylime attestation security. Measuring environment, certification and deployment trust
  dependencies.
- S9: Linux livepatch documentation. Legitimate runtime function replacement; this linked
  version is a mechanism reference, not a support-matrix prescription.
- S10: Linux ftrace. Legitimate tracing and runtime instrumentation.
- S11: Volatility 3 Linux plugin documentation. Existing memory-analysis capabilities;
  plugin names/availability depend on pinned version.
- S12: Linux BPF documentation. BPF mechanisms and supported object types.
- S13: bpftool program documentation in Linux source. Program/link pinning and enumeration
  distinctions.
- S14: systemd unit documentation. Unit search paths, transient units and configuration scope;
  adapt to installed version.
- S15: systemd generators. Generated early boot/service configuration.
- S16: Linux integrity subsystem concepts. IMA/EVM concepts and scope.
- S17: Linux Integrity Policy Enforcement. Policy enforcement on integrity-backed properties
  where supported.

## 18. Pasteable instruction for the active coding session

Read this entire specification and audit our current code against every requirement ID. Do not
assume that a feature exists because its name appears in the code. First produce the
requirement-to-code-and-test matrix and identify P0 gaps. Then fix the P0 gaps with regression
tests, preserving our existing work. Continue with P1 requirements for our explicitly supported
deployment profile. For checks requiring capabilities we do not have, implement honest
partial/unsupported reporting and document the integration work; do not fake implementation.
Verify all technical assumptions against the supported Linux/kernel/tool versions. Never
silently lower protections, trust an observed baseline, execute suspect artifacts, or perform
remediation while scanning. Deliver exact code references, reproducible validation results,
remaining blind spots and a truthful assurance statement. The objective is strong evidence under
an explicit adversary model, not a large count of checks or a reassuring green badge.
