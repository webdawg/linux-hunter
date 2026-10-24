# Future Avenues

A brainstorm, not a roadmap — `docs/SPEC.md` §7 and `CLAUDE.md`'s "build order" are the
committed plan. This file is where bigger or more speculative directions get written down
before they're scoped into something committable, so they survive between sessions instead of
being re-derived from scratch every time someone asks "what else could we do?"

Nothing here is approved for implementation just by being listed. Each item should get its own
scoping conversation (and, where it touches licensing, data handling, or external services, an
explicit go-ahead) before code gets written.

## 1. A real research-ingestion pipeline, not a one-time compile

`docs/research/*.md` was compiled once, on 2026-10-18. Malware doesn't stop shipping new
techniques on that date. The useful version of "search the internet for studies and consume
them" is a repeatable pipeline, not a one-off reading session:

- A recurring job (weekly digest cadence seems right — daily is too noisy to read, monthly is
  too slow against a fast-moving field) that pulls new posts from the sources already in
  `sources.md` (Elastic Security Labs, Sysdig, Aqua, Wiz, Synacktiv, Trend Micro, Acronis TRU,
  CISA advisories) plus abuse.ch's feeds, and drafts candidate rows for
  `malware-case-studies.md` / `persistence-techniques.md` / `hiding-techniques.md`.
- Every candidate row gets a status: `cataloged` → `check written` → `test-bench verified`.
  Right now that pipeline exists only as prose in `CLAUDE.md`'s "Current implementation
  status"; it should be a trackable field per technique, not something a reader has to infer.
- Hard constraint carried over from the 2600-article incident: summarize technique *mechanics*
  in our own words, never reproduce someone else's PoC/dropper source into this repo (copyright,
  and it was also what got the original conversation turn flagged).
- Caution: "until we find everything" isn't an achievable stopping condition — SPEC.md §1 says
  this explicitly ("no detector is perfect... the target is to make undetected persistence
  expensive, not to promise it is impossible"). Treat this as a standing process, not a project
  with a finish line.

## 2. Threat-intel and sandboxing integrations

Specific services worth evaluating as optional, explicitly-opt-in data sources (never silently
phoning home — this is a tool people run on boxes they don't fully trust yet):

| Source | What it's good for | Note |
| --- | --- | --- |
| VirusTotal | Hash/IOC lookup, multi-engine verdicts on ELF binaries | API has rate limits on the free tier; useful as a secondary signal, not primary detection (see SPEC §4 — static signatures are a bonus, not the backbone) |
| Intezer Analyze | Code-similarity / family attribution, Linux & IoT-focused | Closest existing thing to "VirusTotal for Linux" |
| abuse.ch (MalwareBazaar, ThreatFox, URLhaus) | Free Linux-tagged sample/IOC feeds | Good seed source for `rules/` once that directory exists |
| Triage (tria.ge) | Automated sandbox detonation, Linux/IoT architectures supported | Useful for test-bench dynamic analysis without running samples ourselves |
| MISP | Threat-intel platform, AGPL-3.0 (same license family) | Already noted in `docs/SPEC.md` §3.14; consuming its feed format is far more realistic than vendoring the platform |
| CISA KEV + OSV.dev | Known-exploited and open-source vuln feeds | Feeds the not-yet-built supply-chain/vuln module (SPEC §3.8) |
| Distro advisories (Debian DSA, RHEL errata, Arch security tracker) | Per-package vulnerability status | Same module |

## 3. GTFOBins-aware SUID/sudo check — done

Built: `src/checks/gtfobins.rs`. Enumerates SUID/SGID binaries in the standard bin/sbin
directories and sudoers-permitted commands (`/etc/sudoers` + `/etc/sudoers.d/*`), cross-
referenced against two name lists derived programmatically from GTFOBins' own data (308 SUID,
455 sudo entries — see `docs/research/sources.md` for provenance and how to re-derive them as
GTFOBins adds entries). Still open: SPEC.md §3.6's "SUID/SGID inventory vs baseline" more
generally — this check flags only binaries with a *documented* GTFOBins technique, not drift
from an expected SUID set, since there's no package-hash baseline yet (see §6 below).

## 4. The "ultimate network analysis tool"

Worth being honest about scope: this is "build a Zeek/Suricata-class deep packet inspection and
flow-analysis engine," which is a materially bigger undertaking than anything in `hunter`
today. `src/checks/network.rs` is a point-in-time socket-table cross-view; a real network
analysis tool is continuous, packet-level, and protocol-aware. Candidate capabilities, roughly
in order of cost:

1. **Flow/connection logging** — who talked to whom, when, how much data, for how long. Cheap
   relative to the rest of this list; mostly bookkeeping on top of what we already read from
   `/proc/net`.
2. **Outbound reputation** — cross-reference destination IPs against Tor exit lists, known C2
   infrastructure, newly-registered domains (already named in SPEC §3.9). Needs a feed, not
   packet capture.
3. **Beaconing/periodicity detection** — regular-interval outbound connections are a strong C2
   signal regardless of payload content. Needs the flow log from (1) plus some time-series math.
4. **Protocol dissection** — DNS tunneling (entropy/length anomalies in queries), TLS
   fingerprinting (JA3/JA3S), raw/packet-socket filters (BPFDoor-style). Needs actual packet
   capture (AF_PACKET or eBPF/XDP), which means new capabilities (`CAP_NET_RAW` or BPF), a much
   bigger parsing surface, and real performance engineering.

Recommendation if this gets picked up: treat it as a separate component (its own binary within
this workspace, e.g. `src/bin/netwatch.rs`, or even a separate repo) rather than folding packet
capture into `hunter`'s single-static-binary, read-only-by-default design. The privilege model
and threat model are different enough that bolting it onto Phase 1 would blur both.

## 5. Claude API integration

Where an LLM genuinely helps versus where it's a liability, for a tool whose entire selling
point is "verbose and inspectable, not a black box":

- **Finding correlation and narrative summary** — feed the structured JSON report (findings +
  coverage) to Claude to synthesize attack chains and write a plain-English "here's what likely
  happened, in what order, do this next." This is a reasonable first implementation of SPEC §6's
  "Correlation, scoring and evidence" (today that's unbuilt — findings are a flat list, not a
  graph) ahead of hand-building a real correlation engine.
- **Finding explanation for less experienced admins** — expand on a specific finding's "why this
  matters" in the context of details the user provides, strictly on-demand.
- **Hard constraint**: must be opt-in, off by default, and never silently send scan output
  anywhere. This is the same principle as rule #5 (read-only by default) and the whole
  transparency philosophy in the README — an LLM call that phones a finding home without the
  user asking for it is exactly the kind of thing this project exists to catch other tools
  doing. Document data handling explicitly if/when this is built.
- Possible offline angle: a self-hosted/local model path for air-gapped deployments, since
  SPEC §4/§7 already wants an air-gapped mode with signed bundles.

## 6. Other avenues worth a line

- **`testbench/` with real VM recipes — started, scoped down.** `testbench/run.sh` exists
  with 6 scenarios, but using unprivileged bubblewrap sandboxing instead of real VMs (none
  available in this environment). Covers userland/filesystem techniques only — see
  `testbench/README.md`'s "Known gaps" for exactly what that excludes (process/network
  scenarios, the DT_NEEDED-injection technique, anything kernel/eBPF-level) and what it'll
  take to extend past it. PANIX/Atomic Red Team integration and real VM recipes remain
  future work for whenever a kernel-level check needs them. `rules/` still doesn't exist.
- **Package-hash baseline** (`internal/baseline` equivalent) — still the biggest structural gap
  per `CLAUDE.md`. Everything in `persistence.rs`/`libraries.rs` today flags by heuristic
  (location, recency, duplication), not "is this file actually owned by the package that claims
  it." This unlocks much lower-false-positive versions of several existing checks, not just new
  ones.
- **Container/Kubernetes module** (SPEC §3.11) — unimplemented. Image scanning (Trivy/Grype
  integration, consistent with the "mere aggregation" model used for Lynis), privileged
  container detection, `docker.sock` exposure.
- **Cloud/IMDS module** (SPEC §3.12) — unimplemented. Relevant the moment this runs on a
  cloud-hosted box rather than bare metal.
- **Fleet aggregation** — a lightweight collector that ingests `hunter scan --json` from many
  hosts, for the "10,000+ hosts per collector cluster" non-functional goal in SPEC §7. Could
  start as something as simple as "push JSON to a log/metrics backend" before it's a real
  dashboard.
- **Self-attestation** — `hunter` verifying its own binary hash against a signed manifest at
  startup (SPEC §4 already asks for this), plus signed releases / reproducible builds more
  generally, since a security tool asking for trust without being verifiable itself is a bad
  look.
- **Tamper-evident log shipping** — forward findings to remote syslog/journald or write-once
  storage as they're generated, so evidence survives a host being wiped mid-incident (ties to
  the "write-once evidence store" in SPEC §2).
