# Third-party tools

Software vendored here for **benchmarking and testing**, not for `hunter` to run,
shell out to, or link against at scan time. CLAUDE.md rule #1 is "never trust the
suspect host" — these tools work the opposite way (they read config and shell
out to host commands in place, with no cross-view verification), which is exactly
why SPEC.md §7 lists them as tools "to beat, not as coverage." Keeping them out of
`hunter`'s own code path is deliberate, not an oversight.

What they're for: the test-bench (SPEC.md roadmap Phase 1/validation) plants a
technique from `docs/research/` on a disposable VM and checks that both `hunter`
and the relevant vendored tool catch it — or, more usefully, that `hunter` catches
something the other tool misses.

Each subdirectory is an **unmodified, pinned upstream release**, kept under its own
original license (never relicensed, never merged into `hunter`'s AGPL-3.0-or-later
source — this is "mere aggregation," not a combined work). See each tool's own
`LICENSE` file.

| Tool | Version | License | Source | Why it's here |
| --- | --- | --- | --- | --- |
| [Lynis](https://github.com/CISOfy/lynis) | 3.1.7 | GPL-3.0 | `archive/refs/tags/3.1.7.tar.gz`, sha256 `48d829d0dc2c583a3e838cc09a7190b69a3af844bcb913c7cf9c0226b04b95c5` | General-purpose hardening/audit scanner from [linux-audit.com](https://linux-audit.com/about/) (Michael Boelen / CISOfy); already listed as a benchmark tool in `docs/SPEC.md` §7. GPLv3 is explicitly combination-compatible with AGPLv3 (GPLv3 §13 / AGPLv3 §13) but is kept as a separate, unmodified tree regardless, per the aggregation note above. |

GPLv2-only tools (rkhunter, AIDE, ClamAV, LKRG, ...) are **not yet vendored**. They
need the same "unmodified, separate tree, invoked as its own subprocess" treatment
if added, since GPLv2-only code can't be merged into an AGPLv3 conveyed work the
way GPLv3 can — keeping them untouched in their own directory sidesteps that
entirely.
