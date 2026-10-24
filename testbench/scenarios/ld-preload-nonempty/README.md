# ld-preload-nonempty

**Technique**: global `LD_PRELOAD` via `/etc/ld.so.preload`. See
`docs/research/persistence-techniques.md` §4 ("Global preload") and the
2026 Spring 2600 Magazine case study in
`docs/research/malware-case-studies.md` (the "hoxha" rootkit this fixture's
fake library name is a nod to).

**Plants**: a non-empty `/etc/ld.so.preload`.

**Expects**: a `persistence` finding whose summary contains
`"ld.so.preload is non-empty"`.

**Check under test**: `src/checks/persistence.rs::check_ld_preload`.
