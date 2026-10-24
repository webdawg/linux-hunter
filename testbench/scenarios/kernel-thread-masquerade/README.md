# kernel-thread-masquerade

**Technique**: a userspace process renames itself via
`prctl(PR_SET_NAME, ...)` to match a real kernel thread's name
(`kworker/...`, `ksoftirqd/...`, ...), hiding in plain sight in a
`ps`/`top` listing full of real kernel threads. Seen in perfctl,
BPFDoor variants, and LinkPro — see
`docs/research/hiding-techniques.md` §1 ("Process masquerading").

**Plants**: `masquerade.c` — a trivial C program that calls
`prctl(PR_SET_NAME, "kworker/0:1", 0, 0, 0)` then sleeps. Compiled at
test-run time with `gcc` (the one scenario here with an extra tool
dependency; the scenario fails clearly rather than silently if `gcc`
isn't on `PATH`), bound into the sandbox, and executed backgrounded —
same live-process pattern as `deleted-exe-process`.

**Expects**: a `processes` finding whose summary contains "matches
kernel-thread prefix".

**Check under test**: `src/checks/processes.rs`'s
`KERNEL_THREAD_NAME_PREFIXES` check — specifically the part that
distinguishes this from a *real* kernel thread, which never reaches
that check at all because it has no `/proc/<pid>/exe` symlink (this
fixture does, since it's a real file at `/tmp/masquerade`).
