# deleted-exe-process

**Technique**: a running process whose backing binary has been deleted
from disk since exec — the process keeps running (the kernel holds the
inode open), but nothing on disk shows what it's actually running. A
common way a dropped payload dodges on-disk/static scanning after it
starts. See `docs/research/hiding-techniques.md` §1 and
`docs/SPEC.md` §3.4.

**Plants**: copies `/bin/sleep` to `/tmp/victim` (inside the sandbox's
own `--tmpfs /tmp`), execs it backgrounded, then deletes `/tmp/victim`
while it's still running — `/proc/<pid>/exe` then resolves to
`/tmp/victim (deleted)`.

This is the first testbench scenario that plants a live *process* rather
than just files; see `run_script_in_sandbox` in
`testbench/lib/sandbox.sh` for how that works (a script executed inside
the sandbox's own pid namespace, with hunter's JSON output written to
`/tmp/output.json` inside the sandbox, bound back out to a real file on
the host so it survives the sandbox tearing down).

**Expects**: a `processes` finding whose summary contains "deleted off
disk".

**Check under test**: `src/checks/processes.rs` (the `exe_str.ends_with("
(deleted)")` branch).
