# gtfobins-suid-find

**Technique**: a SUID binary with a documented
[GTFOBins](https://gtfobins.github.io/gtfobins/find/) privilege-escalation
technique. `find -exec` (among other things) gets you a root shell when
`find` itself is setuid-root.

**Plants**: an executable file named `find`, mode `4755` (setuid), in
`/usr/local/bin` (one of `SUID_SCAN_DIRS`).

**Expects**: a `gtfobins` finding whose summary contains "documented
GTFOBins privilege-escalation technique".

**Check under test**: `src/checks/gtfobins.rs::check_suid_binaries`.
