# gtfobins-sudo-vim

**Technique**: scoping `sudo` to "just one command" that's actually a
documented [GTFOBins](https://gtfobins.github.io/gtfobins/vim/) sudo
technique. `vim -c ':!sh'` (among other things) gets a root shell from
sudo access to `vim` alone -- restricting the command doesn't help.

**Plants**: `/etc/sudoers.d/99-scoped-vim` granting `alice` passwordless
sudo on `/usr/bin/vim`.

**Expects**: a `gtfobins` finding whose summary contains "documented
GTFOBins sudo technique".

**Check under test**: `src/checks/gtfobins.rs::check_sudoers_commands`
-- also exercises the first-`=`-plus-runas-stripping fix described in
that file's `extract_commands` doc comment.
