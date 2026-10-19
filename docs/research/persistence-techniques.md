# Linux Persistence Techniques — Detection Catalog

*Research compiled 2026-10-18. Every row is a detection backlog item.*

Persistence = any way an attacker makes their code run again after a reboot, a logout, a
process kill, or a clean-up attempt. Real malware rarely relies on one: QLNX (2026) installs
seven redundant mechanisms, perfctl copies itself to many paths, and Gayfemboy restarts itself
when killed. **The scanner must therefore enumerate all locations every time — finding one
mechanism never means you found them all.**

Legend — **Priv**: `U` = works as a normal user, `R` = needs root. **ATT&CK** IDs are from
MITRE ATT&CK Enterprise; "—" = not cleanly covered by a technique (udev was undocumented by
ATT&CK when sedexp was found in 2024).

## Universal detection approach

For every location below, the check must:

1. Enumerate entries by reading files/dirs directly (raw-disk view too, since rootkits hide
   files from `readdir` — sedexp hid its own udev rule).
2. Attribute each entry to an installed package (path + hash match the package manifest **and**
   the vendor repo) or to an approved change record.
3. Flag anything unattributed, and raise severity when the entry: points into `/tmp`, `/dev/shm`,
   `/var/tmp`, `/run`, `/var/log`, a hidden dir, or a deleted file; downloads content (`curl`,
   `wget`, `/dev/tcp`); base64/hex-decodes; or names a binary that masquerades as a system one.
4. Record mtime/ctime/crtime and compare with the package install time (timestomp check).

---

## 1. Scheduled execution

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| System crontab | `/etc/crontab`, `/etc/cron.d/*` | R | T1053.003 | XorDDoS, Kaiji, Kinsing, many miners | Parse every line incl. `@reboot`; watch for every-minute re-downloaders |
| Periodic cron dirs | `/etc/cron.hourly`, `.daily`, `.weekly`, `.monthly` | R | T1053.003 | XorDDoS (`cron.hourly`) | Every script attributed to a package |
| User crontabs | `/var/spool/cron/` (RHEL), `/var/spool/cron/crontabs/` (Debian) | U | T1053.003 | Miners, perfctl | Enumerate for **all** users incl. service accounts; perfctl shipped a trojanized `crontab` that hides entries — never trust the `crontab -l` binary |
| anacron | `/etc/anacrontab`, `/var/spool/anacron` | R | T1053.003 | — | Same as cron |
| `at` / `batch` jobs | `/var/spool/at`, `/var/spool/cron/atjobs` | U | T1053.002 | — | One-shot jobs that re-schedule themselves |
| systemd timers | `*.timer` in all unit paths (see §2) | U/R | T1053.006 | QLNX-class implants | Pair each timer with its service; check `OnBootSec`, `OnCalendar` |

## 2. Init systems and services

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| systemd system service | `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/lib/systemd/system/`, `/run/systemd/system/`, `/usr/local/lib/systemd/system/` | R | T1543.002 | LinkPro (`systemd-resolveld.service` posing as `systemd-resolved`), QLNX, perfctl | Diff unit names against package list; typosquat check vs real unit names (edit distance); `ExecStart`, `ExecStartPre/Post`, `ExecStop` all count |
| systemd drop-ins | `*.service.d/*.conf` override dirs | R | T1543.002 | — | A clean unit plus a malicious drop-in `ExecStartPre` is easy to miss |
| `.wants` / `.requires` symlinks | `*.target.wants/`, `default.target.wants/` | R | T1543.002 | — | Symlink to a unit outside package control |
| systemd user services | `~/.config/systemd/user/`, `/etc/systemd/user/`, `/usr/lib/systemd/user/` | U | T1543.002 | Developer-targeting RATs | Runs at user login; check `loginctl` linger (`/var/lib/systemd/linger/`) which makes them start at boot |
| systemd generators | `/etc/systemd/system-generators/`, `/usr/lib/systemd/system-generators/`, user-generators | R | T1543.002 | Research/PANIX | Executed very early every boot and on `daemon-reload`; any non-package generator is critical |
| Transient units | `/run/systemd/transient/` | R | T1543.002 | — | Created by `systemd-run`; volatile but useful for live triage |
| SysV init scripts | `/etc/init.d/`, `/etc/rc[0-6S].d/` | R | T1037.004 | QLNX, older botnets | Still honoured by systemd's sysv generator |
| `rc.local` | `/etc/rc.local`, `/etc/rc.d/rc.local` | R | T1037.004 | Many | Existence + executable bit is itself notable on modern distros |
| Upstart / OpenRC | `/etc/init/*.conf`, `/etc/local.d/*.start`, `/etc/runlevels/` | R | T1037 | Legacy / Alpine | Alpine containers and older hosts |
| Message of the day | `/etc/update-motd.d/` | R | T1037 | Research | Runs as root on every SSH login (Debian/Ubuntu) |

## 3. Shell and login hooks

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| Per-user shell config | `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.bash_logout`, `~/.zshrc`, `~/.zprofile`, `~/.zlogin`, `~/.config/fish/config.fish` | U | T1546.004 | perfctl (`~/.profile` runs payload before the real workload), QLNX (`.bashrc`) | Baseline these per user; flag exec of hidden/temp paths, `nohup … &`, aliases shadowing `sudo`/`ls`/`ps` |
| System shell config | `/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bash.bashrc`, `/etc/bashrc`, `/etc/zsh/*`, `/etc/environment` | R | T1546.004 | Many | Package-attribute every file in `profile.d` |
| Malicious aliases / functions | Any shell rc file | U | T1546.004 | Credential-stealing `sudo` wrappers | Alias or function named like a system command |
| `PROMPT_COMMAND` / `trap` | Shell rc files | U | T1546.004 | Research | Runs on every prompt |
| Shell history suppression | `HISTFILE=/dev/null`, `unset HISTFILE`, `HISTSIZE=0` in rc files | U | T1070.003 | Plague, many | Not persistence itself but a strong co-indicator |

## 4. Dynamic linker and library hijacking

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| Global preload | `/etc/ld.so.preload` | R | T1574.006 | Auto-color (`libcext.so.2`, makes file immutable), perfctl, QLNX, Symbiote, HiddenWasp, Azazel, Jynx, LinkPro fallback (`/etc/libld.so`) | **Should normally not exist.** Read it with a static binary (the rootkit hides it from dynamic tools); check `lsattr`; verify every listed `.so` |
| `LD_PRELOAD` env | `/etc/environment`, shell rc files, systemd `Environment=`, `/proc/PID/environ` | U/R | T1574.006 | Userland rootkits | Scan every running process's environ |
| `LD_LIBRARY_PATH` / `ld.so.conf.d` | `/etc/ld.so.conf`, `/etc/ld.so.conf.d/*`, `/etc/ld.so.cache` | R | T1574.006 | — | New library dirs ahead of system ones; rebuild cache from config and diff |
| Replaced system libraries | `libc`, `libpam`, `libpcap`, `libkeyutils`, `libaudit` | R | T1574.006 / T1554 | Ebury (libkeyutils), Symbiote/perfctl (libpcap hooks) | Hash every library vs vendor repo |
| Library injected via loader path tricks | RPATH/RUNPATH in binaries, `$ORIGIN` abuse | R | T1574.006 | — | Parse ELF dynamic sections of system binaries |

## 5. Authentication path

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| Malicious PAM module | `/lib*/security/`, `/usr/lib*/security/`, `/lib/x86_64-linux-gnu/security/` | R | T1556.003 | **Plague** (2024–25, undetected by AV engines for a year; static password, wipes session traces), **QLNX** (2026, compiles PAM backdoor on host with gcc), perfctl, Orbit, Skidmap, Azazel | Hash every module vs package; unknown `.so` names; modules with network code or hardcoded strings |
| Modified PAM config | `/etc/pam.d/*` | R | T1556.003 | — | `pam_exec.so` lines, `sufficient` modules inserted above `pam_unix`, unknown module names |
| SSH authorized keys | `~/.ssh/authorized_keys`, `authorized_keys2`, for **every** account incl. `nobody`, `www-data`, `games` | U | T1098.004 | perfctl variant (keys under default system users' home dirs) | Enumerate home dirs from `/etc/passwd`, not just `/home`; inspect `command=`, `from=`, `environment=` options |
| sshd config | `/etc/ssh/sshd_config`, `sshd_config.d/*` | R | T1098.004 | — | `AuthorizedKeysFile` pointing elsewhere, `AuthorizedKeysCommand`, `PermitRootLogin`, `Match` blocks, `ForceCommand` |
| Trojanized sshd / ssh | `/usr/sbin/sshd`, `/usr/bin/ssh`, `libsystemd`/`liblzma` linkage | R | T1554 | Ebury, xz-utils backdoor (CVE-2024-3094) | Hash vs repo; list libraries linked by sshd |
| New / modified accounts | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | R | T1136.001 | Many | UID 0 duplicates; service accounts given a real shell or password |
| sudoers | `/etc/sudoers`, `/etc/sudoers.d/*` | R | T1548.003 | — | `NOPASSWD: ALL` for unexpected users |
| Polkit rules | `/etc/polkit-1/rules.d/`, `/usr/share/polkit-1/rules.d/` | R | T1548 | — | JavaScript rules returning `YES` broadly |
| SUID / capabilities backdoor | Any SUID binary or `setcap` file | R | T1548.001 | — | Diff full SUID/cap inventory against baseline |

## 6. Kernel-level persistence

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| LKM autoload | `/etc/modules`, `/etc/modules-load.d/`, `/usr/lib/modules-load.d/`, `/run/modules-load.d/` | R | T1547.006 | Reptile, Diamorphine, PUMAKIT, Singularity, VoidLink | Each listed module must exist in `/lib/modules/$(uname -r)` and be package-owned |
| `modprobe` install hooks | `/etc/modprobe.d/*.conf` `install`/`softdep` directives | R | T1547.006 | — | `install <mod> /path/to/script` runs arbitrary code when a module loads |
| Module files dropped into tree | `/lib/modules/*/` (`extra/`, `updates/`, `kernel/`) | R | T1547.006 | Rootkits | Diff tree vs package manifest; check signatures |
| initramfs injection | `/boot/initrd*`, `/boot/initramfs*`, dracut/mkinitcpio/initramfs-tools hook dirs | R | T1542 | Research PoCs | Unpack and diff; hooks in `/etc/initramfs-tools/`, `/usr/lib/dracut/modules.d/` |
| Bootloader / kernel cmdline | `/boot/grub*/grub.cfg`, `/etc/default/grub`, `/etc/grub.d/`, systemd-boot entries | R | T1542.003 | Bootkits | `init=`, unknown modules, disabled lockdown/sig checks |
| UEFI / firmware | ESP, SPI flash | R | T1542.001 / .003 | BlackLotus-class, firmware implants | See SPEC §3.1 |
| Persistent BPF | Pinned programs in `/sys/fs/bpf/` + a loader in any mechanism above | R | — | LinkPro, BPFDoor, QLNX eBPF part, AUR 2026 stealer | BPF programs don't survive reboot on their own: always find the **loader's** persistence too |

## 7. Event-triggered execution

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| udev rules | `/etc/udev/rules.d/`, `/lib/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/run/udev/rules.d/` | R | T1546.017 (added to ATT&CK after sedexp) | **sedexp** (since 2022; rule fires on `/dev/random` add — i.e. every boot; payload copied to `/lib/udev/`; hides the rule via memory tampering) | Every `RUN+=` / `PROGRAM=` value must be package-owned; read via raw disk too |
| NetworkManager dispatcher | `/etc/NetworkManager/dispatcher.d/` | R | T1546 | Research | Runs on interface up/down |
| ifupdown hooks | `/etc/network/if-up.d/`, `if-pre-up.d`, `if-down.d` | R | T1546 | — | — |
| DHCP client hooks | `/etc/dhcp/dhclient-exit-hooks.d/`, `dhclient-enter-hooks.d/` | R | T1546 | — | — |
| APT / DNF / package hooks | `/etc/apt/apt.conf.d/*` (`DPkg::Pre/Post-Invoke`), DNF/YUM plugins, pacman hooks `/etc/pacman.d/hooks/`, dpkg triggers | R | T1546 | PANIX research | Re-executes on every package operation — survives cleanup that reinstalls packages |
| Git hooks | `.git/hooks/*` in repos, global `core.hooksPath` in `~/.gitconfig` | U | T1546 | Developer-targeting malware | Developer workstations especially |
| Python startup hooks | `*.pth` files in `site-packages`, `sitecustomize.py`, `usercustomize.py` | U/R | T1546.018 | Supply-chain packages | Any `.pth` with `import` lines that execute code |
| Node / npm hooks | `postinstall` scripts, `~/.npmrc`, global `node_modules` | U | T1195.002 | npm worms, AUR 2026 incident | Audit lifecycle scripts |
| Socket activation | `*.socket` units | R | T1543.002 | — | Service starts on first connection to a port — invisible until triggered |
| `core_pattern` | `/proc/sys/kernel/core_pattern` beginning with `\|` | R | T1546 | Container escape research | Program runs as root on any crash |
| binfmt_misc | `/proc/sys/fs/binfmt_misc/`, `/etc/binfmt.d/`, `/usr/lib/binfmt.d/` | R | T1546 | Research | Interpreter runs whenever a matching file is executed |

## 8. Desktop sessions (workstations)

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| XDG autostart | `~/.config/autostart/*.desktop`, `/etc/xdg/autostart/` | U | T1547.013 | QLNX, desktop RATs | `Exec=` lines; `Hidden`/`NoDisplay` entries |
| Session scripts | `~/.xinitrc`, `~/.xsession`, `~/.xprofile`, `/etc/X11/Xsession.d/` | U | T1037 | — | — |
| Desktop extensions | GNOME `~/.local/share/gnome-shell/extensions/`, KDE autostart scripts, browser extensions | U | T1176 | — | — |
| Application shortcuts hijack | `~/.local/share/applications/*.desktop` overriding system ones | U | T1547.013 | — | Same-name override of a common app |

## 9. Application-level persistence

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| Web shells | Web roots (`/var/www`, app dirs, upload dirs), CMS plugin dirs | U | T1505.003 | sedexp (hidden webshells), countless | YARA + diff vs app release; files executed by web server user |
| **In-memory web shell (no file)** | Apache/PHP worker memory | R | T1505.003 / T1620 | **PoisonedRefresh** (2026, F5 BIG-IP: hooks `__libc_start_main` and APR `apr_dso_load`, rewrites PHP scripts at `mmap()` time; files on disk stay clean) | Compare in-memory file mappings to disk; hash `httpd` and loaded modules; inspect web server binary for patches |
| Web server module/config | `httpd.conf`, `mods-enabled/`, `conf.d/`, nginx `modules/`, PHP `auto_prepend_file`, `.user.ini`, `.htaccess` | R/U | T1505 | sedexp (modified Apache config) | Package-attribute every module; flag `auto_prepend_file` |
| Trojanized service binary | Any daemon (`httpd`, `sshd`, `cron`, `systemd-*`) | R | T1554 | PoisonedRefresh (patched `/usr/sbin/httpd`), PUMAKIT (`cron` dropper) | Hash vs vendor repo, not just local package DB |
| Database triggers / UDFs | MySQL `plugin_dir`, PostgreSQL extensions | R | T1505.001 | Miners targeting DBs | List loaded UDF libraries |
| Appliance upgrade persistence | Vendor upgrade image slots | R | T1542 | PoisonedRefresh (survived BIG-IP upgrades) | Inspect **all** boot volumes / images, not just the active one |

## 10. Containers and cloud

| Technique | Where to look | Priv | ATT&CK | Seen in | Detection notes |
| --- | --- | --- | --- | --- | --- |
| Malicious images | Registries, local image store | — | T1525 | LinkPro (delivered via Docker image on EKS) | Scan images; pin digests; flag images pulled outside CI |
| Restart policies | `docker inspect` `RestartPolicy`, compose files | R | T1610 | Miners | `always`/`unless-stopped` on unknown containers |
| DaemonSets / static pods | Cluster API; `/etc/kubernetes/manifests/` | R | T1610 | Cloud campaigns | Static pod manifests on nodes are often forgotten |
| Admission/mutating webhooks | Cluster API | R | T1546 | Research | Injects sidecars into every new pod |
| Cloud identity | New IAM users/keys/roles, SSH keys in instance metadata, startup scripts / user-data | — | T1098 | Cloud campaigns, VoidLink-class | Correlate cloud audit logs with host events |

## 11. Self-healing / redundancy tricks (meta-techniques)

These are not locations but behaviours the scanner must expect:

- **Multiple copies under decoy names** — perfctl copied itself to several paths
  (`/root/.config/cron/perfcc`, `/usr/bin/perfcc`, `/usr/lib/libpprocps.so`) plus a tiny
  watchdog binary (`wizlmsh`) that relaunches the main payload.
- **Respawn on kill** — Gayfemboy restarts itself if its process is terminated; QLNX respawns.
- **Re-download** — cron jobs that fetch a fresh copy every minute, so deleting the binary
  doesn't help.
- **Immutable flag** — `chattr +i` on persistence files (Auto-color protects `ld.so.preload`).
- **Compile on target** — QLNX ships C source as strings and builds its PAM/preload modules
  with the host's own `gcc`, so every victim gets a unique hash.
- **Server-side compiled kernel modules** — VoidLink's C2 compiles a rootkit for the victim's
  exact kernel, so the module never appears in public sample sets.
- **Clean shutdown on signal** — LinkPro removes its eBPF programs and restores
  `/etc/libld.so` on SIGTERM/SIGINT/SIGHUP, which can defeat a naive "stop then scan" response.
- **Kill competing malware** — perfctl and QLNX kill rival implants; unexpected process kills of
  known miner names can itself be a signal.

**Test-bench requirement:** plant each row above with PANIX / Atomic Red Team (or a custom
recipe) on a disposable VM, verify detection, and keep the scenario as a regression test.
