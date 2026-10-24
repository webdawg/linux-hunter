// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-references SUID/SGID binaries and sudoers-permitted commands
//! against GTFOBins (<https://gtfobins.github.io/>) -- the catalog of
//! ordinary Unix binaries that can be abused for privilege escalation,
//! arbitrary file read/write, or a shell when run as root (via a SUID
//! bit) or via sudo. An admin who scopes `sudo` down to "just let this
//! user run vim" or sets a SUID bit on `find` for a legitimate reason has
//! usually just handed out root, and it's easy to not realize that.
//!
//! The two name lists below (`GTFOBINS_SUID`, `GTFOBINS_SUDO`) were
//! derived programmatically from GTFOBins' own `_gtfobins/*` data files
//! (GPL-3.0 -- combination-compatible with our AGPL-3.0-or-later per
//! GPLv3 §13 / AGPLv3 §13, the same basis as the Lynis vendoring in
//! third_party/, see its README) by checking which binaries have at
//! least one documented function whose context includes `suid` or
//! `sudo` respectively. This embeds only that derived fact (a list of
//! names) rather than GTFOBins' own write-ups/technique descriptions,
//! which are not reproduced here. Snapshot taken 2026-10-24; GTFOBins
//! adds new entries over time, so this list will drift stale -- re-derive
//! it from the upstream repo's `_gtfobins/` directory periodically
//! (see docs/research/sources.md).
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

const SUID_SCAN_DIRS: &[&str] = &["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin", "/usr/local/sbin"];

const SUDOERS_TAGS: &[&str] =
    &["NOPASSWD:", "PASSWD:", "NOEXEC:", "EXEC:", "SETENV:", "NOSETENV:", "LOG_INPUT:", "NOLOG_INPUT:", "LOG_OUTPUT:", "NOLOG_OUTPUT:"];

const SUDOERS_NON_GRANT_KEYWORDS: &[&str] = &["Defaults", "Cmnd_Alias", "Host_Alias", "User_Alias", "Runas_Alias"];

pub struct GtfobinsCheck;

impl Check for GtfobinsCheck {
    fn name(&self) -> &'static str {
        "gtfobins"
    }

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();
        check_suid_binaries(&mut out);
        check_sudoers_commands(&mut out);
        Ok(out)
    }
}

fn check_suid_binaries(out: &mut CheckOutput) {
    let suid_set: HashSet<&str> = GTFOBINS_SUID.iter().copied().collect();

    for dir in SUID_SCAN_DIRS {
        debug!(dir, "scanning for SUID/SGID binaries");
        let Ok(entries) = fs::read_dir(dir) else {
            debug!(dir, "does not exist on this system — skipping");
            continue;
        };

        for entry in entries.flatten() {
            let Ok(meta) = fs::metadata(entry.path()) else { continue };
            let mode = meta.permissions().mode();
            let setuid = mode & 0o4000 != 0;
            let setgid = mode & 0o2000 != 0;
            if !setuid && !setgid {
                continue;
            }

            let name = entry.file_name().to_string_lossy().into_owned();
            let bit = match (setuid, setgid) {
                (true, true) => "setuid+setgid",
                (true, false) => "setuid",
                (false, true) => "setgid",
                (false, false) => unreachable!(),
            };
            debug!(path = %entry.path().display(), bit, "found a SUID/SGID binary");

            if suid_set.contains(name.as_str()) {
                out.push(Finding::new(
                    "gtfobins",
                    Severity::Critical,
                    format!("{} is {bit} and has a documented GTFOBins privilege-escalation technique", entry.path().display()),
                    format!(
                        "GTFOBins (https://gtfobins.github.io/gtfobins/{name}/) documents a way to \
                         get a root shell, read any file, or write any file through this binary \
                         when it carries the {bit} bit. Unless there's a specific, understood \
                         reason this binary needs that bit, removing it (chmod u-s,g-s) closes an \
                         off-the-shelf local privilege-escalation path."
                    ),
                ));
            }
        }
    }
}

fn check_sudoers_commands(out: &mut CheckOutput) {
    let sudo_set: HashSet<&str> = GTFOBINS_SUDO.iter().copied().collect();

    let mut sudoers_files = vec!["/etc/sudoers".to_string()];
    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            sudoers_files.push(entry.path().to_string_lossy().into_owned());
        }
    }

    let mut any_readable = false;
    for path in &sudoers_files {
        debug!(path, "checking sudoers file for GTFOBins-listed commands");
        let contents = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => continue,
            Err(_) => continue,
        };
        any_readable = true;

        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some(principal) = trimmed.split_whitespace().next() else { continue };
            if SUDOERS_NON_GRANT_KEYWORDS.contains(&principal) {
                continue; // not a user/group grant line
            }

            for raw_command in extract_commands(trimmed) {
                let command = strip_sudoers_tags(raw_command);
                if !command.starts_with('/') {
                    continue; // "ALL", an alias name, or a relative name we can't resolve
                }
                let command_path = command.split_whitespace().next().unwrap_or(command);
                let basename = Path::new(command_path).file_name().and_then(|n| n.to_str()).unwrap_or("");

                if sudo_set.contains(basename) {
                    out.push(Finding::new(
                        "gtfobins",
                        Severity::High,
                        format!("{path} lets {principal} run {command_path} via sudo, which has a documented GTFOBins sudo technique"),
                        format!(
                            "GTFOBins (https://gtfobins.github.io/gtfobins/{basename}/) documents a \
                             way to turn sudo access to this specific binary into a full root \
                             shell -- scoping sudo to \"just one command\" doesn't help if that \
                             command is on this list. Line: `{trimmed}`"
                        ),
                    ));
                }
            }
        }
    }

    if !any_readable {
        out.skip("could not read /etc/sudoers or /etc/sudoers.d/* (permission denied) — GTFOBins sudoers check did not run; needs root".to_string());
    }
}

/// Commands follow the first `=` on a sudoers grant line
/// (`user host_list = (runas_list) tag_list cmnd_list, ...`), optionally
/// preceded by a parenthesized runas spec -- which is *not* set off by
/// another `=`, so it has to be stripped explicitly rather than assumed
/// away by splitting on the last `=` (a real bug caught by this module's
/// own tests: a line with exactly one `=` left "(ALL)" glued onto the
/// front of the first extracted command). Only the first runas spec is
/// stripped: a line with multiple comma-separated `(runas) cmnd_list`
/// groups will leak a later `(runas)` into that group's first command,
/// which simply won't match any GTFOBins name and gets skipped -- a
/// false negative on an uncommon sudoers construct, not a false positive.
fn extract_commands(line: &str) -> Vec<&str> {
    let Some((_, after_eq)) = line.split_once('=') else { return Vec::new() };
    let after_eq = after_eq.trim_start();

    let cmd_part = match after_eq.strip_prefix('(').and_then(|rest| rest.find(')').map(|i| &rest[i + 1..])) {
        Some(rest) => rest,
        None => after_eq, // no runas spec present
    };

    cmd_part.split(',').map(str::trim).collect()
}

/// Strips sudoers command tags (`NOPASSWD:`, `SETENV:`, ...) and `!`
/// negations, which can appear repeated and in either order.
fn strip_sudoers_tags(mut token: &str) -> &str {
    loop {
        token = token.trim_start();
        if let Some(rest) = token.strip_prefix('!') {
            token = rest;
            continue;
        }
        match SUDOERS_TAGS.iter().find_map(|tag| token.strip_prefix(tag)) {
            Some(rest) => token = rest,
            None => break,
        }
    }
    token.trim_start()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_comma_separated_commands_after_last_equals() {
        let line = "alice ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find";
        let commands = extract_commands(line);
        assert_eq!(commands, vec!["NOPASSWD: /usr/bin/vim", "/usr/bin/find"]);
    }

    #[test]
    fn extract_commands_returns_empty_without_equals() {
        assert!(extract_commands("not a grant line").is_empty());
    }

    #[test]
    fn strips_nopasswd_tag_and_whitespace() {
        assert_eq!(strip_sudoers_tags("NOPASSWD: /usr/bin/vim"), "/usr/bin/vim");
    }

    #[test]
    fn strips_stacked_tags_and_negation_in_any_order() {
        assert_eq!(strip_sudoers_tags("!EXEC: NOPASSWD: /usr/bin/find"), "/usr/bin/find");
    }

    #[test]
    fn leaves_bare_all_untouched_so_it_wont_match_a_basename() {
        // "ALL" doesn't start with '/', so callers correctly skip it rather
        // than treating it as a path with an empty/garbage basename.
        assert_eq!(strip_sudoers_tags("ALL"), "ALL");
        assert!(!strip_sudoers_tags("ALL").starts_with('/'));
    }

    #[test]
    fn gtfobins_lists_are_sorted_and_deduplicated() {
        for list in [GTFOBINS_SUID, GTFOBINS_SUDO] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(list.len(), sorted.len(), "list has a duplicate entry");
        }
    }

    #[test]
    fn known_binaries_land_in_the_expected_lists() {
        // Spot-check against a couple of well-known GTFOBins entries so a
        // bad regeneration of the embedded lists fails loudly.
        assert!(GTFOBINS_SUID.contains(&"find"), "find is a textbook SUID GTFOBin");
        assert!(GTFOBINS_SUDO.contains(&"vim"), "vim is a textbook sudo GTFOBin");
        assert!(!GTFOBINS_SUID.contains(&"killall"), "killall has no GTFOBins entry at all");
    }
}

const GTFOBINS_SUID: &[&str] = &[
    "R", "aa-exec", "ab", "acr", "agetty", "alpine", "apache2", "apt-get", "ar", "aria2c", "arj", "arp", "as",
    "ascii-xfr", "ash", "aspell", "asterisk", "atobm", "aws", "base32", "base64", "basenc", "basez", "bash",
    "batcat", "bc", "bconsole", "bee", "bridge", "busctl", "bzip2", "cabal", "cancel", "capsh", "cat", "chattr",
    "chmod", "choom", "chown", "chroot", "chrt", "clamscan", "clisp", "cmp", "cobc", "column", "comm", "cp", "cpio",
    "cpulimit", "crash", "csh", "csplit", "csvtool", "ctr", "cupsfilter", "curl", "cut", "dash", "date", "dc", "dd",
    "debugfs", "dialog", "diff", "dig", "distcc", "dmesg", "dmsetup", "dnsmasq", "docker", "dos2unix", "dosbox",
    "dpkg", "dvips", "easyrsa", "ed", "efax", "egrep", "elvish", "enscript", "env", "eqn", "espeak", "ex", "expand",
    "expect", "fastfetch", "ffmpeg", "fgrep", "file", "find", "finger", "fish", "flock", "fmt", "fold", "forge",
    "fping", "ftp", "fzf", "gawk", "gcloud", "gcore", "gdb", "genie", "genisoimage", "getent", "ginsh", "git",
    "gnuplot", "grep", "gtester", "guile", "gzip", "head", "hexdump", "hg", "highlight", "hping3", "iconv", "iftop",
    "install", "ionice", "ip", "ispell", "joe", "join", "jq", "jrunscript", "julia", "ksshell", "kubectl", "last",
    "latex", "ld.so", "ldconfig", "less", "lftp", "links", "logrotate", "logsave", "look", "lp", "ltrace", "lua",
    "lualatex", "luatex", "lxd", "m4", "mail", "make", "man", "mawk", "minicom", "more", "mosquitto", "msgattrib",
    "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime", "mv", "mysql", "nano", "nasm", "nc",
    "ncdu", "ncftp", "nginx", "nice", "nl", "nm", "nmap", "node", "nohup", "nsenter", "ntpdate", "octave", "od",
    "opencode", "openssl", "openvpn", "pandoc", "paste", "pax", "pdflatex", "pdftex", "perf", "perl", "pexec", "pg",
    "php", "pic", "pidstat", "plymouth", "pr", "psftp", "psql", "ptx", "python", "qpdf", "rc", "readelf", "redis",
    "restic", "rev", "rlogin", "rlwrap", "rpm", "rpmdb", "rpmquery", "rpmverify", "rsync", "rtorrent", "run-parts",
    "runscript", "sash", "scanmem", "scp", "script", "scrot", "sed", "setarch", "setcap", "setfacl", "setlock",
    "sftp", "shred", "shuf", "slsh", "socat", "socket", "soelim", "softlimit", "sort", "split", "sqlite3", "ss",
    "ssh", "ssh-agent", "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings",
    "sysctl", "systemctl", "tac", "tail", "tar", "task", "tasksh", "tbl", "tclsh", "tcpdump", "tcsh", "tdbtool",
    "tee", "telnet", "terraform", "tex", "tftp", "tic", "time", "timeout", "tmate", "tmux", "troff", "ul",
    "unexpand", "uniq", "unshare", "unsquashfs", "unzip", "update-alternatives", "urlget", "uuencode",
    "varnishncsa", "vi", "vigr", "vim", "vipw", "volatility", "w3m", "watch", "wc", "wget", "whiptail", "whois",
    "wish", "xargs", "xdotool", "xmodmap", "xmore", "xpad", "xxd", "xz", "yash", "zic", "zip", "zless", "zsh",
    "zsoelim",
];

const GTFOBINS_SUDO: &[&str] = &[
    "7z", "R", "aa-exec", "ab", "acr", "alpine", "ansible-playbook", "ansible-test", "aoss", "apache2",
    "apache2ctl", "apt-get", "aptitude", "ar", "arch-nspawn", "aria2c", "arj", "arp", "as", "ascii-xfr", "ascii85",
    "ash", "aspell", "asterisk", "at", "atobm", "autoconf", "autoheader", "autoreconf", "aws", "base32", "base58",
    "base64", "basenc", "basez", "bash", "bashbug", "batcat", "bbot", "bc", "bconsole", "bee", "borg", "bpftrace",
    "bridge", "bundle", "busctl", "busybox", "byebug", "bzip2", "cabal", "cancel", "capsh", "cargo", "cat", "cdist",
    "certbot", "chattr", "check_by_ssh", "check_cups", "check_log", "check_memory", "check_raid", "check_ssl_cert",
    "check_statusfile", "chmod", "choom", "chown", "chroot", "chrt", "clamscan", "clisp", "cmake", "cmp", "cobc",
    "code", "codex", "column", "comm", "composer", "cowsay", "cowthink", "cp", "cpan", "cpio", "cpulimit", "crash",
    "crontab", "csh", "csplit", "csvtool", "ctr", "cupsfilter", "curl", "cut", "dash", "date", "dc", "dd",
    "debugfs", "dhclient", "dialog", "diff", "dig", "distcc", "dmesg", "dmsetup", "dnf", "dnsmasq", "doas",
    "docker", "dos2unix", "dosbox", "dotnet", "dpkg", "dstat", "dvips", "easy_install", "easyrsa", "eb", "ed",
    "efax", "egrep", "elvish", "emacs", "enscript", "env", "eqn", "espeak", "ex", "exiftool", "expand", "expect",
    "facter", "fail2ban-client", "fastfetch", "ffmpeg", "fgrep", "file", "find", "finger", "firejail", "fish",
    "flock", "fmt", "fold", "forge", "fping", "ftp", "fzf", "gawk", "gcc", "gcloud", "gcore", "gdb", "gem", "genie",
    "genisoimage", "getent", "ghc", "ghci", "gimp", "ginsh", "git", "gnuplot", "go", "grc", "grep", "gtester",
    "guile", "gzip", "hashcat", "head", "hexdump", "hg", "highlight", "hping3", "iconv", "iftop", "install",
    "ionice", "ip", "iptables-save", "irb", "ispell", "java", "jjs", "joe", "join", "journalctl", "jq",
    "jrunscript", "jshell", "jtag", "julia", "knife", "ksshell", "ksu", "kubectl", "last", "latex", "latexmk",
    "ld.so", "ldconfig", "less", "lftp", "links", "ln", "loginctl", "logrotate", "logsave", "look", "lp", "ltrace",
    "lua", "lualatex", "luatex", "lwp-download", "lwp-request", "lxd", "m4", "mail", "make", "man", "mawk",
    "minicom", "more", "mosh-server", "mosquitto", "mount", "msfconsole", "msgattrib", "msgcat", "msgconv",
    "msgfilter", "msgmerge", "msguniq", "mtr", "multitime", "mutt", "mv", "mypy", "mysql", "nano", "nasm", "nc",
    "ncdu", "ncftp", "needrestart", "neofetch", "nft", "nginx", "nice", "nl", "nm", "nmap", "node", "nohup", "npm",
    "nroff", "nsenter", "ntpdate", "octave", "od", "opencode", "openssl", "openvpn", "openvt", "opkg", "pandoc",
    "passwd", "paste", "pax", "pdb", "pdflatex", "pdftex", "perf", "perl", "perlbug", "pexec", "pg", "php", "pic",
    "pidstat", "pip", "pipx", "pkexec", "pkg", "plymouth", "podman", "poetry", "posh", "pr", "procmail", "pry",
    "psftp", "psql", "ptx", "puppet", "pwsh", "pygmentize", "pyright", "python", "qpdf", "rake", "ranger", "rc",
    "readelf", "redcarpet", "redis", "restic", "rev", "rlogin", "rlwrap", "rpm", "rpmdb", "rpmquery", "rpmverify",
    "rsync", "rsyslogd", "rtorrent", "ruby", "run-mailcap", "run-parts", "runscript", "rustc", "rustdoc", "rustfmt",
    "rustup", "sash", "scanmem", "scp", "screen", "script", "scrot", "sed", "service", "setarch", "setcap",
    "setfacl", "setlock", "sftp", "sg", "shred", "shuf", "slsh", "smbclient", "snap", "socat", "socket", "soelim",
    "softlimit", "sort", "split", "sqlite3", "sqlmap", "ss", "ssh", "ssh-agent", "ssh-copy-id", "ssh-keygen",
    "ssh-keyscan", "sshfs", "sshpass", "sshuttle", "start-stop-daemon", "stdbuf", "strace", "strings", "su", "sudo",
    "sysctl", "systemctl", "systemd-resolve", "systemd-run", "tac", "tail", "tailscale", "tar", "task", "taskset",
    "tasksh", "tbl", "tclsh", "tcpdump", "tcsh", "tdbtool", "tee", "telnet", "terraform", "tex", "tftp", "tic",
    "time", "timedatectl", "timeout", "tmate", "tmux", "top", "torify", "torsocks", "troff", "tsc", "tshark", "ul",
    "unexpand", "uniq", "unshare", "unsquashfs", "unzip", "update-alternatives", "urlget", "uuencode", "uv",
    "vagrant", "valgrind", "varnishncsa", "vi", "vigr", "vim", "vipw", "virsh", "volatility", "w3m", "wall",
    "watch", "wc", "wg-quick", "wget", "whiptail", "whois", "wireshark", "wish", "xargs", "xdg-user-dir", "xdotool",
    "xmodmap", "xmore", "xpad", "xxd", "xz", "yarn", "yash", "yelp", "yt-dlp", "yum", "zathura", "zcat", "zgrep",
    "zic", "zip", "zless", "zsh", "zsoelim", "zypper",
];
