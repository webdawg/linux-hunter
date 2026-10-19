// SPDX-License-Identifier: AGPL-3.0-or-later
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

/// Directories where a root-run process would normally not expect writes
/// from unprivileged users; if any of these turn out world-writable, any
/// local user can plant a persistence mechanism that runs as root.
const WORLD_WRITABLE_WATCH: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/systemd/system",
    "/etc/ld.so.conf.d",
];

/// Autostart location trees enumerated purely for recency (no package
/// attribution yet — see CLAUDE.md "Current implementation status"). Each
/// entry is (human label used in finding text, paths to walk).
/// Source: docs/research/persistence-techniques.md §1-7.
const AUTOSTART_TREES: &[(&str, &[&str])] = &[
    ("cron entry", &["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"]),
    (
        "systemd unit",
        &[
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
            "/usr/local/lib/systemd/system",
        ],
    ),
    ("SysV init script", &["/etc/init.d", "/etc/rc.d"]),
    (
        "udev rule",
        &[
            "/etc/udev/rules.d",
            "/lib/udev/rules.d",
            "/usr/lib/udev/rules.d",
            "/run/udev/rules.d",
        ],
    ),
    (
        "kernel module autoload entry",
        &["/etc/modules", "/etc/modules-load.d", "/usr/lib/modules-load.d", "/run/modules-load.d"],
    ),
    ("system shell profile script", &["/etc/profile.d", "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"]),
    ("NetworkManager dispatcher hook", &["/etc/NetworkManager/dispatcher.d"]),
];

/// Per-user shell rc files checked both for recent changes and for history
/// suppression (docs/research/persistence-techniques.md §3).
const USER_SHELL_RC_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".bash_logout",
    ".zshrc",
    ".zprofile",
    ".zlogin",
];

const HISTORY_SUPPRESSION_PATTERNS: &[&str] = &["HISTFILE=/dev/null", "unset HISTFILE", "HISTSIZE=0"];

const RECENT_WINDOW_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

pub struct PersistenceCheck;

impl Check for PersistenceCheck {
    fn name(&self) -> &'static str {
        "persistence"
    }

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();

        check_ld_preload(&mut out);
        check_world_writable_dirs(&mut out);
        check_rc_local(&mut out);
        check_autostart_trees(&mut out);

        let home_dirs = read_account_home_dirs(&mut out);
        check_authorized_keys(&home_dirs, &mut out);
        check_history_suppression(&home_dirs, &mut out);
        check_xdg_autostart(&home_dirs, &mut out);

        Ok(out)
    }
}

fn check_ld_preload(out: &mut CheckOutput) {
    let path = "/etc/ld.so.preload";
    debug!(path, "checking global LD_PRELOAD file");
    if let Ok(contents) = fs::read_to_string(path) {
        debug!(path, bytes = contents.len(), "file exists and was read");
        if !contents.trim().is_empty() {
            out.push(Finding::new(
                "persistence",
                Severity::Critical,
                "/etc/ld.so.preload is non-empty".to_string(),
                format!(
                    "Contents:\n{}\nThis file forces every dynamically-linked process on the \
                     system to load the listed shared objects first. It's a classic userland \
                     rootkit technique (e.g. hiding files/processes via libc hooking) and is \
                     empty on almost every unmodified install.",
                    contents.trim()
                ),
            ));
        } else {
            debug!(path, "file exists but is empty — clean");
        }

        match is_immutable(Path::new(path)) {
            Some(true) => out.push(Finding::new(
                "persistence",
                Severity::High,
                format!("{path} has the immutable flag set"),
                "chattr +i on this file is itself suspicious: Auto-color used it to protect \
                 its ld.so.preload entry from removal. A legitimate empty preload file has no \
                 reason to be immutable."
                    .to_string(),
            )),
            Some(false) => debug!(path, "immutable flag not set"),
            None => out.skip(format!("could not read the immutable flag on {path} (ioctl failed)")),
        }
    } else {
        debug!(path, "file does not exist — clean (this is the common case)");
    }
}

/// Reads the ext2/3/4-family FS_IOC_GETFLAGS attributes (what `lsattr` shows)
/// via ioctl rather than shelling out to `lsattr`, per CLAUDE.md rule #1.
fn is_immutable(path: &Path) -> Option<bool> {
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
    const FS_IMMUTABLE_FL: libc::c_long = 0x00000010;

    let file = File::open(path).ok()?;
    let mut flags: libc::c_long = 0;
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) };
    if ret != 0 {
        return None;
    }
    Some(flags & FS_IMMUTABLE_FL != 0)
}

fn check_world_writable_dirs(out: &mut CheckOutput) {
    for dir in WORLD_WRITABLE_WATCH {
        debug!(dir, "checking directory permissions");
        if let Ok(meta) = fs::metadata(dir) {
            let mode = meta.permissions().mode() & 0o7777;
            debug!(dir, mode = format!("{mode:o}"), "read mode bits");
            if is_world_writable(meta.permissions().mode()) {
                out.push(Finding::new(
                    "persistence",
                    Severity::High,
                    format!("{dir} is world-writable"),
                    format!(
                        "mode {mode:o}. Any local user can drop or modify a unit/cron entry here \
                         and have it executed with the privileges of whatever runs it \
                         (often root)."
                    ),
                ));
            }
        } else {
            debug!(dir, "does not exist on this system — clean");
        }
    }
}

/// `rc.local`'s mere existence (as an executable) is notable on a modern
/// distro — most no longer ship one at all.
fn check_rc_local(out: &mut CheckOutput) {
    for path in ["/etc/rc.local", "/etc/rc.d/rc.local"] {
        debug!(path, "checking for rc.local");
        let Ok(meta) = fs::metadata(path) else {
            debug!(path, "does not exist — clean");
            continue;
        };
        let executable = meta.permissions().mode() & 0o111 != 0;
        debug!(path, executable, "rc.local exists");
        if executable {
            out.push(Finding::new(
                "persistence",
                Severity::Low,
                format!("{path} exists and is executable"),
                "Most modern distros ship no rc.local at all; one being present and executable \
                 is worth a manual read of its contents."
                    .to_string(),
            ));
        }
    }
}

fn check_autostart_trees(out: &mut CheckOutput) {
    for (label, paths) in AUTOSTART_TREES {
        debug!(label, ?paths, "walking autostart tree for recently-modified entries");
        for base in *paths {
            scan_recent(label, Path::new(base), out);
        }
    }
}

fn scan_recent(label: &str, path: &Path, out: &mut CheckOutput) {
    let Ok(meta) = fs::metadata(path) else {
        debug!(path = %path.display(), "path does not exist — skipping");
        return;
    };

    if meta.is_dir() {
        debug!(path = %path.display(), "descending into directory");
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            scan_recent(label, &entry.path(), out);
        }
        return;
    }

    if let Ok(modified) = meta.modified()
        && let Ok(age) = SystemTime::now().duration_since(modified)
    {
        debug!(path = %path.display(), age_secs = age.as_secs(), "read file mtime");
        if age.as_secs() < RECENT_WINDOW_SECS {
            out.push(Finding::new(
                "persistence",
                Severity::Low,
                format!("{label} {} was modified recently", path.display()),
                format!(
                    "Modified {} ago. Not inherently malicious, but recently-added \
                     autostart entries are worth a manual read — this is a common \
                     persistence vector.",
                    humanize(age.as_secs())
                ),
            ));
        }
    }
}

/// (username, home dir) for every account in /etc/passwd.
fn read_account_home_dirs(out: &mut CheckOutput) -> Vec<(String, String)> {
    debug!("reading /etc/passwd to enumerate every account's home directory");
    let passwd = match fs::read_to_string("/etc/passwd") {
        Ok(p) => p,
        Err(err) => {
            out.skip(format!("could not read /etc/passwd ({err}) — no per-account checks were run"));
            return Vec::new();
        }
    };

    passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let user = fields.first()?.to_string();
            let home = fields.get(5)?.to_string();
            if home.is_empty() { None } else { Some((user, home)) }
        })
        .collect()
}

fn check_authorized_keys(home_dirs: &[(String, String)], out: &mut CheckOutput) {
    for (user, home) in home_dirs {
        let auth_keys = Path::new(home).join(".ssh").join("authorized_keys");
        debug!(user, path = %auth_keys.display(), "checking account's authorized_keys");
        let Ok(meta) = fs::metadata(&auth_keys) else {
            debug!(user, "no authorized_keys file for this account — clean");
            continue;
        };

        if is_world_writable(meta.permissions().mode()) {
            out.push(Finding::new(
                "persistence",
                Severity::High,
                format!("{} is world-writable", auth_keys.display()),
                "Any local user could append their own key and gain SSH access as this account.".to_string(),
            ));
        }

        if let Ok(modified) = meta.modified()
            && let Ok(age) = SystemTime::now().duration_since(modified)
            && age.as_secs() < RECENT_WINDOW_SECS
        {
            out.push(Finding::new(
                "persistence",
                Severity::Medium,
                format!("{} was modified recently", auth_keys.display()),
                format!(
                    "Modified {} ago. A new or changed authorized_keys entry is one of \
                     the most common footholds attackers leave behind.",
                    humanize(age.as_secs())
                ),
            ));
        }
    }
}

fn check_history_suppression(home_dirs: &[(String, String)], out: &mut CheckOutput) {
    for (user, home) in home_dirs {
        for rc_name in USER_SHELL_RC_FILES {
            let rc_path = Path::new(home).join(rc_name);
            debug!(user, path = %rc_path.display(), "checking shell rc file for history suppression");
            let Ok(contents) = fs::read_to_string(&rc_path) else {
                continue;
            };
            for pattern in HISTORY_SUPPRESSION_PATTERNS {
                if contents.contains(pattern) {
                    out.push(Finding::new(
                        "persistence",
                        Severity::Medium,
                        format!("{} suppresses shell history (`{pattern}`)", rc_path.display()),
                        "Not persistence by itself, but a common co-indicator: attackers \
                         disable history in a shell rc file they've also used to plant a \
                         payload, to cover their tracks on every future login."
                            .to_string(),
                    ));
                }
            }
        }
    }
}

fn check_xdg_autostart(home_dirs: &[(String, String)], out: &mut CheckOutput) {
    for (_, home) in home_dirs {
        let autostart_dir = Path::new(home).join(".config").join("autostart");
        scan_recent("XDG autostart entry", &autostart_dir, out);
    }
    scan_recent("XDG autostart entry", Path::new("/etc/xdg/autostart"), out);
}

fn is_world_writable(mode: u32) -> bool {
    mode & 0o002 != 0
}

fn humanize(secs: u64) -> String {
    if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}
