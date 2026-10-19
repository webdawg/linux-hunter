// SPDX-License-Identifier: AGPL-3.0-or-later
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{Finding, Severity};

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

const RECENT_WINDOW_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

pub struct PersistenceCheck;

impl Check for PersistenceCheck {
    fn name(&self) -> &'static str {
        "persistence"
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        check_ld_preload(&mut findings);
        check_world_writable_dirs(&mut findings);
        check_cron_recency(&mut findings);
        check_authorized_keys(&mut findings);

        Ok(findings)
    }
}

fn check_ld_preload(findings: &mut Vec<Finding>) {
    let path = "/etc/ld.so.preload";
    debug!(path, "checking global LD_PRELOAD file");
    if let Ok(contents) = fs::read_to_string(path) {
        debug!(path, bytes = contents.len(), "file exists and was read");
        if !contents.trim().is_empty() {
            findings.push(Finding::new(
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
    } else {
        debug!(path, "file does not exist — clean (this is the common case)");
    }
}

fn check_world_writable_dirs(findings: &mut Vec<Finding>) {
    for dir in WORLD_WRITABLE_WATCH {
        debug!(dir, "checking directory permissions");
        if let Ok(meta) = fs::metadata(dir) {
            let mode = meta.permissions().mode() & 0o7777;
            debug!(dir, mode = format!("{mode:o}"), "read mode bits");
            if is_world_writable(meta.permissions().mode()) {
                findings.push(Finding::new(
                    "persistence",
                    Severity::High,
                    format!("{dir} is world-writable"),
                    format!(
                        "mode {:o}. Any local user can drop or modify a unit/cron entry here \
                         and have it executed with the privileges of whatever runs it \
                         (often root).",
                        meta.permissions().mode() & 0o7777
                    ),
                ));
            }
        } else {
            debug!(dir, "does not exist on this system — clean");
        }
    }
}

fn check_cron_recency(findings: &mut Vec<Finding>) {
    let cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    ];

    debug!(?cron_paths, "walking cron locations for recently-modified entries");
    for base in cron_paths {
        walk_recent(Path::new(base), findings);
    }
}

fn walk_recent(path: &Path, findings: &mut Vec<Finding>) {
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
            walk_recent(&entry.path(), findings);
        }
        return;
    }

    if let Ok(modified) = meta.modified() {
        if let Ok(age) = SystemTime::now().duration_since(modified) {
            debug!(path = %path.display(), age_secs = age.as_secs(), "read cron file mtime");
            if age.as_secs() < RECENT_WINDOW_SECS {
                findings.push(Finding::new(
                    "persistence",
                    Severity::Low,
                    format!("cron entry {} was modified recently", path.display()),
                    format!(
                        "Modified {} ago. Not inherently malicious, but recently-added \
                         scheduled jobs are worth a manual read since cron is a common \
                         persistence vector.",
                        humanize(age.as_secs())
                    ),
                ));
            }
        }
    }
}

fn check_authorized_keys(findings: &mut Vec<Finding>) {
    debug!("reading /etc/passwd to enumerate every account's home directory");
    let Ok(passwd) = fs::read_to_string("/etc/passwd") else {
        return;
    };

    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let Some(user) = fields.first() else { continue };
        let Some(home) = fields.get(5) else { continue };
        if home.is_empty() {
            continue;
        }

        let auth_keys = Path::new(home).join(".ssh").join("authorized_keys");
        debug!(user, path = %auth_keys.display(), "checking account's authorized_keys");
        let Ok(meta) = fs::metadata(&auth_keys) else {
            debug!(user, "no authorized_keys file for this account — clean");
            continue;
        };

        if is_world_writable(meta.permissions().mode()) {
            findings.push(Finding::new(
                "persistence",
                Severity::High,
                format!("{} is world-writable", auth_keys.display()),
                "Any local user could append their own key and gain SSH access as this account.".to_string(),
            ));
        }

        if let Ok(modified) = meta.modified() {
            if let Ok(age) = SystemTime::now().duration_since(modified) {
                if age.as_secs() < RECENT_WINDOW_SECS {
                    findings.push(Finding::new(
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
    }
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
