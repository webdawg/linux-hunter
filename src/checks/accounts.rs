// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

/// UIDs below this are conventionally reserved for system/service accounts
/// across the distros in scope (SPEC.md §1). Not a hard standard — some
/// distros vary — so this is a heuristic, not a guarantee.
const SERVICE_UID_MAX: u32 = 999;

const NOLOGIN_SHELLS: &[&str] = &["/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin", "/bin/false", "/bin/true", ""];

/// Group membership in any of these is root-equivalent: wheel/sudo grant
/// full sudo, docker grants root via the daemon socket (CLAUDE.md rule #1
/// says never trust `id`/`groups` output either — we parse /etc/group raw).
const ROOT_EQUIVALENT_GROUPS: &[&str] = &["root", "wheel", "sudo", "docker"];

struct PasswdEntry {
    name: String,
    uid: u32,
    home: String,
    shell: String,
}

pub struct AccountsCheck;

impl Check for AccountsCheck {
    fn name(&self) -> &'static str {
        "accounts"
    }

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();

        let entries = read_passwd(&mut out);
        check_uid_zero_duplicates(&entries, &mut out);
        check_service_account_posture(&entries, &mut out);
        check_shadow(&mut out);
        check_sudoers(&mut out);
        check_root_equivalent_groups(&mut out);

        Ok(out)
    }
}

fn read_passwd(out: &mut CheckOutput) -> Vec<PasswdEntry> {
    debug!("reading /etc/passwd");
    let contents = match fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(err) => {
            out.skip(format!("could not read /etc/passwd ({err}) — accounts check did not run"));
            return Vec::new();
        }
    };

    contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            Some(PasswdEntry {
                name: fields.first()?.to_string(),
                uid: fields.get(2)?.parse().ok()?,
                home: fields.get(5)?.to_string(),
                shell: fields.get(6).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

fn check_uid_zero_duplicates(entries: &[PasswdEntry], out: &mut CheckOutput) {
    let root_equivalents: Vec<&str> = entries.iter().filter(|e| e.uid == 0).map(|e| e.name.as_str()).collect();
    debug!(?root_equivalents, "accounts with uid 0");

    if root_equivalents.len() > 1 || (root_equivalents.len() == 1 && root_equivalents[0] != "root") {
        out.push(Finding::new(
            "accounts",
            Severity::Critical,
            "more than one account has uid 0, or the sole uid-0 account is not named \"root\"".to_string(),
            format!(
                "Accounts with uid 0: {}. A second root-equivalent account is a classic, \
                 simple backdoor — anyone who can log in as it has full root with no sudo \
                 trail.",
                root_equivalents.join(", ")
            ),
        ));
    }
}

fn check_service_account_posture(entries: &[PasswdEntry], out: &mut CheckOutput) {
    for entry in entries {
        if entry.uid == 0 || entry.uid > SERVICE_UID_MAX {
            continue;
        }

        debug!(user = entry.name, uid = entry.uid, shell = entry.shell, "checking service account posture");

        if !NOLOGIN_SHELLS.contains(&entry.shell.as_str()) {
            out.push(Finding::new(
                "accounts",
                Severity::Medium,
                format!("service account \"{}\" (uid {}) has an interactive shell: {}", entry.name, entry.uid, entry.shell),
                "Service/system accounts are normally set to a nologin shell. An interactive \
                 shell on one is either an unusual local configuration or a sign the account \
                 was repurposed for access."
                    .to_string(),
            ));
        }

        let ssh_dir = Path::new(&entry.home).join(".ssh");
        if fs::metadata(&ssh_dir).is_ok() {
            out.push(Finding::new(
                "accounts",
                Severity::Medium,
                format!("service account \"{}\" (uid {}) has an ~/.ssh directory", entry.name, entry.uid),
                format!(
                    "{} exists. Service accounts rarely need SSH access; perfctl has been \
                     observed planting authorized_keys under default system accounts' home \
                     directories specifically because nobody looks there.",
                    ssh_dir.display()
                ),
            ));
        }
    }
}

fn check_shadow(out: &mut CheckOutput) {
    debug!("reading /etc/shadow for empty password hashes");
    let contents = match fs::read_to_string("/etc/shadow") {
        Ok(c) => c,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            out.skip("could not read /etc/shadow (permission denied) — empty-password check did not run; needs root".to_string());
            return;
        }
        Err(err) => {
            out.skip(format!("could not read /etc/shadow ({err}) — empty-password check did not run"));
            return;
        }
    };

    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(user) = fields.next() else { continue };
        let Some(hash) = fields.next() else { continue };

        debug!(user, hash_empty = hash.is_empty(), "checked shadow entry");
        if hash.is_empty() {
            out.push(Finding::new(
                "accounts",
                Severity::Critical,
                format!("account \"{user}\" has an empty password hash"),
                "An empty hash field in /etc/shadow means this account can log in (at consoles \
                 that allow it, and via some PAM configurations) with no password at all."
                    .to_string(),
            ));
        }
    }
}

fn check_sudoers(out: &mut CheckOutput) {
    let mut sudoers_files = vec!["/etc/sudoers".to_string()];
    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            sudoers_files.push(entry.path().to_string_lossy().into_owned());
        }
    }

    let mut any_readable = false;
    for path in &sudoers_files {
        debug!(path, "checking sudoers file for broad NOPASSWD grants");
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
            if trimmed.contains("NOPASSWD") && trimmed.contains("ALL") {
                out.push(Finding::new(
                    "accounts",
                    Severity::Medium,
                    format!("{path} grants passwordless sudo: `{trimmed}`"),
                    "NOPASSWD:ALL lets the matched user run anything as root with no \
                     re-authentication. Sometimes a deliberate operational choice, but every \
                     instance is worth confirming against a change record."
                        .to_string(),
                ));
            }
        }
    }

    if !any_readable {
        out.skip("could not read /etc/sudoers or /etc/sudoers.d/* (permission denied) — sudoers check did not run; needs root".to_string());
    }
}

fn check_root_equivalent_groups(out: &mut CheckOutput) {
    debug!("reading /etc/group for root-equivalent group membership");
    let Ok(contents) = fs::read_to_string("/etc/group") else {
        out.skip("could not read /etc/group — group-membership check did not run".to_string());
        return;
    };

    let mut by_group: HashMap<&str, Vec<&str>> = HashMap::new();
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let Some(name) = fields.first() else { continue };
        if !ROOT_EQUIVALENT_GROUPS.contains(name) {
            continue;
        }
        let members: Vec<&str> = fields.get(3).map(|m| m.split(',').filter(|m| !m.is_empty()).collect()).unwrap_or_default();
        debug!(group = name, ?members, "read root-equivalent group");
        if !members.is_empty() {
            by_group.insert(name, members);
        }
    }

    for (group, members) in by_group {
        out.push(Finding::new(
            "accounts",
            Severity::Low,
            format!("group \"{group}\" has {} member(s): {}", members.len(), members.join(", ")),
            "Membership in root/wheel/sudo/docker is root-equivalent (docker via the daemon \
             socket). Not a finding on its own without a baseline of who's expected — listed \
             for manual review."
                .to_string(),
        ));
    }
}
