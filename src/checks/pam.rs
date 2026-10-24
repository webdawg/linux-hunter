// SPDX-License-Identifier: AGPL-3.0-or-later
//! PAM (Pluggable Authentication Modules) checks, per
//! docs/research/persistence-techniques.md §5 and SPEC.md §3.6: "Hash
//! every module vs package; unknown .so names" and "pam_exec.so lines,
//! `sufficient` modules inserted above pam_unix.so, unknown module
//! names". Plague (2024-25) went undetected by every AV engine for a
//! year as a malicious PAM module with a static backdoor password;
//! QLNX, perfctl, Orbit, Skidmap, and Azazel all used the same family of
//! technique.
//!
//! No package-hash baseline exists yet (see CLAUDE.md "Current
//! implementation status"), so this flags by two heuristics instead:
//! an unrecognized module filename, and a PAM config line whose control
//! flag can grant access on its own (`sufficient`) for a module that
//! isn't one of the common legitimate SSO/alternate-auth modules that
//! pattern is normally used for.
use std::fs;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

const PAM_MODULE_DIRS: &[&str] = &[
    "/lib/security",
    "/usr/lib/security",
    "/lib64/security",
    "/usr/lib64/security",
    "/lib/x86_64-linux-gnu/security",
    "/usr/lib/x86_64-linux-gnu/security",
    "/lib/aarch64-linux-gnu/security",
    "/usr/lib/aarch64-linux-gnu/security",
];

/// Curated from what ships across major distros (Arch, Debian/Ubuntu,
/// RHEL/Fedora): a module not on this list isn't necessarily malicious
/// (this is a heuristic, not a baseline -- see module doc comment), but
/// it's an unusual enough name to be worth a human look. Snapshot taken
/// 2026-10-24 against a live Arch host's /usr/lib/security (54 modules,
/// all recognized) plus common modules from other distros/SSO setups
/// that weren't present there.
const COMMON_PAM_MODULES: &[&str] = &[
    "pam_access.so",
    "pam_apparmor.so",
    "pam_canonicalize_user.so",
    "pam_cap.so",
    "pam_cifscreds.so",
    "pam_cracklib.so",
    "pam_debug.so",
    "pam_deny.so",
    "pam_duo.so",
    "pam_echo.so",
    "pam_ecryptfs.so",
    "pam_env.so",
    "pam_exec.so",
    "pam_faildelay.so",
    "pam_faillock.so",
    "pam_filter.so",
    "pam_fprintd.so",
    "pam_ftp.so",
    "pam_gnome_keyring.so",
    "pam_google_authenticator.so",
    "pam_group.so",
    "pam_issue.so",
    "pam_keyinit.so",
    "pam_krb5.so",
    "pam_lastlog.so",
    "pam_lastlog2.so",
    "pam_ldap.so",
    "pam_limits.so",
    "pam_listfile.so",
    "pam_localuser.so",
    "pam_loginuid.so",
    "pam_mail.so",
    "pam_mkhomedir.so",
    "pam_motd.so",
    "pam_mount.so",
    "pam_namespace.so",
    "pam_nologin.so",
    "pam_oath.so",
    "pam_permit.so",
    "pam_pwhistory.so",
    "pam_pwquality.so",
    "pam_radius.so",
    "pam_rhosts.so",
    "pam_rootok.so",
    "pam_securetty.so",
    "pam_selinux.so",
    "pam_setquota.so",
    "pam_shells.so",
    "pam_sss.so",
    "pam_stress.so",
    "pam_succeed_if.so",
    "pam_systemd.so",
    "pam_systemd_home.so",
    "pam_systemd_loadkey.so",
    "pam_tally2.so",
    "pam_time.so",
    "pam_timestamp.so",
    "pam_tty_audit.so",
    "pam_u2f.so",
    "pam_umask.so",
    "pam_unix.so",
    "pam_usertype.so",
    "pam_warn.so",
    "pam_wheel.so",
    "pam_winbind.so",
    "pam_xauth.so",
    "pam_yubico.so",
];

/// Modules it's normal to see with a `sufficient` control flag.
/// `pam_unix.so` itself, SSO/alternate-auth-method modules ("try this,
/// fall through to local auth if it's not configured for this user"),
/// and -- confirmed against a real Arch host's shipped configs, which is
/// how `pam_rootok.so` and `pam_rhosts.so` ended up here -- a handful of
/// "the calling context already proves who you are" modules: su/passwd/
/// chfn/chsh/runuser all ship `auth sufficient pam_rootok.so` ("already
/// root? skip the password"), and rlogin ships `auth sufficient
/// pam_rhosts.so` (that's the entire point of rlogin). Originally this
/// list only had the SSO entries and flagged all three of those as
/// Critical/High on a stock, unmodified system -- a real false-positive
/// bug caught by running the finished check against this host's full
/// /etc/pam.d, not just the one file (system-auth) used while writing
/// the parser tests.
const LEGITIMATE_SUFFICIENT_MODULES: &[&str] = &[
    "pam_unix.so",
    "pam_sss.so",
    "pam_ldap.so",
    "pam_krb5.so",
    "pam_winbind.so",
    "pam_google_authenticator.so",
    "pam_u2f.so",
    "pam_yubico.so",
    "pam_duo.so",
    "pam_radius.so",
    "pam_systemd_home.so",
    "pam_rootok.so",
    "pam_rhosts.so",
    "pam_wheel.so",
    "pam_localuser.so",
];

pub struct PamCheck;

impl Check for PamCheck {
    fn name(&self) -> &'static str {
        "pam"
    }

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();
        check_pam_modules(&mut out);
        check_pam_config(&mut out);
        Ok(out)
    }
}

fn check_pam_modules(out: &mut CheckOutput) {
    for dir in PAM_MODULE_DIRS {
        debug!(dir, "scanning PAM module directory");
        let Ok(entries) = fs::read_dir(dir) else {
            debug!(dir, "does not exist on this system — skipping");
            continue;
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".so") {
                continue;
            }
            debug!(dir, module = name, recognized = COMMON_PAM_MODULES.contains(&name.as_str()), "checked PAM module");

            if !COMMON_PAM_MODULES.contains(&name.as_str()) {
                out.push(Finding::new(
                    "pam",
                    Severity::Medium,
                    format!("{dir}/{name} is not a commonly-recognized PAM module"),
                    "Not on our curated common-module list (heuristic, not a package-hash \
                     baseline — see CLAUDE.md). Plague (2024-25) went undetected by every AV \
                     engine for a year as exactly this: a PAM module with an unremarkable name \
                     sitting in this directory. Worth confirming it's installed by a real \
                     package and doing what its name suggests."
                        .to_string(),
                ));
            }
        }
    }
}

fn check_pam_config(out: &mut CheckOutput) {
    let Ok(entries) = fs::read_dir("/etc/pam.d") else {
        out.skip("could not read /etc/pam.d — PAM config check did not run".to_string());
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else { continue };
        debug!(path = %path.display(), "checking PAM config file");

        for (lineno, line) in contents.lines().enumerate() {
            let Some(parsed) = parse_pam_line(line) else { continue };
            debug!(path = %path.display(), lineno = lineno + 1, ?parsed, "parsed pam.d line");

            if parsed.module == "pam_exec.so" {
                out.push(Finding::new(
                    "pam",
                    Severity::Low,
                    format!("{}:{} runs pam_exec.so", path.display(), lineno + 1),
                    format!(
                        "`{}`. pam_exec.so runs an arbitrary external command as part of the \
                         auth flow -- legitimate (2FA hooks, account provisioning scripts) but \
                         worth confirming the command is expected.",
                        line.trim()
                    ),
                ));
            }

            if parsed.control.eq_ignore_ascii_case("sufficient") && is_unexpected_sufficient_module(&parsed.module) {
                out.push(Finding::new(
                    "pam",
                    Severity::Medium,
                    format!("{}:{} has \"{}\" as a sufficient module in the {} stack", path.display(), lineno + 1, parsed.module, parsed.pam_type),
                    format!(
                        "`{}`. A `sufficient` result ends the stack and grants access \
                         immediately, without the rest of the stack (including pam_unix.so) \
                         running at all -- the pattern malicious PAM modules use to add an \
                         authentication bypass. It's also a legitimate, common pattern on its \
                         own (su-style \"already-proven\" shortcuts, SSO fallthrough, \
                         service-internal stacks with no real auth by design), so this isn't \
                         conclusive by itself: worth a look especially if this file governs a \
                         network-facing or remote-login service rather than a local utility.",
                        line.trim()
                    ),
                ));
            }
        }
    }
}

fn is_unexpected_sufficient_module(module: &str) -> bool {
    !LEGITIMATE_SUFFICIENT_MODULES.contains(&module)
}

#[derive(Debug, PartialEq, Eq)]
struct PamLine {
    pam_type: String,
    control: String,
    module: String,
}

/// Parses one `/etc/pam.d/*` line into (type, control, module), handling
/// both simple control flags (`required`, `sufficient`, ...) and bracket
/// syntax (`[success=1 default=bad]`, which contains spaces and is NOT a
/// single whitespace-delimited token -- a naive `split_whitespace` would
/// shift every field after it). Also strips the leading `-` ("don't log
/// if this module is missing") marker. Returns `None` for blank lines,
/// comments, and lines this parser doesn't recognize the shape of
/// (e.g. `@include` directives).
fn parse_pam_line(line: &str) -> Option<PamLine> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
        return None;
    }
    let line = line.strip_prefix('-').unwrap_or(line).trim_start();

    let (pam_type, rest) = take_token(line)?;
    let rest = rest.trim_start();

    let (control, rest) = if rest.starts_with('[') { take_bracketed(rest)? } else { take_token(rest)? };
    let rest = rest.trim_start();

    let (module, _rest) = take_token(rest)?;

    Some(PamLine {
        pam_type: pam_type.to_ascii_lowercase(),
        control: control.to_string(),
        module: module.to_string(),
    })
}

/// Splits off the next whitespace-delimited token, returning it and the
/// remainder of the string after it.
fn take_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(i) => Some((&s[..i], &s[i..])),
        None => Some((s, "")),
    }
}

/// Splits off a `[...]` bracketed expression (which may contain internal
/// whitespace, e.g. `[success=1 default=bad]`), returning its full text
/// including the brackets, and the remainder after the closing `]`.
fn take_bracketed(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let rest = s.strip_prefix('[')?;
    let close = rest.find(']')?;
    Some((&s[..close + 2], &rest[close + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_control_flag() {
        let parsed = parse_pam_line("auth required pam_unix.so try_first_pass nullok").unwrap();
        assert_eq!(parsed.pam_type, "auth");
        assert_eq!(parsed.control, "required");
        assert_eq!(parsed.module, "pam_unix.so");
    }

    #[test]
    fn parses_bracketed_control_flag_containing_spaces() {
        // The exact real-world shape that would break a plain split_whitespace
        // field-index parser by shifting every later field over.
        let parsed = parse_pam_line("auth      [success=1 default=bad]     pam_unix.so          try_first_pass nullok").unwrap();
        assert_eq!(parsed.pam_type, "auth");
        assert_eq!(parsed.control, "[success=1 default=bad]");
        assert_eq!(parsed.module, "pam_unix.so");
    }

    #[test]
    fn strips_leading_silent_marker() {
        let parsed = parse_pam_line("-auth      [success=2 default=ignore]  pam_systemd_home.so").unwrap();
        assert_eq!(parsed.pam_type, "auth");
        assert_eq!(parsed.module, "pam_systemd_home.so");
    }

    #[test]
    fn ignores_comments_blank_lines_and_includes() {
        assert!(parse_pam_line("# a comment").is_none());
        assert!(parse_pam_line("").is_none());
        assert!(parse_pam_line("   ").is_none());
        assert!(parse_pam_line("@include common-auth").is_none());
    }

    #[test]
    fn pam_type_is_case_normalized() {
        let parsed = parse_pam_line("AUTH required pam_unix.so").unwrap();
        assert_eq!(parsed.pam_type, "auth");
    }

    #[test]
    fn common_distro_shipped_sufficient_patterns_are_not_flagged() {
        // Each of these is a real line from an unmodified Arch host's
        // /etc/pam.d/{su,rlogin,system-services} -- all three were flagged
        // as High/Critical by an earlier version of this check before being
        // run against the full /etc/pam.d directory (not just system-auth,
        // which the parser unit tests were originally built against) surfaced
        // the false positives. pam_permit.so is deliberately NOT on the
        // allowlist (see is_unexpected_sufficient_module's remaining true
        // case below) -- it's still surfaced, just at reduced severity.
        for module in ["pam_rootok.so", "pam_rhosts.so"] {
            assert!(!is_unexpected_sufficient_module(module), "{module} is a standard distro-shipped sufficient module");
        }
    }

    #[test]
    fn pam_permit_sufficient_is_still_surfaced() {
        // Unlike pam_rootok/pam_rhosts, pam_permit.so unconditionally
        // succeeds -- worth a look even though some distros ship it
        // deliberately for service-internal, no-real-auth-needed stacks.
        assert!(is_unexpected_sufficient_module("pam_permit.so"));
    }

    #[test]
    fn real_host_system_auth_produces_no_sufficient_or_unrecognized_lines() {
        // Regression guard for the exact file shape seen on the Arch host
        // this check was developed against: optional pam_permit.so and
        // bracket-syntax pam_systemd_home.so lines must NOT be mistaken
        // for a `sufficient` bypass.
        let fixture = "auth       required                    pam_faillock.so      preauth\n\
             -auth      [success=2 default=ignore]  pam_systemd_home.so\n\
             auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok\n\
             auth       optional                    pam_permit.so\n";
        for line in fixture.lines() {
            let parsed = parse_pam_line(line).unwrap();
            assert_ne!(parsed.control.to_ascii_lowercase(), "sufficient", "line should not parse as sufficient: {line}");
        }
    }
}
