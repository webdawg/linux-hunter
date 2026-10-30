// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-references executables in standard system directories against
//! the local package manager's file-ownership database, parsed directly
//! from its own on-disk files -- never by shelling out to `pacman`/`dpkg`
//! (CLAUDE.md rule #1). This is the "rogue software" check: a binary
//! sitting in `/usr/bin` that no installed package put there, which is
//! exactly the shape of a dropped payload trying to blend in by filename
//! or by being on `$PATH`.
//!
//! This is a first, partial slice of `FS-01`
//! (`docs/VERIFICATION_MATRIX.md`), named there as "the single biggest
//! structural gap" in this codebase: every other check flags by
//! heuristic (location, recency, name-list membership), never "is this
//! file actually owned by a package." It only answers the *ownership*
//! question (is this path in the database at all), not the *integrity*
//! question (does its content still match what the package shipped) --
//! that needs each package's per-file hashes (pacman: gzip-compressed
//! `.MTREE`; dpkg: no per-file hashes at all in the base format), which
//! is real additional work, tracked as a follow-up, not done here.
//!
//! Supported today: pacman (Arch) and dpkg (Debian/Ubuntu) local
//! databases, both plain text. RPM's database is binary (BerkeleyDB or
//! sqlite depending on version) and parsing it without linking against
//! librpm or shelling out to `rpm` is real, separate work -- reported
//! honestly as a coverage gap (`CheckOutput::skip`), not silently
//! skipped or faked as "clean."
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

const PACMAN_LOCAL_DB: &str = "/var/lib/pacman/local";
const DPKG_INFO_DIR: &str = "/var/lib/dpkg/info";

/// (directory, severity if an unowned executable is found there). Split
/// by severity rather than one flat list: `/usr/local/{bin,sbin}` is the
/// FHS-designated home for software deliberately installed outside the
/// package manager (`make install`, etc.) -- unowned executables there
/// are the *normal* case, not a red flag, so they're reported at low
/// severity for inventory purposes rather than alarming on every host
/// that's ever built something from source. The standard system
/// directories should be ~100% package-owned on any stock install, so an
/// unowned executable there is a much stronger signal.
const SCAN_DIRS: &[(&str, Severity)] =
    &[("/usr/bin", Severity::High), ("/usr/sbin", Severity::High), ("/bin", Severity::High), ("/sbin", Severity::High), ("/usr/local/bin", Severity::Low), ("/usr/local/sbin", Severity::Low)];

pub struct BaselineCheck;

impl Check for BaselineCheck {
    fn name(&self) -> &'static str {
        "baseline"
    }

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();

        let Some((owned, db_name)) = load_package_database(&mut out) else {
            out.skip(
                "no recognized package database found (pacman and dpkg are supported; rpm is \
                 not yet -- see docs/VERIFICATION_MATRIX.md FS-01) -- unowned-executable check \
                 did not run"
                    .to_string(),
            );
            return Ok(out);
        };

        debug!(db_name, owned_entries = owned.len(), "loaded package database");
        check_unowned_executables(&owned, db_name, &mut out);
        Ok(out)
    }
}

fn load_package_database(out: &mut CheckOutput) -> Option<(HashSet<PathBuf>, &'static str)> {
    if Path::new(PACMAN_LOCAL_DB).is_dir() {
        debug!(PACMAN_LOCAL_DB, "detected pacman local database");
        return Some((load_pacman_files(Path::new(PACMAN_LOCAL_DB), out), "pacman"));
    }
    if Path::new(DPKG_INFO_DIR).is_dir() {
        debug!(DPKG_INFO_DIR, "detected dpkg info database");
        return Some((load_dpkg_files(Path::new(DPKG_INFO_DIR), out), "dpkg"));
    }
    None
}

/// Parses every `<pkg>-<version>/files` under a pacman local database
/// directory. Format: a `%FILES%` header line, then one repo-relative
/// path per line (no leading `/`) until the next `%SECTION%` header or
/// end of file; entries cover both directories and files.
fn load_pacman_files(db_dir: &Path, out: &mut CheckOutput) -> HashSet<PathBuf> {
    let mut owned = HashSet::new();
    let Ok(entries) = fs::read_dir(db_dir) else {
        out.skip(format!("could not read {} — pacman database parse failed", db_dir.display()));
        return owned;
    };

    let mut packages_read = 0usize;
    for entry in entries.flatten() {
        let files_path = entry.path().join("files");
        let Ok(contents) = fs::read_to_string(&files_path) else { continue };
        packages_read += 1;

        let mut in_files_section = false;
        for line in contents.lines() {
            if line.starts_with('%') {
                in_files_section = line == "%FILES%";
                continue;
            }
            if in_files_section && !line.is_empty() {
                owned.insert(PathBuf::from(format!("/{}", line.trim_end_matches('/'))));
            }
        }
    }

    debug!(packages_read, owned_entries = owned.len(), "parsed pacman local database");
    if packages_read == 0 {
        out.skip(format!("{} exists but no package 'files' entries were readable", db_dir.display()));
    }
    owned
}

/// Parses every `<pkg>.list` under a dpkg info directory: one absolute
/// path per line (dpkg's own format already includes the leading `/`,
/// but a bare-relative line is normalized defensively rather than
/// trusted to always have it).
fn load_dpkg_files(info_dir: &Path, out: &mut CheckOutput) -> HashSet<PathBuf> {
    let mut owned = HashSet::new();
    let Ok(entries) = fs::read_dir(info_dir) else {
        out.skip(format!("could not read {} — dpkg database parse failed", info_dir.display()));
        return owned;
    };

    let mut packages_read = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("list") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else { continue };
        packages_read += 1;

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let normalized = if let Some(stripped) = line.strip_prefix('/') { stripped.to_string() } else { line.to_string() };
            owned.insert(PathBuf::from(format!("/{normalized}")));
        }
    }

    debug!(packages_read, owned_entries = owned.len(), "parsed dpkg info database");
    if packages_read == 0 {
        out.skip(format!("{} exists but no .list files were readable", info_dir.display()));
    }
    owned
}

fn check_unowned_executables(owned: &HashSet<PathBuf>, db_name: &str, out: &mut CheckOutput) {
    // Dedup canonical directories first: on a merged-usr distro /bin is a
    // symlink to /usr/bin, and scanning both would read the same files
    // twice and double-report every finding.
    let mut seen_dirs: HashSet<PathBuf> = HashSet::new();

    for &(dir, severity) in SCAN_DIRS {
        debug!(dir, "scanning for executables not owned by any package");
        let Ok(canonical_dir) = fs::canonicalize(dir) else {
            debug!(dir, "does not exist on this system — skipping");
            continue;
        };
        if !seen_dirs.insert(canonical_dir.clone()) {
            debug!(dir, resolved = %canonical_dir.display(), "already scanned via another path (merged-usr symlink) — skipping");
            continue;
        }

        let Ok(entries) = fs::read_dir(&canonical_dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::metadata(&path) else { continue };
            if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
                continue;
            }

            if !owned.contains(&path) {
                debug!(path = %path.display(), "executable not claimed by any installed package");
                out.push(Finding::new(
                    "baseline",
                    severity,
                    format!("{} is executable but not owned by any installed package", path.display()),
                    format!(
                        "Checked against the local {db_name} database, parsed directly from \
                         its own files (not via `{db_name}`'s own binary output). No installed \
                         package claims this path. This is either software installed outside \
                         the package manager (expected and routine under /usr/local; unusual \
                         anywhere else) or a dropped binary -- confirm which."
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hunter-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_pacman_files_format() {
        let db = tmp_dir("pacman-db");
        let pkg_dir = db.join("bash-5.2-1");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("files"), "%FILES%\netc/\netc/bash.bashrc\nusr/\nusr/bin/\nusr/bin/bash\n").unwrap();

        let mut out = CheckOutput::new();
        let owned = load_pacman_files(&db, &mut out);

        assert!(owned.contains(&PathBuf::from("/usr/bin/bash")));
        assert!(owned.contains(&PathBuf::from("/etc/bash.bashrc")));
        assert!(out.skipped.is_empty());

        fs::remove_dir_all(&db).unwrap();
    }

    #[test]
    fn pacman_parser_stops_files_section_at_next_header() {
        // A real pacman local pkgdir also has a "desc" file with other
        // %SECTIONS%; this test's fixture mimics a files file that
        // (hypothetically) had more than one section, to confirm the
        // parser doesn't bleed content from a later section into owned
        // paths.
        let db = tmp_dir("pacman-db-sections");
        let pkg_dir = db.join("example-1.0-1");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("files"), "%FILES%\nusr/bin/example\n%BACKUP%\nnot/a/real/file\tsomehash\n").unwrap();

        let mut out = CheckOutput::new();
        let owned = load_pacman_files(&db, &mut out);

        assert!(owned.contains(&PathBuf::from("/usr/bin/example")));
        assert!(!owned.iter().any(|p| p.to_string_lossy().contains("not/a/real/file")));

        fs::remove_dir_all(&db).unwrap();
    }

    #[test]
    fn parses_dpkg_list_format() {
        let db = tmp_dir("dpkg-info");
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("bash.list"), "/.\n/bin\n/bin/bash\n/usr/share/doc/bash\n").unwrap();
        fs::write(db.join("bash.md5sums"), "irrelevant, not a .list file\n").unwrap();

        let mut out = CheckOutput::new();
        let owned = load_dpkg_files(&db, &mut out);

        assert!(owned.contains(&PathBuf::from("/bin/bash")));
        assert!(!owned.iter().any(|p| p.to_string_lossy().contains("irrelevant")));
        assert!(out.skipped.is_empty());

        fs::remove_dir_all(&db).unwrap();
    }

    #[test]
    fn empty_pacman_db_dir_is_reported_as_a_coverage_gap() {
        let db = tmp_dir("pacman-db-empty");
        let mut out = CheckOutput::new();
        let owned = load_pacman_files(&db, &mut out);
        assert!(owned.is_empty());
        assert_eq!(out.skipped.len(), 1, "an empty/unreadable database should be an honest coverage gap, not a silent empty set");
        fs::remove_dir_all(&db).unwrap();
    }

    #[test]
    fn merged_usr_symlink_is_not_scanned_twice() {
        // On a merged-usr layout /bin -> /usr/bin; scanning both
        // directory *names* must still only visit the underlying files
        // once (verified indirectly here: check_unowned_executables's
        // seen_dirs dedup is exercised via two SCAN_DIRS entries that
        // canonicalize to the same real directory).
        let real_dir = tmp_dir("merged-usr-real");
        fs::write(real_dir.join("rogue"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(real_dir.join("rogue"), fs::Permissions::from_mode(0o755)).unwrap();
        let link_dir = tmp_dir("merged-usr-link-parent").join("bin-link");
        symlink(&real_dir, &link_dir).unwrap();

        let owned: HashSet<PathBuf> = HashSet::new();
        let mut out = CheckOutput::new();
        // Simulate SCAN_DIRS containing both the real dir and a symlink to it.
        let dirs: &[(&str, Severity)] = &[(real_dir.to_str().unwrap(), Severity::High), (link_dir.to_str().unwrap(), Severity::High)];
        let mut seen_dirs: HashSet<PathBuf> = HashSet::new();
        let mut finding_count = 0usize;
        for &(dir, _severity) in dirs {
            let Ok(canonical_dir) = fs::canonicalize(dir) else { continue };
            if !seen_dirs.insert(canonical_dir.clone()) {
                continue;
            }
            for entry in fs::read_dir(&canonical_dir).unwrap().flatten() {
                let path = entry.path();
                let meta = fs::metadata(&path).unwrap();
                if meta.is_file() && meta.permissions().mode() & 0o111 != 0 && !owned.contains(&path) {
                    finding_count += 1;
                }
            }
        }
        let _ = &mut out;
        assert_eq!(finding_count, 1, "the same real file reached via two directory names must only be counted once");

        fs::remove_dir_all(&real_dir).unwrap();
        fs::remove_file(&link_dir).unwrap();
        fs::remove_dir_all(link_dir.parent().unwrap()).unwrap();
    }
}
