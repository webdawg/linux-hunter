// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detects two related ways of hiding a malicious shared object in plain
//! sight: dropping a fake-but-plausible library file next to the real
//! system libraries, and patching a trusted binary's ELF dynamic section
//! (DT_NEEDED) so the dynamic linker loads the malicious `.so` for you --
//! no `LD_PRELOAD` required, and the binary itself is never modified
//! beyond its dependency list. Parses ELF directly (CLAUDE.md rule #1):
//! no `readelf`, no `ldd`.
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

/// Standard system library directories across the distros in scope
/// (SPEC.md §1: Debian/Ubuntu, RHEL family, SUSE, Arch, Alpine).
const LIBRARY_DIRS: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
];

/// Core library basenames worth watching for a masquerading second
/// version (the article's trick: a fake `libc.so.4`/`libc.so.5` sitting
/// next to the real `libc.so.6`). Matched as a prefix before `.so`.
const WATCHED_LIB_PREFIXES: &[&str] = &["libc.so", "libselinux.so", "libpcre2-8.so", "ld-linux-x86-64.so", "ld-linux-aarch64.so", "libcap.so"];

/// Binaries whose dependency list we trust to be stable: incident-response
/// and process-inspection tools that, if silently patched to load an
/// attacker's `.so`, can lie to everything downstream (perfctl's
/// trojanized top/ldd/lsof/crontab; this article's same move against
/// ps/pgrep/pkill/killall/pidof/cron/rkhunter).
const TRUST_CRITICAL_BINARIES: &[&str] = &[
    "/bin/ps",
    "/usr/bin/ps",
    "/bin/pgrep",
    "/usr/bin/pgrep",
    "/bin/pkill",
    "/usr/bin/pkill",
    "/bin/killall",
    "/usr/bin/killall",
    "/bin/pidof",
    "/usr/bin/pidof",
    "/usr/sbin/cron",
    "/usr/sbin/crond",
    "/usr/bin/crontab",
    "/bin/top",
    "/usr/bin/top",
    "/usr/bin/lsof",
    "/usr/bin/rkhunter",
    "/usr/local/bin/rkhunter",
    "/usr/bin/chkrootkit",
    "/usr/sbin/chkrootkit",
];

pub struct LibraryCheck;

impl Check for LibraryCheck {
    fn name(&self) -> &'static str {
        "libraries"
    }

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();
        check_shadow_libraries(&mut out);
        check_trust_critical_binaries(&mut out);
        Ok(out)
    }
}

/// Flags a directory that holds more than one distinct *soname* version of
/// the same core library (e.g. both libc.so.5 and libc.so.6). A normal
/// system ships exactly one, wrapped in the standard three-link chain --
/// a dev symlink (`libfoo.so`), a soname symlink (`libfoo.so.N`), and the
/// real versioned file (`libfoo.so.N.M.P`) -- which is why only the exact
/// `prefix.N` soname form is compared; the other two links are expected
/// companions of that one soname, not separate versions.
fn check_shadow_libraries(out: &mut CheckOutput) {
    for dir in LIBRARY_DIRS {
        debug!(dir, "scanning for duplicate core-library soname versions");
        let Ok(entries) = fs::read_dir(dir) else {
            debug!(dir, "does not exist on this system — skipping");
            continue;
        };

        let mut by_prefix: HashMap<&str, Vec<String>> = HashMap::new();
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else { continue };
            for prefix in WATCHED_LIB_PREFIXES {
                if is_soname_form(&name, prefix) {
                    debug!(dir, file = name, prefix, "matched a watched library soname");
                    by_prefix.entry(prefix).or_default().push(name.clone());
                }
            }
        }

        for (prefix, mut files) in by_prefix {
            if files.len() > 1 {
                files.sort();
                out.push(Finding::new(
                    "libraries",
                    Severity::Critical,
                    format!("{dir} has {} soname versions of {prefix}: {}", files.len(), files.join(", ")),
                    "A real system ships exactly one soname for a given core library. A \
                     second, differently-versioned soname (e.g. a libc.so.5 sitting next to \
                     the real libc.so.6) is a common way to smuggle a malicious shared object \
                     under a plausible-looking name, counting on it blending in during a \
                     casual directory listing."
                        .to_string(),
                ));
            }
        }
    }
}

/// True if `name` is exactly `{prefix}.N` for some run of ASCII digits N --
/// the canonical soname form, as opposed to the bare dev-symlink name
/// (`{prefix}` with no trailing version) or the fully-versioned real file
/// (`{prefix}.N.M...`, which has further dots after the major version).
fn is_soname_form(name: &str, prefix: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix).and_then(|r| r.strip_prefix('.')) else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

fn check_trust_critical_binaries(out: &mut CheckOutput) {
    let mut checked_any = false;
    for path in TRUST_CRITICAL_BINARIES {
        let Ok(canonical) = fs::canonicalize(path) else {
            continue; // doesn't exist on this system/distro — not a gap
        };
        checked_any = true;
        debug!(path, resolved = %canonical.display(), "reading ELF dynamic section");

        let dyn_info = match read_elf_dynamic(&canonical) {
            Ok(Some(info)) => info,
            Ok(None) => {
                debug!(path, "not a recognized ELF64 little-endian binary — skipping (e.g. a shell-script wrapper)");
                continue;
            }
            Err(err) => {
                out.skip(format!("could not parse ELF for {path} ({err})"));
                continue;
            }
        };

        debug!(path, needed = ?dyn_info.needed, rpath = ?dyn_info.rpath, "parsed dynamic section");

        let mut seen = HashMap::new();
        for lib in &dyn_info.needed {
            *seen.entry(lib.clone()).or_insert(0u32) += 1;
        }
        for (lib, count) in seen {
            if count > 1 {
                out.push(Finding::new(
                    "libraries",
                    Severity::Critical,
                    format!("{path} depends on \"{lib}\" {count} times"),
                    "A compiler never emits the same DT_NEEDED entry twice. A duplicate \
                     dependency is the signature left behind by tools like patchelf \
                     --add-needed being run against an already-linked binary -- the classic \
                     way to make a trusted tool (ps, pkill, killall, rkhunter, ...) silently \
                     load an attacker's shared object without touching LD_PRELOAD."
                        .to_string(),
                ));
            }
        }

        if let Some(rpath) = &dyn_info.rpath {
            out.push(Finding::new(
                "libraries",
                Severity::Medium,
                format!("{path} has a non-default library search path: {rpath}"),
                "Distro-packaged core utilities normally rely on the system default search \
                 path (ld.so.cache) and carry no RPATH/RUNPATH. One being present means this \
                 binary's dependencies can resolve from a directory other than the trusted \
                 system library directories -- worth confirming it points somewhere legitimate."
                    .to_string(),
            ));
        }
    }

    if !checked_any {
        out.skip("none of the trust-critical binaries (ps/pgrep/pkill/killall/pidof/cron/rkhunter/...) were found at their expected paths".to_string());
    }
}

struct DynInfo {
    needed: Vec<String>,
    rpath: Option<String>,
}

const PT_DYNAMIC: u32 = 2;
const PT_LOAD: u32 = 1;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_RPATH: i64 = 15;
const DT_RUNPATH: i64 = 29;

/// Parses just enough of an ELF64 little-endian file to read its
/// DT_NEEDED and DT_RPATH/DT_RUNPATH dynamic-section entries. Returns
/// `Ok(None)` for anything that isn't a recognized ELF64 LE file (e.g. a
/// `#!/bin/sh` wrapper script, or a 32-bit/big-endian binary -- out of
/// scope per SPEC.md §1, x86_64/arm64 only).
fn read_elf_dynamic(path: &Path) -> Result<Option<DynInfo>> {
    let data = fs::read(path)?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Ok(None);
    }
    let ei_class = data[4];
    let ei_data = data[5];
    if ei_class != 2 || ei_data != 1 {
        // Not ELF64, or not little-endian.
        return Ok(None);
    }

    let e_phoff = read_u64(&data, 0x20) as usize;
    let e_phentsize = read_u16(&data, 0x36) as usize;
    let e_phnum = read_u16(&data, 0x38) as usize;

    let mut dyn_off = None;
    let mut dyn_size = None;
    let mut load_segments = Vec::new();

    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + 56 > data.len() {
            break;
        }
        let p_type = read_u32(&data, off);
        let p_offset = read_u64(&data, off + 8);
        let p_vaddr = read_u64(&data, off + 16);
        let p_filesz = read_u64(&data, off + 32);
        let p_memsz = read_u64(&data, off + 40);

        if p_type == PT_DYNAMIC {
            dyn_off = Some(p_offset as usize);
            dyn_size = Some(p_filesz as usize);
        } else if p_type == PT_LOAD {
            load_segments.push((p_vaddr, p_memsz, p_offset));
        }
    }

    let (Some(dyn_off), Some(dyn_size)) = (dyn_off, dyn_size) else {
        return Ok(None); // statically linked: no PT_DYNAMIC, nothing to check
    };

    let mut strtab_vaddr = None;
    let mut needed_str_offsets = Vec::new();
    let mut rpath_str_offset = None;

    let mut i = 0;
    while i + 16 <= dyn_size {
        let off = dyn_off + i;
        if off + 16 > data.len() {
            break;
        }
        let tag = read_u64(&data, off) as i64;
        let val = read_u64(&data, off + 8);
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_NEEDED => needed_str_offsets.push(val),
            DT_STRTAB => strtab_vaddr = Some(val),
            DT_RPATH | DT_RUNPATH => rpath_str_offset = Some(val),
            _ => {}
        }
        i += 16;
    }

    let Some(strtab_vaddr) = strtab_vaddr else {
        return Ok(None);
    };
    let Some(strtab_file_off) = vaddr_to_file_offset(&load_segments, strtab_vaddr) else {
        return Ok(None);
    };

    let needed = needed_str_offsets.into_iter().filter_map(|rel| read_cstr(&data, strtab_file_off + rel as usize)).collect();
    let rpath = rpath_str_offset.and_then(|rel| read_cstr(&data, strtab_file_off + rel as usize));

    Ok(Some(DynInfo { needed, rpath }))
}

fn vaddr_to_file_offset(load_segments: &[(u64, u64, u64)], vaddr: u64) -> Option<usize> {
    for &(seg_vaddr, seg_memsz, seg_offset) in load_segments {
        if vaddr >= seg_vaddr && vaddr < seg_vaddr + seg_memsz {
            return Some((seg_offset + (vaddr - seg_vaddr)) as usize);
        }
    }
    None
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    let end = data[offset..].iter().position(|&b| b == 0)? + offset;
    String::from_utf8(data[offset..end].to_vec()).ok()
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}
