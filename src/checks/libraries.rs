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
/// Returns `Ok(None)` both for "not an ELF64-LE file" (not a bug) and for
/// "an ELF64-LE file whose internal offsets don't add up" (a malformed or
/// truncated file -- also not a bug: every offset read from the file is
/// bounds-checked via the `Option`-returning helpers and `checked_add`
/// below, so a crafted/corrupted binary makes this function give up and
/// return `None`, not panic the process). See the regression tests at the
/// bottom of this file for the specific shapes this guards against.
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

    let Some(dyn_info) = parse_dynamic_section(&data) else {
        return Ok(None);
    };
    Ok(Some(dyn_info))
}

fn parse_dynamic_section(data: &[u8]) -> Option<DynInfo> {
    let e_phoff = read_u64(data, 0x20)? as usize;
    let e_phentsize = read_u16(data, 0x36)? as usize;
    let e_phnum = read_u16(data, 0x38)? as usize;

    let mut dyn_off = None;
    let mut dyn_size = None;
    let mut load_segments = Vec::new();

    for i in 0..e_phnum {
        let off = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        if off.checked_add(56)? > data.len() {
            break;
        }
        let p_type = read_u32(data, off)?;
        let p_offset = read_u64(data, off.checked_add(8)?)?;
        let p_vaddr = read_u64(data, off.checked_add(16)?)?;
        let p_filesz = read_u64(data, off.checked_add(32)?)?;
        let p_memsz = read_u64(data, off.checked_add(40)?)?;

        if p_type == PT_DYNAMIC {
            dyn_off = Some(usize::try_from(p_offset).ok()?);
            dyn_size = Some(usize::try_from(p_filesz).ok()?);
        } else if p_type == PT_LOAD {
            load_segments.push((p_vaddr, p_memsz, p_offset));
        }
    }

    let (dyn_off, dyn_size) = (dyn_off?, dyn_size?); // statically linked: no PT_DYNAMIC, nothing to check

    let mut strtab_vaddr = None;
    let mut needed_str_offsets = Vec::new();
    let mut rpath_str_offset = None;

    let mut i = 0usize;
    while i.checked_add(16)? <= dyn_size {
        let off = dyn_off.checked_add(i)?;
        if off.checked_add(16)? > data.len() {
            break;
        }
        let tag = read_u64(data, off)? as i64;
        let val = read_u64(data, off.checked_add(8)?)?;
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_NEEDED => needed_str_offsets.push(val),
            DT_STRTAB => strtab_vaddr = Some(val),
            DT_RPATH | DT_RUNPATH => rpath_str_offset = Some(val),
            _ => {}
        }
        i = i.checked_add(16)?;
    }

    let strtab_file_off = vaddr_to_file_offset(&load_segments, strtab_vaddr?)?;

    let needed = needed_str_offsets
        .into_iter()
        .filter_map(|rel| strtab_file_off.checked_add(usize::try_from(rel).ok()?).and_then(|o| read_cstr(data, o)))
        .collect();
    let rpath = rpath_str_offset
        .and_then(|rel| strtab_file_off.checked_add(usize::try_from(rel).ok()?))
        .and_then(|o| read_cstr(data, o));

    Some(DynInfo { needed, rpath })
}

fn vaddr_to_file_offset(load_segments: &[(u64, u64, u64)], vaddr: u64) -> Option<usize> {
    for &(seg_vaddr, seg_memsz, seg_offset) in load_segments {
        let seg_end = seg_vaddr.checked_add(seg_memsz)?;
        if vaddr >= seg_vaddr && vaddr < seg_end {
            let file_off = seg_offset.checked_add(vaddr.checked_sub(seg_vaddr)?)?;
            return usize::try_from(file_off).ok();
        }
    }
    None
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    let rest = data.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    String::from_utf8(rest.get(..end)?.to_vec()).ok()
}

/// All three readers below return `None` rather than panicking on a bad
/// offset. This file reads untrusted ELF files -- real binaries the
/// scan walks, which on an already-compromised host could be deliberately
/// malformed specifically to crash the scanner -- so every offset here is
/// attacker-influenced. Bounds checks must use `checked_add`/`slice::get`
/// rather than raw `+`/indexing: both panic on overflow/out-of-range (the
/// former only in debug builds, the latter in both), and this file's own
/// `read_elf_dynamic` was built with raw `+` and `.unwrap()` here
/// originally -- a crafted PT_DYNAMIC segment with a large `p_offset` (or
/// a DT_NEEDED value picked to push a later offset near `usize::MAX`)
/// could panic the whole process, not just fail this one check. See the
/// malformed-ELF regression tests at the bottom of this file.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(data.get(offset..end)?.try_into().ok()?))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(data.get(offset..end)?.try_into().ok()?))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    Some(u64::from_le_bytes(data.get(offset..end)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-builds a minimal, otherwise-valid ELF64-LE file with one
    /// PT_LOAD segment (vaddr 0 == file offset 0, covering the whole
    /// file) and one PT_DYNAMIC segment containing `needed` as DT_NEEDED
    /// entries (as (value, string) pairs so a test can plant an
    /// out-of-range value deliberately) plus a terminating DT_NULL.
    fn build_minimal_elf(needed: &[(u64, &str)]) -> Vec<u8> {
        let mut strtab = vec![0u8]; // leading NUL, like a real strtab
        let mut needed_entries: Vec<(u64, u64)> = Vec::new(); // (tag_val, resolved_rel_offset) pairs we'll override below
        for &(forced_val, name) in needed {
            let rel = if forced_val != 0 { forced_val } else { strtab.len() as u64 };
            if forced_val == 0 {
                strtab.extend_from_slice(name.as_bytes());
                strtab.push(0);
            }
            needed_entries.push((1, rel)); // DT_NEEDED tag = 1
        }

        const EHDR_SIZE: usize = 64;
        const PHDR_SIZE: usize = 56;
        let phdr_count = 2; // PT_LOAD, PT_DYNAMIC
        let phdrs_end = EHDR_SIZE + phdr_count * PHDR_SIZE;
        let dyn_off = phdrs_end;
        let dyn_entry_count = needed_entries.len() + 2; // + DT_STRTAB + DT_NULL
        let dyn_size = dyn_entry_count * 16;
        let strtab_off = dyn_off + dyn_size;
        let total_len = strtab_off + strtab.len();

        let mut data = vec![0u8; total_len];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[0x20..0x28].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_phoff
        data[0x36..0x38].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
        data[0x38..0x3a].copy_from_slice(&(phdr_count as u16).to_le_bytes()); // e_phnum

        // PT_LOAD: p_offset=0, p_vaddr=0, p_filesz=p_memsz=total_len.
        let load_off = EHDR_SIZE;
        data[load_off..load_off + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        data[load_off + 8..load_off + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        data[load_off + 16..load_off + 24].copy_from_slice(&0u64.to_le_bytes()); // p_vaddr
        data[load_off + 32..load_off + 40].copy_from_slice(&(total_len as u64).to_le_bytes()); // p_filesz
        data[load_off + 40..load_off + 48].copy_from_slice(&(total_len as u64).to_le_bytes()); // p_memsz

        // PT_DYNAMIC: p_offset=p_vaddr=dyn_off, p_filesz=p_memsz=dyn_size.
        let dynhdr_off = EHDR_SIZE + PHDR_SIZE;
        data[dynhdr_off..dynhdr_off + 4].copy_from_slice(&2u32.to_le_bytes()); // p_type = PT_DYNAMIC
        data[dynhdr_off + 8..dynhdr_off + 16].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        data[dynhdr_off + 16..dynhdr_off + 24].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        data[dynhdr_off + 32..dynhdr_off + 40].copy_from_slice(&(dyn_size as u64).to_le_bytes());
        data[dynhdr_off + 40..dynhdr_off + 48].copy_from_slice(&(dyn_size as u64).to_le_bytes());

        // Dynamic entries: one DT_NEEDED per `needed`, then DT_STRTAB, then DT_NULL.
        let mut off = dyn_off;
        for &(tag, val) in &needed_entries {
            data[off..off + 8].copy_from_slice(&(tag as u64).to_le_bytes());
            data[off + 8..off + 16].copy_from_slice(&val.to_le_bytes());
            off += 16;
        }
        data[off..off + 8].copy_from_slice(&5u64.to_le_bytes()); // DT_STRTAB
        data[off + 8..off + 16].copy_from_slice(&(strtab_off as u64).to_le_bytes());
        off += 16;
        data[off..off + 8].copy_from_slice(&0u64.to_le_bytes()); // DT_NULL
        off += 16;
        let _ = off;

        data[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
        data
    }

    #[test]
    fn parses_a_well_formed_minimal_elf() {
        let data = build_minimal_elf(&[(0, "libc.so.6"), (0, "libselinux.so.1")]);
        let info = parse_dynamic_section(&data).expect("well-formed fixture should parse");
        assert_eq!(info.needed, vec!["libc.so.6", "libselinux.so.1"]);
        assert_eq!(info.rpath, None);
    }

    #[test]
    fn truncated_file_returns_none_not_panic() {
        let data = build_minimal_elf(&[(0, "libc.so.6")]);
        // Cut it off partway through the program headers.
        let truncated = &data[..70];
        assert!(parse_dynamic_section(truncated).is_none());
    }

    #[test]
    fn huge_phoff_does_not_panic_or_overflow() {
        // The exact shape of the original bug: a crafted e_phoff near
        // usize::MAX, which the old `e_phoff + i * e_phentsize` raw
        // addition (and the old `.unwrap()`-based readers) would have
        // panicked on -- taking the whole scan down, not just this check.
        let mut data = build_minimal_elf(&[(0, "libc.so.6")]);
        data[0x20..0x28].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_dynamic_section(&data).is_none());
    }

    #[test]
    fn huge_dt_needed_value_is_dropped_not_fatal() {
        // One DT_NEEDED entry with an out-of-range string-table offset
        // (what the real attack surface looks like: a legitimate ELF
        // with one tampered dynamic entry) must not take down parsing of
        // the rest of a perfectly normal dynamic section.
        let data = build_minimal_elf(&[(0, "libc.so.6"), (u64::MAX, "unused")]);
        let info = parse_dynamic_section(&data).expect("the rest of the file is well-formed");
        assert_eq!(info.needed, vec!["libc.so.6"], "the malformed entry should be silently dropped, not panic or poison the whole result");
    }

    #[test]
    fn huge_dyn_size_terminates_promptly() {
        let mut data = build_minimal_elf(&[(0, "libc.so.6")]);
        // PT_DYNAMIC's p_filesz, at dynhdr_off + 32.
        let dynhdr_off = 64 + 56;
        data[dynhdr_off + 32..dynhdr_off + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        // Must terminate (bounded by data.len(), not by dyn_size) and
        // must not panic computing `i + 16` against a huge dyn_size.
        let _ = parse_dynamic_section(&data);
    }
}
