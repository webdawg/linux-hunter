// SPDX-License-Identifier: AGPL-3.0-or-later
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

const SUSPICIOUS_EXE_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp", "/dev/.", "/run/shm"];

/// Name prefixes real Linux kernel threads use (kworker, ksoftirqd, rcu_*,
/// migration, watchdog, ...). A *real* kernel thread never reaches this
/// check at all -- it has no /proc/<pid>/exe symlink, so we bail out
/// before this point. A process that both (a) has a real exe and (b) is
/// named like one of these is specifically masquerading as one --
/// `prctl(PR_SET_NAME, "kworker/u9:1")` is a one-line call.
const KERNEL_THREAD_NAME_PREFIXES: &[&str] = &[
    "kworker/", "ksoftirqd/", "migration/", "rcu_", "watchdog/", "kswapd", "kcompactd", "kthreadd", "kdevtmpfs", "writeback", "kblockd",
    "khugepaged", "kintegrityd", "kauditd", "irq/", "cpuhp/", "ksmd",
];

pub struct ProcessCheck;

impl Check for ProcessCheck {
    fn name(&self) -> &'static str {
        "processes"
    }

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();

        debug!("reading /proc to enumerate every pid directory");
        let mut inspected = 0usize;
        let mut permission_denied = 0usize;

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(pid) = file_name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };

            let proc_dir = entry.path();
            let exe_link = proc_dir.join("exe");

            let exe_target = match fs::read_link(&exe_link) {
                Ok(target) => target,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    // We can see the pid but not its exe target: a real coverage
                    // gap, not a kernel thread. Count it rather than silently
                    // treating it the same as "no such process".
                    debug!(pid, "permission denied reading exe symlink — this pid's binary is NOT verified");
                    permission_denied += 1;
                    continue;
                }
                Err(_) => {
                    // Kernel threads and processes that have already exited
                    // have no exe symlink at all; that's normal.
                    debug!(pid, "no exe symlink (kernel thread or already exited) — skipping");
                    continue;
                }
            };
            let exe_str = exe_target.to_string_lossy();
            inspected += 1;
            debug!(pid, exe = %exe_str, "resolved exe symlink");

            if exe_str.ends_with(" (deleted)") {
                out.push(Finding::new(
                    self.name(),
                    Severity::High,
                    format!("pid {pid} is running from a binary deleted off disk"),
                    format!(
                        "exe symlink: {exe_str}. This is a common sign of a dropped malware \
                         binary that deleted itself after exec to dodge on-disk scanning. \
                         Inspect with: cat /proc/{pid}/cmdline; ls -l /proc/{pid}/exe"
                    ),
                ));
                continue;
            }

            if let Some(dir) = SUSPICIOUS_EXE_DIRS
                .iter()
                .find(|d| Path::new(exe_str.as_ref()).starts_with(d))
            {
                out.push(Finding::new(
                    self.name(),
                    Severity::Medium,
                    format!("pid {pid} is executing out of {dir}"),
                    format!(
                        "exe: {exe_str}. World-writable scratch directories are a common \
                         staging ground for dropped payloads."
                    ),
                ));
            }

            if let Ok(comm) = fs::read_to_string(proc_dir.join("comm")) {
                let comm = comm.trim_end();
                debug!(pid, comm, "read comm");
                if let Some(prefix) = KERNEL_THREAD_NAME_PREFIXES.iter().find(|p| comm.starts_with(**p)) {
                    out.push(Finding::new(
                        self.name(),
                        Severity::High,
                        format!("pid {pid} is named \"{comm}\" (matches kernel-thread prefix \"{prefix}\") but has a real exe"),
                        format!(
                            "exe: {exe_str}. Genuine kernel threads have no /proc/{pid}/exe at \
                             all (we already filtered those out before reaching this check). A \
                             userspace process can set this name with a single \
                             prctl(PR_SET_NAME) call specifically to blend into a `ps`/`top` \
                             listing full of real kworker/ksoftirqd/migration threads."
                        ),
                    ));
                }
            }

            let cmdline_path = proc_dir.join("cmdline");
            if let Ok(cmdline) = fs::read(&cmdline_path) {
                debug!(pid, cmdline_bytes = cmdline.len(), "read cmdline");
                if cmdline.is_empty() {
                    out.push(Finding::new(
                        self.name(),
                        Severity::Low,
                        format!("pid {pid} has an empty cmdline"),
                        format!(
                            "exe: {exe_str}. A running process with no argv is unusual outside \
                             of kernel threads (which have no /proc/{pid}/exe at all) and can \
                             indicate argv was zeroed to hide the process's purpose."
                        ),
                    ));
                } else if cmdline.iter().all(|&b| b == 0) {
                    out.push(Finding::new(
                        self.name(),
                        Severity::High,
                        format!("pid {pid} has a non-empty cmdline that is entirely null bytes"),
                        format!(
                            "exe: {exe_str}, cmdline length {} bytes, all zero. This is a much \
                             stronger signal than a simply-empty cmdline: the kernel recorded a \
                             real argv length at exec time, and something has since \
                             deliberately overwritten every byte of it in place (e.g. looping \
                             over sys.argv and assigning '\\0' * len(arg)) -- a direct attempt \
                             to hide the command line from `ps`/`cat /proc/{pid}/cmdline` after \
                             the fact.",
                            cmdline.len()
                        ),
                    ));
                }
            }

            check_rwx_mappings(self.name(), pid, &exe_str, &proc_dir, &mut out);
        }

        if permission_denied > 0 {
            out.skip(format!(
                "{permission_denied} process(es) had an unreadable /proc/<pid>/exe (permission denied) — \
                 their binaries were not verified; run as root for full coverage"
            ));
        }

        debug!(inspected, permission_denied, "finished process check");
        Ok(out)
    }
}

/// Flags purely anonymous (no backing file, no `[heap]`/`[stack]`-style
/// label) memory regions mapped both writable and executable at once --
/// exactly the shape of a reflective shellcode loader: decode a payload,
/// `mmap(MAP_ANONYMOUS, PROT_WRITE|PROT_EXEC)`, write it in, jump to it.
/// Legitimate JITs generally avoid simultaneous W+X (W^X) for this exact
/// reason, so this has a low false-positive rate for a from-scratch check.
fn check_rwx_mappings(check_name: &'static str, pid: u32, exe_str: &str, proc_dir: &Path, out: &mut CheckOutput) {
    let Ok(maps) = fs::read_to_string(proc_dir.join("maps")) else {
        return;
    };

    for line in maps.lines() {
        // Fields are whitespace-padded for alignment (the pathname column
        // in particular), so split_whitespace (which collapses runs of
        // whitespace) rather than a fixed single-space split.
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(perms) = fields.get(1) else { continue };
        if !perms.contains('w') || !perms.contains('x') {
            continue;
        }

        // Anything after the 5th field (inode) is the pathname, possibly
        // absent for a plain anonymous mapping, or a bracketed label like
        // [heap]/[stack]/[vdso] for one the kernel names itself. We only
        // want the fully-unnamed case.
        let pathname = fields.get(5).map(|s| s.trim()).unwrap_or("");
        if !pathname.is_empty() {
            continue;
        }

        let address = fields.first().copied().unwrap_or("?");
        debug!(pid, address, perms = *perms, "found anonymous writable+executable mapping");
        out.push(Finding::new(
            check_name,
            Severity::Medium,
            format!("pid {pid} has an anonymous memory region mapped both writable and executable"),
            format!(
                "exe: {exe_str}, region {address}, perms {perms}. No backing file and no \
                 kernel-assigned label ([heap]/[stack]/[vdso]/...) means this memory didn't \
                 come from loading a file or the normal process layout. This is *also* exactly \
                 what libffi closure trampolines look like (ubiquitous in GObject-Introspection \
                 / GTK / Python ctypes-using apps -- typically a tiny single page with zero RSS \
                 until first use) and what some JIT engines produce, so it's common enough on a \
                 desktop to not be conclusive by itself. It is also the shape a reflective \
                 shellcode loader leaves behind (decode a payload into an anonymous mmap, mark \
                 it PROT_EXEC, call it) -- worth a second look with `/proc/{pid}/smaps` \
                 (size and Rss) on a server where libffi/JIT workloads aren't expected."
            ),
        ));
    }
}
