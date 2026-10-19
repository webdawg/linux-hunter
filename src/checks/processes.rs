// SPDX-License-Identifier: AGPL-3.0-or-later
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

const SUSPICIOUS_EXE_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp", "/dev/.", "/run/shm"];

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
                }
            }
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
