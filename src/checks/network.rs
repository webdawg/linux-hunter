// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::Result;

use super::Check;
use crate::report::{Finding, Severity};

const SUSPICIOUS_EXE_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp", "/run/shm"];

/// A socket in LISTEN state, as read from /proc/net/tcp{,6}.
struct Listener {
    local_addr: String,
    inode: u64,
}

pub struct NetworkCheck;

impl Check for NetworkCheck {
    fn name(&self) -> &'static str {
        "network"
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let running_as_root = unsafe { libc::geteuid() } == 0;

        let mut listeners = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(contents) = fs::read_to_string(path) {
                listeners.extend(parse_listeners(&contents));
            }
        }

        let inode_to_pid = build_inode_to_pid_map();

        for listener in listeners {
            let owner = inode_to_pid.get(&listener.inode);

            match owner {
                None => {
                    if running_as_root {
                        findings.push(Finding::new(
                            self.name(),
                            Severity::Medium,
                            format!("listening socket {} has no identifiable owning process", listener.local_addr),
                            format!(
                                "inode {} appears in the listen table but no /proc/*/fd entry \
                                 maps to it. On a fully-enumerable system (we're running as \
                                 root) this can indicate a rootkit hiding its process while \
                                 leaving the raw socket table visible.",
                                listener.inode
                            ),
                        ));
                    }
                }
                Some(&pid) => {
                    let exe_link = format!("/proc/{pid}/exe");
                    if let Ok(exe_target) = fs::read_link(&exe_link) {
                        let exe_str = exe_target.to_string_lossy();
                        if exe_str.ends_with(" (deleted)") {
                            findings.push(Finding::new(
                                self.name(),
                                Severity::Critical,
                                format!("listening socket {} is owned by pid {pid}, whose binary was deleted after exec", listener.local_addr),
                                format!("exe: {exe_str}"),
                            ));
                        } else if let Some(dir) = SUSPICIOUS_EXE_DIRS
                            .iter()
                            .find(|d| Path::new(exe_str.as_ref()).starts_with(d))
                        {
                            findings.push(Finding::new(
                                self.name(),
                                Severity::High,
                                format!("listening socket {} is owned by pid {pid}, executing out of {dir}", listener.local_addr),
                                format!("exe: {exe_str}"),
                            ));
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}

fn parse_listeners(contents: &str) -> Vec<Listener> {
    const TCP_LISTEN: &str = "0A";

    contents
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local_addr = fields.get(1)?;
            let state = fields.get(3)?;
            let inode_field = fields.get(9)?;

            if *state != TCP_LISTEN {
                return None;
            }

            let inode = inode_field.parse::<u64>().ok()?;
            Some(Listener {
                local_addr: decode_hex_addr(local_addr),
                inode,
            })
        })
        .collect()
}

/// /proc/net/tcp encodes "ADDR:PORT" as little-endian hex, e.g. "0100007F:0050".
fn decode_hex_addr(hex_addr: &str) -> String {
    let Some((addr_hex, port_hex)) = hex_addr.split_once(':') else {
        return hex_addr.to_string();
    };
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);

    if addr_hex.len() % 2 != 0 {
        return format!("[{addr_hex}]:{port}");
    }
    let octets: Option<Vec<u8>> = (0..addr_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&addr_hex[i..i + 2], 16).ok())
        .collect();

    match octets {
        Some(mut o) if o.len() == 4 => {
            o.reverse();
            format!("{}.{}.{}.{}:{port}", o[0], o[1], o[2], o[3])
        }
        _ => format!("[{addr_hex}]:{port}"),
    }
}

fn build_inode_to_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();

    let Ok(proc_entries) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };

        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue; // not our process and we lack permission; not evidence of anything
        };

        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if let Some(inode) = parse_socket_inode(&target.to_string_lossy()) {
                    map.insert(inode, pid);
                }
            }
        }
    }

    map
}

fn parse_socket_inode(link_target: &str) -> Option<u64> {
    let inner = link_target.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse().ok()
}
