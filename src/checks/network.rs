// SPDX-License-Identifier: AGPL-3.0-or-later
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::Result;
use tracing::debug;

use super::Check;
use crate::report::{CheckOutput, Finding, Severity};

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

    fn run(&self) -> Result<CheckOutput> {
        let mut out = CheckOutput::new();
        let running_as_root = unsafe { libc::geteuid() } == 0;
        debug!(running_as_root, "checked effective uid");

        let mut listeners = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            debug!(path, "reading raw socket table");
            if let Ok(contents) = fs::read_to_string(path) {
                let found = parse_listeners(&contents);
                debug!(path, listeners = found.len(), "parsed listening sockets from this table");
                listeners.extend(found);
            } else {
                debug!(path, "table unreadable or absent (e.g. no IPv6 support) — skipping");
            }
        }

        debug!("walking /proc/*/fd to build an inode -> pid map (view #2 of who owns each socket)");
        let (inode_to_pid, permission_denied) = build_inode_to_pid_map();
        debug!(mapped_sockets = inode_to_pid.len(), "finished building inode -> pid map");

        if !running_as_root && permission_denied > 0 {
            out.skip(format!(
                "{permission_denied} process(es)' fd tables were unreadable (permission denied) — \
                 socket-to-process mapping is incomplete; run as root for full coverage"
            ));
        }

        for listener in &listeners {
            let owner = inode_to_pid.get(&listener.inode);
            debug!(addr = %listener.local_addr, inode = listener.inode, owner = ?owner, "cross-referencing listener against fd map");

            match owner {
                None => {
                    if running_as_root {
                        out.push(Finding::new(
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
                            out.push(Finding::new(
                                self.name(),
                                Severity::Critical,
                                format!("listening socket {} is owned by pid {pid}, whose binary was deleted after exec", listener.local_addr),
                                format!("exe: {exe_str}"),
                            ));
                        } else if let Some(dir) = SUSPICIOUS_EXE_DIRS
                            .iter()
                            .find(|d| Path::new(exe_str.as_ref()).starts_with(d))
                        {
                            out.push(Finding::new(
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

        Ok(out)
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

/// Returns the inode -> pid map plus a count of pids whose fd table we could
/// not read because we lack permission (as opposed to the pid having simply
/// exited, which `fs::read_dir` also reports as an error but isn't a gap).
fn build_inode_to_pid_map() -> (HashMap<u64, u32>, usize) {
    let mut map = HashMap::new();
    let mut permission_denied = 0usize;

    let Ok(proc_entries) = fs::read_dir("/proc") else {
        return (map, permission_denied);
    };

    for entry in proc_entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };

        let fd_dir = entry.path().join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(fds) => fds,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                debug!(pid, "permission denied reading fd table — this pid's sockets are NOT mapped");
                permission_denied += 1;
                continue;
            }
            Err(_) => continue, // pid exited between readdir and now; not a gap
        };

        let mut sockets_for_pid = 0usize;
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path())
                && let Some(inode) = parse_socket_inode(&target.to_string_lossy())
            {
                debug!(pid, inode, "fd points at a socket");
                map.insert(inode, pid);
                sockets_for_pid += 1;
            }
        }
        if sockets_for_pid > 0 {
            debug!(pid, sockets = sockets_for_pid, "finished walking this pid's fd table");
        }
    }

    (map, permission_denied)
}

fn parse_socket_inode(link_target: &str) -> Option<u64> {
    let inner = link_target.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse().ok()
}
