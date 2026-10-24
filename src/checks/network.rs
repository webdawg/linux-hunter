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

/// A socket in LISTEN state, as read from /proc/net/tcp{,6} or
/// /proc/net/sctp/eps.
struct Listener {
    proto: &'static str,
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
                let found = parse_tcp_listeners(&contents);
                debug!(path, listeners = found.len(), "parsed listening sockets from this table");
                listeners.extend(found);
            } else {
                debug!(path, "table unreadable or absent (e.g. no IPv6 support) — skipping");
            }
        }

        // SCTP: specifically worth checking in its own right, not just for
        // completeness. It's a real, if obscure, transport -- and `netstat`
        // (deprecated since 2016, still common on older admin habits) never
        // learned to show it, which makes it an attractive channel for a
        // backdoor that wants to be invisible to a quick `netstat -tlpn`
        // glance while `ss` or a raw /proc/net/sctp read still sees it fine.
        let sctp_path = "/proc/net/sctp/eps";
        debug!(path = sctp_path, "reading raw SCTP endpoint table");
        if let Ok(contents) = fs::read_to_string(sctp_path) {
            let found = parse_sctp_listeners(&contents);
            debug!(path = sctp_path, listeners = found.len(), "parsed listening SCTP endpoints");
            listeners.extend(found);
        } else {
            debug!(path = sctp_path, "table unreadable or absent (sctp kernel module not loaded) — skipping");
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
            debug!(proto = listener.proto, addr = %listener.local_addr, inode = listener.inode, owner = ?owner, "cross-referencing listener against fd map");

            match owner {
                None => {
                    if running_as_root {
                        out.push(Finding::new(
                            self.name(),
                            Severity::Medium,
                            format!("listening {} socket {} has no identifiable owning process", listener.proto, listener.local_addr),
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
                                format!("listening {} socket {} is owned by pid {pid}, whose binary was deleted after exec", listener.proto, listener.local_addr),
                                format!("exe: {exe_str}"),
                            ));
                        } else if let Some(dir) = SUSPICIOUS_EXE_DIRS
                            .iter()
                            .find(|d| Path::new(exe_str.as_ref()).starts_with(d))
                        {
                            out.push(Finding::new(
                                self.name(),
                                Severity::High,
                                format!("listening {} socket {} is owned by pid {pid}, executing out of {dir}", listener.proto, listener.local_addr),
                                format!("exe: {exe_str}"),
                            ));
                        } else if listener.proto == "sctp" {
                            out.push(Finding::new(
                                self.name(),
                                Severity::Low,
                                format!("listening sctp socket {} is owned by pid {pid}", listener.local_addr),
                                format!(
                                    "exe: {exe_str}. SCTP is rarely used legitimately outside \
                                     telecom/signaling workloads and multipath setups, and \
                                     classic `netstat` doesn't show SCTP sockets at all -- \
                                     making it an attractive channel for a backdoor shell \
                                     counting on an admin's `netstat -tlpn` habit. Flagged at \
                                     low severity purely for visibility; confirm this process \
                                     has a legitimate reason to speak SCTP."
                                ),
                            ));
                        }
                    }
                }
            }
        }

        Ok(out)
    }
}

fn parse_tcp_listeners(contents: &str) -> Vec<Listener> {
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
                proto: "tcp",
                local_addr: decode_hex_addr(local_addr),
                inode,
            })
        })
        .collect()
}

/// Parses /proc/net/sctp/eps. Columns (kernel net/sctp/proc.c):
/// `ENDPT SOCK STY SST HBKT LPORT UID INODE LADDRS`. Unlike /proc/net/tcp,
/// SST is decimal, not hex, but reuses the same generic inet socket-state
/// numbering -- 10 is LISTEN either way. LADDRS is one or more local
/// addresses (SCTP multi-homes); we join them for display since any of
/// them is a valid way in.
fn parse_sctp_listeners(contents: &str) -> Vec<Listener> {
    const SCTP_LISTEN: &str = "10";

    contents
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let state = fields.get(3)?;
            let lport = fields.get(5)?;
            let inode_field = fields.get(7)?;

            if *state != SCTP_LISTEN {
                return None;
            }

            let addrs: Vec<&str> = fields.get(8..).map(|rest| rest.to_vec()).unwrap_or_default();
            let addr_display = if addrs.is_empty() { "*".to_string() } else { addrs.join(",") };

            let inode = inode_field.parse::<u64>().ok()?;
            Some(Listener {
                proto: "sctp",
                local_addr: format!("{addr_display}:{lport}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_listener_and_skips_established() {
        let fixture = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123456 1 0000000000000000 100 0 0 10 0\n\
             1: 0101007F:0050 0202007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 999999 1 0000000000000000 100 0 0 10 0\n";
        let listeners = parse_tcp_listeners(fixture);
        assert_eq!(listeners.len(), 1, "only the 0A (LISTEN) row should be kept, not the 01 (ESTABLISHED) row");
        assert_eq!(listeners[0].proto, "tcp");
        assert_eq!(listeners[0].local_addr, "127.0.0.1:8080");
        assert_eq!(listeners[0].inode, 123456);
    }

    #[test]
    fn parses_sctp_listener_per_kernel_field_layout() {
        // Field layout per net/sctp/proc.c sctp_eps_seq_show:
        // ENDPT SOCK STY SST HBKT LPORT UID INODE LADDRS...
        let fixture = "ENDPT     SOCK      STY SST HBKT LPORT   UID INODE LADDRS\n\
             ffff888012345678 ffff888087654321   2  10   45 12345     0 654321 127.0.0.1 10.0.0.5\n";
        let listeners = parse_sctp_listeners(fixture);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].proto, "sctp");
        assert_eq!(listeners[0].local_addr, "127.0.0.1,10.0.0.5:12345");
        assert_eq!(listeners[0].inode, 654321);
    }

    #[test]
    fn sctp_non_listen_state_is_skipped() {
        // SST=1 is ESTABLISHED, not LISTEN (10) -- must not be reported as a listener.
        let fixture = "ENDPT SOCK STY SST HBKT LPORT UID INODE LADDRS\n\
             ffff8880 ffff8881 2 1 1 12345 0 111 127.0.0.1\n";
        assert!(parse_sctp_listeners(fixture).is_empty());
    }

    #[test]
    fn decodes_hex_addr_little_endian() {
        // 0100007F little-endian = 127.0.0.1; 1F90 hex = port 8080.
        assert_eq!(decode_hex_addr("0100007F:1F90"), "127.0.0.1:8080");
    }
}
