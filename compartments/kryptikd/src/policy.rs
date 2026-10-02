//! Per-zone policy files (docs/design/zone-policy-files.md). Each line adds one thing to the
//! base policy: `allow-syscall NAME`, `allow-socket AF_X`, `allow-netlink NETLINK_X` or
//! `keep-capability CAP_X`. A denied syscall stays denied and capabilities come only from
//! `caps::KEEPABLE`; an unknown name is an error with its line, and any error refuses the launch.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::caps;
use crate::seccomp;

/// What a policy file adds to the base policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// The path the file was read from, for messages.
    pub source: String,
    pub extra_syscalls: Vec<libc::c_long>,
    pub extra_syscall_names: Vec<String>,
    pub sockets: seccomp::SocketPolicy,
    pub socket_names: Vec<String>,
    pub netlink_names: Vec<String>,
    pub keep_caps: Vec<libc::c_int>,
    pub keep_cap_names: Vec<String>,
    /// Lines the base policy already allows; reported, not fatal.
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum PolicyError {
    Io { path: String, err: String },
    Line { path: String, line: usize, msg: String },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Io { path, err } => write!(f, "{path}: {err}"),
            PolicyError::Line { path, line, msg } => write!(f, "{path}:{line}: {msg}"),
        }
    }
}

/// Resolves `policy.seccomp`: absolute as given, otherwise under the zone directory.
pub fn resolve(zones_dir: &Path, given: &str) -> PathBuf {
    let p = Path::new(given);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        zones_dir.join(p)
    }
}

pub fn load(path: &Path) -> Result<Policy, PolicyError> {
    let text = fs::read_to_string(path).map_err(|e| PolicyError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    })?;
    parse(&text, &path.display().to_string())
}

pub fn parse(text: &str, source: &str) -> Result<Policy, PolicyError> {
    let mut p = Policy { source: source.to_string(), ..Default::default() };
    let mut seen: HashSet<(&str, &str)> = HashSet::new();

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let err = |msg: String| PolicyError::Line { path: source.to_string(), line: lineno, msg };

        let mut it = line.split_whitespace();
        let directive = it.next().unwrap_or("");
        let Some(arg) = it.next() else {
            return Err(err(format!("{directive}: expected exactly one argument")));
        };
        if it.next().is_some() {
            return Err(err(format!("{directive}: expected exactly one argument")));
        }
        if !seen.insert((directive, arg)) {
            return Err(err(format!("duplicate directive {directive} {arg}")));
        }

        match directive {
            "allow-syscall" => {
                let nr = seccomp::syscall_by_name(arg)
                    .ok_or_else(|| err(format!("unknown syscall name {arg:?}")))?;
                if seccomp::is_denied(nr) {
                    return Err(err(format!(
                        "{arg} is denied by the base policy and cannot be re-allowed by a zone policy"
                    )));
                }
                if seccomp::BASE_ALLOWLIST.contains(&nr) {
                    p.warnings.push(format!("{source}:{lineno}: {arg} is already allowed by the base policy"));
                    continue;
                }
                p.extra_syscalls.push(nr);
                p.extra_syscall_names.push(arg.to_string());
            }
            "allow-socket" => {
                let fam = seccomp::socket_family_by_name(arg).ok_or_else(|| {
                    err(format!(
                        "unknown socket family {arg:?} (expected one of {})",
                        seccomp::SOCKET_FAMILY_NAMES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                    ))
                })?;
                if fam == seccomp::AF_NETLINK {
                    p.sockets.netlink_all = true;
                } else if seccomp::BASE_SOCKET_FAMILIES.contains(&fam) {
                    p.warnings.push(format!("{source}:{lineno}: {arg} is already allowed by the base policy"));
                    continue;
                } else {
                    p.sockets.families.push(fam);
                }
                p.socket_names.push(arg.to_string());
            }
            "allow-netlink" => {
                let proto = seccomp::netlink_protocol_by_name(arg).ok_or_else(|| {
                    err(format!(
                        "unknown netlink protocol {arg:?} (expected one of {})",
                        seccomp::NETLINK_PROTOCOL_NAMES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                    ))
                })?;
                if proto == seccomp::NETLINK_ROUTE {
                    p.warnings.push(format!("{source}:{lineno}: {arg} is already allowed by the base policy"));
                    continue;
                }
                p.sockets.netlink_protocols.push(proto);
                p.netlink_names.push(arg.to_string());
            }
            "keep-capability" => {
                let c = caps::cap_by_name(arg)
                    .ok_or_else(|| err(format!("unknown capability {arg:?}")))?;
                if !caps::KEEPABLE.contains(&c) {
                    return Err(err(format!(
                        "{arg} cannot be kept by a zone policy (keepable: {})",
                        caps::KEEPABLE.iter().map(|c| caps::cap_name(*c)).collect::<Vec<_>>().join(", ")
                    )));
                }
                if c == caps::KEEP {
                    p.warnings.push(format!("{source}:{lineno}: {arg} is kept by every zone already"));
                    continue;
                }
                p.keep_caps.push(c);
                p.keep_cap_names.push(arg.to_string());
            }
            other => {
                return Err(err(format!(
                    "unknown directive {other:?} (expected allow-syscall, allow-socket, allow-netlink or keep-capability)"
                )))
            }
        }
    }
    Ok(p)
}

impl Policy {
    /// Only the nic zone may keep `CAP_NET_ADMIN` or `CAP_NET_RAW`; elsewhere they let a zone
    /// re-address its veth, route around port isolation via the bridge address, or forge frames.
    pub fn check_for_zone(&self, zone: &crate::zone::Zone) -> Result<(), PolicyError> {
        if zone.network != crate::zone::NetworkMode::Nic {
            for (c, name) in self.keep_caps.iter().zip(&self.keep_cap_names) {
                if caps::NIC_ONLY.contains(c) {
                    return Err(PolicyError::Line {
                        path: self.source.clone(),
                        line: 0,
                        msg: format!(
                            "{name} may be kept only by the zone that owns the NIC \
                             (network.mode = \"nic\"); zone {:?} is {:?}",
                            zone.name, zone.network
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.extra_syscalls.is_empty()
            && self.sockets == seccomp::SocketPolicy::default()
            && self.keep_caps.is_empty()
    }

    /// One line for `explain` and `check`: what this file adds.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for n in &self.extra_syscall_names {
            parts.push(format!("+{n}"));
        }
        for n in &self.socket_names {
            parts.push(format!("socket {n}"));
        }
        for n in &self.netlink_names {
            parts.push(format!("netlink {n}"));
        }
        for n in &self.keep_cap_names {
            parts.push(format!("keep {n}"));
        }
        if parts.is_empty() {
            "no additions".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
mod tests;
