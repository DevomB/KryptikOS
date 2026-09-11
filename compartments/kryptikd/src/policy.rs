//! Per-zone policy files: named, additive widenings of the base policy.
//!
//! `[policy] seccomp = "policy/net.seccomp"` used to be parsed and then
//! ignored, and a zone naming one was refused without the developer
//! override. This is what makes the file mean something.
//!
//! It is deliberately not a language. A policy file is a list of directives,
//! one per line, each naming ONE thing the zone may do beyond the shared base
//! policy (docs/design/07-zone-policy-files.md):
//!
//! ```text
//! allow-syscall    sethostname        # a syscall, by name
//! allow-socket     AF_PACKET          # a socket family
//! allow-netlink    NETLINK_NETFILTER  # a netlink protocol
//! keep-capability  CAP_NET_RAW        # a capability left in the bounding set
//! ```
//!
//! Three rules make it safe to review by reading it:
//!
//! 1. It can only ADD. Nothing in a policy file can remove a base allowance,
//!    and nothing can re-allow a syscall the base policy denies
//!    (`seccomp::DENIED_RATIONALE`): `allow-syscall ptrace` is an error, not
//!    a widening.
//! 2. Every name comes from a fixed vocabulary. An unknown syscall, family,
//!    protocol or capability is an error with a line number, never a silent
//!    no-op - a typo must not produce a zone that is quietly narrower or
//!    wider than its file says.
//! 3. Capabilities are a short allowlist of their own (`caps::KEEPABLE`):
//!    the network zone needs `CAP_NET_ADMIN` and `CAP_NET_RAW` over its own
//!    interfaces; no zone gets to keep `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`,
//!    `CAP_DAC_OVERRIDE` or the like by writing a line.
//!
//! Any error in the file refuses the launch. `kryptikd check` parses every
//! zone's file so a bad one is found before a launch, and `explain` prints
//! what the file adds.

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
    /// Lines that added nothing (already allowed by the base). Reported,
    /// not fatal: they are harmless, but the author should know.
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

/// Where a zone file's `policy.seccomp` value points: absolute as given,
/// otherwise relative to the zone directory (`--zones DIR`), so a zone set
/// and its policies move together.
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
    let mut seen: HashSet<String> = HashSet::new();

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
        if !seen.insert(format!("{directive} {arg}")) {
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
mod tests {
    use super::*;

    #[test]
    fn a_valid_file_adds_exactly_what_it_names() {
        let p = parse(
            "# comment\n\
             allow-syscall sched_setscheduler\n\
             allow-socket AF_PACKET   # raw frames for dhcp\n\
             allow-netlink NETLINK_NETFILTER\n\
             keep-capability CAP_NET_RAW\n",
            "t",
        )
        .unwrap();
        assert_eq!(p.extra_syscalls, vec![libc::SYS_sched_setscheduler]);
        assert_eq!(p.sockets.families, vec![17]);
        assert_eq!(p.sockets.netlink_protocols, vec![12]);
        assert!(!p.sockets.netlink_all);
        assert_eq!(p.keep_caps, vec![13]);
        assert!(p.warnings.is_empty());
        assert_eq!(
            p.describe(),
            "+sched_setscheduler, socket AF_PACKET, netlink NETLINK_NETFILTER, keep CAP_NET_RAW"
        );
        assert!(!p.is_empty());
        assert!(parse("", "t").unwrap().is_empty());
    }

    #[test]
    fn a_denied_syscall_cannot_be_re_allowed() {
        for name in ["ptrace", "mount", "setns", "unshare", "bpf", "keyctl", "chown"] {
            let err = parse(&format!("allow-syscall {name}\n"), "t").unwrap_err();
            let s = err.to_string();
            assert!(s.contains("cannot be re-allowed") && s.contains("t:1:"), "{name}: {s}");
        }
    }

    #[test]
    fn unknown_names_and_directives_are_errors_with_line_numbers() {
        for text in [
            "allow-syscall nosuchcall\n",
            "allow-socket AF_NOPE\n",
            "allow-netlink NETLINK_NOPE\n",
            "keep-capability CAP_NOPE\n",
            "frobnicate x\n",
            "allow-syscall\n",
            "allow-syscall a b\n",
        ] {
            let err = parse(&format!("# first line\n{text}"), "t").unwrap_err();
            assert!(err.to_string().starts_with("t:2:"), "{text:?}: {err}");
        }
    }

    #[test]
    fn dangerous_capabilities_cannot_be_kept() {
        for name in ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SYS_MODULE", "CAP_MKNOD"] {
            let err = parse(&format!("keep-capability {name}\n"), "t").unwrap_err();
            assert!(err.to_string().contains("cannot be kept"), "{name}: {err}");
        }
        let p = parse("keep-capability CAP_NET_ADMIN\n", "t").unwrap();
        assert_eq!(p.keep_caps, vec![12]);
    }

    #[test]
    fn duplicates_are_errors_and_redundant_lines_are_warnings() {
        assert!(parse("allow-socket AF_PACKET\nallow-socket AF_PACKET\n", "t").is_err());
        let p = parse("allow-syscall read\nallow-socket AF_INET\nallow-netlink NETLINK_ROUTE\nkeep-capability CAP_NET_BIND_SERVICE\n", "t").unwrap();
        assert!(p.is_empty());
        assert_eq!(p.warnings.len(), 4, "{:?}", p.warnings);
    }

    #[test]
    fn allow_socket_af_netlink_lifts_the_protocol_check() {
        let p = parse("allow-socket AF_NETLINK\n", "t").unwrap();
        assert!(p.sockets.netlink_all);
        assert!(p.sockets.families.is_empty());
    }

    #[test]
    fn relative_paths_resolve_under_the_zone_directory() {
        assert_eq!(resolve(Path::new("/etc/kryptik/zones"), "policy/net.seccomp"), PathBuf::from("/etc/kryptik/zones/policy/net.seccomp"));
        assert_eq!(resolve(Path::new("/etc/kryptik/zones"), "/abs/p.seccomp"), PathBuf::from("/abs/p.seccomp"));
    }
}
