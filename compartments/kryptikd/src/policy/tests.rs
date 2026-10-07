use super::*;

#[test]
fn valid_file_adds_directives() {
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
fn denied_syscall_cannot_be_allowed() {
    for name in ["ptrace", "mount", "setns", "unshare", "bpf", "keyctl", "reboot"] {
        let err = parse(&format!("allow-syscall {name}\n"), "t").unwrap_err();
        let s = err.to_string();
        assert!(s.contains("cannot be re-allowed") && s.contains("t:1:"), "{name}: {s}");
    }
}

#[test]
fn errors_carry_line_number() {
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
fn duplicates_error_redundant_lines_warn() {
    assert!(parse("allow-socket AF_PACKET\nallow-socket AF_PACKET\n", "t").is_err());
    let p = parse("allow-syscall read\nallow-socket AF_INET\nallow-netlink NETLINK_ROUTE\nkeep-capability CAP_NET_BIND_SERVICE\n", "t").unwrap();
    assert!(p.is_empty());
    assert_eq!(p.warnings.len(), 4, "{:?}", p.warnings);
    // Any base call is known by name, so naming one warns rather than fails.
    let p = parse("allow-syscall futex\n", "t").unwrap();
    assert!(p.is_empty() && p.warnings[0].contains("futex is already allowed"), "{:?}", p.warnings);
}

#[test]
fn only_nic_zone_keeps_net_caps() {
    let z = |mode: &str| {
        crate::zone::Zone::from_str(&format!(
            "[zone]\nname = \"t\"\n[network]\nmode = \"{mode}\"\n\
                 [storage]\nmode = \"ephemeral\"\nsize = \"64M\"\n[ui]\nborder_color = \"#123456\"\n"
        ))
        .unwrap()
    };
    for cap in ["CAP_NET_ADMIN", "CAP_NET_RAW"] {
        let p = parse(&format!("keep-capability {cap}\n"), "t").unwrap();
        assert!(p.check_for_zone(&z("nic")).is_ok(), "{cap} must be allowed for the nic zone");
        let e = p.check_for_zone(&z("routed")).unwrap_err();
        assert!(e.to_string().contains("owns the NIC"), "{cap}: {e}");
        assert!(p.check_for_zone(&z("none")).is_err());
    }
    // Other keepable capabilities are not mode-restricted.
    let p = parse("keep-capability CAP_SYS_NICE\n", "t").unwrap();
    assert!(p.check_for_zone(&z("routed")).is_ok());
}

#[test]
fn af_netlink_lifts_protocol_check() {
    let p = parse("allow-socket AF_NETLINK\n", "t").unwrap();
    assert!(p.sockets.netlink_all);
    assert!(p.sockets.families.is_empty());
}

#[test]
fn resolve_relative_and_absolute() {
    assert_eq!(resolve(Path::new("/etc/kryptik/zones"), "policy/net.seccomp"), PathBuf::from("/etc/kryptik/zones/policy/net.seccomp"));
    assert_eq!(resolve(Path::new("/etc/kryptik/zones"), "/abs/p.seccomp"), PathBuf::from("/abs/p.seccomp"));
}
