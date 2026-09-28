use super::*;

#[test]
fn keeps_only_net_bind_service() {
    assert_eq!(KEEP, 10);
    assert_eq!(1u64 << KEEP, 0x400);
}

#[test]
fn keep_is_not_dangerous() {
    for dangerous in [
        cap::SYS_ADMIN,
        cap::NET_ADMIN,
        cap::NET_RAW,
        cap::SYS_MODULE,
        cap::SYS_PTRACE,
        cap::DAC_OVERRIDE,
        cap::SETUID,
        cap::SETGID,
        cap::MKNOD,
    ] {
        assert_ne!(KEEP, dangerous, "capability {dangerous} must not be kept");
    }
}

#[test]
fn last_cap_is_sane() {
    let n = last_cap();
    assert!(n >= cap::SYS_ADMIN, "cap_last_cap {n} is implausibly low");
    assert!(n <= 63, "cap_last_cap {n} is out of range for a u64 mask");
}
