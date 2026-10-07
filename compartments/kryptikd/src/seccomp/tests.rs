use super::*;
use std::collections::HashSet;

#[test]
fn program_has_expected_shape() {
    let p = build_program(&[libc::SYS_read, libc::SYS_write]).unwrap();
    // 4 prologue + 2 x32 + 2 per soft refusal + 2 per syscall (no arg rules) + 1 deny
    assert_eq!(p.len(), 3 + 1 + 2 + 2 * REFUSED_SOFTLY.len() + 4 + 1);
    assert_eq!(p[0].code, BPF_LD | BPF_W | BPF_ABS);
    assert_eq!(p[0].k, OFF_ARCH);
    let last = p.last().unwrap();
    assert_eq!(last.code, BPF_RET | BPF_K);
    assert_eq!(last.k, SECCOMP_RET_KILL_PROCESS, "filter must default-deny");
}

#[test]
fn jump_offsets_stay_small() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    // Arg-rule offsets reach 9, the rest are 0 or 1; all must land inside.
    for (i, ins) in p.iter().enumerate() {
        assert!(ins.jt <= 9, "instruction {i} has jt={}", ins.jt);
        assert!(ins.jf <= 9, "instruction {i} has jf={}", ins.jf);
        if ins.code & 0x07 == BPF_JMP {
            assert!((i + 1 + ins.jt as usize) < p.len(), "instruction {i} jt runs off the end");
            assert!((i + 1 + ins.jf as usize) < p.len(), "instruction {i} jf runs off the end");
        }
    }
}

#[test]
fn program_fits_kernel_limit() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    assert!(p.len() <= 4096, "program is {} instructions", p.len());
}

#[test]
fn arch_checked_before_syscall_number() {
    // Else a foreign architecture's number could match a different syscall.
    let p = build_program(&[libc::SYS_read]).unwrap();
    assert_eq!(p[0].k, OFF_ARCH, "arch must be loaded first");
    assert!(p.iter().take(3).any(|i| i.k == AUDIT_ARCH_X86_64));
}

/// Interprets what `build_program` emits, so tests check what the filter does, not its constants.
fn evaluate(prog: &[SockFilter], arch: u32, nr: u32) -> u32 {
    evaluate_args(prog, arch, nr, [0; 6])
}

fn evaluate_args(prog: &[SockFilter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
    let mut pc = 0usize;
    let mut acc: u32 = 0;
    loop {
        let ins = prog[pc];
        match ins.code {
            c if c == BPF_LD | BPF_W | BPF_ABS => {
                acc = match ins.k {
                    OFF_ARCH => arch,
                    OFF_NR => nr,
                    k if (16..64).contains(&k) && (k - 16) % 8 == 0 => {
                        args[((k - 16) / 8) as usize] as u32
                    }
                    k if (16..64).contains(&k) && (k - 16) % 8 == 4 => {
                        (args[((k - 16) / 8) as usize] >> 32) as u32
                    }
                    other => panic!("unexpected load offset {other}"),
                };
                pc += 1;
            }
            c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                pc += 1 + if acc == ins.k { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JGE | BPF_K => {
                pc += 1 + if acc >= ins.k { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_JMP | BPF_JSET | BPF_K => {
                pc += 1 + if acc & ins.k != 0 { ins.jt as usize } else { ins.jf as usize };
            }
            c if c == BPF_RET | BPF_K => return ins.k,
            other => panic!("unexpected opcode {other:#x}"),
        }
        assert!(pc < prog.len(), "program ran off the end without returning");
    }
}

#[test]
fn interpreter_allows_permitted_syscalls() {
    let p = build_program(&[libc::SYS_read, libc::SYS_write]).unwrap();
    for nr in [libc::SYS_read, libc::SYS_write] {
        assert_eq!(
            evaluate(&p, AUDIT_ARCH_X86_64, nr as u32),
            SECCOMP_RET_ALLOW,
            "syscall {nr} should be allowed"
        );
    }
}

#[test]
fn interpreter_kills_unlisted_syscalls() {
    let p = build_program(&[libc::SYS_read]).unwrap();
    assert_eq!(
        evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_ptrace as u32),
        SECCOMP_RET_KILL_PROCESS
    );
}

#[test]
fn arg_rules_follow_the_list() {
    // A rule allows on some path, so it exists only for a listed syscall.
    let p = build_program(&[libc::SYS_read]).unwrap();
    for nr in ARG_RULES.iter().map(|r| r.nr()) {
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, nr as u32), SECCOMP_RET_KILL_PROCESS, "syscall {nr} is not on the list");
    }
    let p = build_program(&[libc::SYS_read, libc::SYS_clone3]).unwrap();
    assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_clone3 as u32), errno_action(ENOSYS));
}

#[test]
fn inotify_refused_softly() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for nr in [libc::SYS_inotify_init, libc::SYS_inotify_init1] {
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, nr as u32), errno_action(ENOSYS));
    }
    let mut allow = BASE_ALLOWLIST.to_vec();
    allow.push(libc::SYS_inotify_init1);
    let p = build_program(&allow).unwrap();
    assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_inotify_init1 as u32), SECCOMP_RET_ALLOW, "a policy opens it");
}

#[test]
fn id_changes_fail_not_kill() {
    // Denied all the same: no policy may allow them.
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for nr in [
        libc::SYS_setfsuid, libc::SYS_setfsgid, libc::SYS_setuid, libc::SYS_setgid,
        libc::SYS_setreuid, libc::SYS_setregid, libc::SYS_setresuid, libc::SYS_setresgid,
        libc::SYS_setgroups, libc::SYS_capset,
    ] {
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, nr as u32), errno_action(EPERM), "syscall {nr}");
        assert!(is_denied(nr));
    }
}

#[test]
fn trace_names_soft_refusals() {
    // clone3 keeps its errno: no policy opens it, so naming it would mislead.
    let p = build_program_with(BASE_ALLOWLIST, libc::SECCOMP_RET_USER_NOTIF).unwrap();
    assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_inotify_init1 as u32), libc::SECCOMP_RET_USER_NOTIF);
    assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, libc::SYS_clone3 as u32), errno_action(ENOSYS));
}

#[test]
fn interpreter_kills_foreign_arch() {
    let p = build_program(&[libc::SYS_read]).unwrap();
    // i386 would otherwise match on a syscall number meaning something else.
    assert_eq!(evaluate(&p, 0x4000_0003, libc::SYS_read as u32), SECCOMP_RET_KILL_PROCESS);
}

#[test]
fn every_x32_syscall_is_killed() {
    // A spread of numbers: an == guard would catch only the first.
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for offset in [0u32, 1, 2, 60, 101, 257, 1000] {
        let x32_nr = X32_SYSCALL_BIT | offset;
        assert_eq!(
            evaluate(&p, AUDIT_ARCH_X86_64, x32_nr),
            SECCOMP_RET_KILL_PROCESS,
            "x32 syscall {x32_nr:#x} (x86-64 nr {offset}) was not killed"
        );
    }
}

#[test]
fn x32_guard_is_range_comparison() {
    // == matches one value; the guard must cover every x32 number.
    let p = build_program(&[libc::SYS_read]).unwrap();
    let guard = p
        .iter()
        .find(|i| i.k == X32_SYSCALL_BIT)
        .expect("no x32 guard in the program");
    assert_eq!(
        guard.code,
        BPF_JMP | BPF_JGE | BPF_K,
        "x32 guard must be a >= comparison, not =="
    );
}

#[test]
fn whole_allowlist_evaluates_correctly() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for &nr in BASE_ALLOWLIST {
        let r = evaluate(&p, AUDIT_ARCH_X86_64, nr as u32);
        // With zero arguments clone3 gets ENOSYS and family 0 is refused; nothing listed is killed.
        assert_ne!(r, SECCOMP_RET_KILL_PROCESS, "allowlisted syscall {nr} was killed");
        if ![libc::SYS_clone3, libc::SYS_socket, libc::SYS_socketpair].contains(&nr) {
            assert_eq!(r, SECCOMP_RET_ALLOW, "allowlisted syscall {nr} was not allowed");
        }
    }
    for (nr, why) in DENIED_RATIONALE {
        let want = REFUSED_SOFTLY.iter().find(|(n, _)| n == nr).map_or(SECCOMP_RET_KILL_PROCESS, |&(_, e)| errno_action(e));
        assert_eq!(evaluate(&p, AUDIT_ARCH_X86_64, *nr as u32), want, "denied syscall {nr} ({why}) was not refused");
    }
}

#[test]
fn denied_list_not_in_allowlist() {
    let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
    for (nr, why) in DENIED_RATIONALE {
        assert!(
            !allowed.contains(nr),
            "syscall {nr} is in BASE_ALLOWLIST but documented as denied: {why}"
        );
    }
}

#[test]
fn out_of_range_numbers_refused() {
    // Truncated to 32 bits this is 1, SYS_write.
    let bogus: libc::c_long = 0x1_0000_0001;
    assert!(build_program(&[bogus]).is_err());
    assert!(build_program(&[-1]).is_err());
}

#[test]
fn allowlist_has_no_duplicates() {
    let mut seen = HashSet::new();
    for nr in BASE_ALLOWLIST {
        assert!(seen.insert(*nr), "duplicate syscall {nr} in allowlist");
    }
}

#[test]
fn essential_syscalls_are_permitted() {
    let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
    for nr in [
        libc::SYS_read, libc::SYS_write, libc::SYS_exit_group,
        libc::SYS_mmap, libc::SYS_munmap, libc::SYS_rt_sigreturn,
        libc::SYS_execve, libc::SYS_futex, libc::SYS_brk,
    ] {
        assert!(allowed.contains(&nr), "essential syscall {nr} is not allowed");
    }
}

// --- argument rules -----------------------------------------------------

const X86: u32 = AUDIT_ARCH_X86_64;

fn with_arg(i: usize, v: u64) -> [u64; 6] {
    let mut a = [0u64; 6];
    a[i] = v;
    a
}

#[test]
fn plain_clone_allowed() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    // What pthread_create and fork() pass.
    let thread = 0x3d0f00u64; // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID
    let fork = 0x1200011u64; // CHILD_SETTID|CHILD_CLEARTID|SIGCHLD
    for f in [thread, fork, 17] {
        assert_eq!(
            evaluate_args(&p, X86, libc::SYS_clone as u32, with_arg(0, f)),
            SECCOMP_RET_ALLOW,
            "clone flags {f:#x} should be allowed"
        );
    }
}

#[test]
fn namespace_clone_fails_with_eperm() {
    // As unshare(2) does: a program probing for user namespaces lives on.
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for f in [
        libc::CLONE_NEWUSER, libc::CLONE_NEWNS, libc::CLONE_NEWPID,
        libc::CLONE_NEWNET, libc::CLONE_NEWIPC, libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ] {
        let flags = (f as u32 | libc::SIGCHLD as u32) as u64;
        assert_eq!(
            evaluate_args(&p, X86, libc::SYS_clone as u32, with_arg(0, flags)),
            errno_action(EPERM),
            "clone flags {flags:#x} must fail with EPERM"
        );
        // Legacy clone ignores the high word, and so does the filter.
        assert_eq!(
            evaluate_args(&p, X86, libc::SYS_clone as u32, with_arg(0, flags | (1 << 40))),
            errno_action(EPERM)
        );
    }
}

#[test]
fn unshare_fails_setns_killed() {
    // Both stay on the denied list: no policy may allow either.
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for f in [0, libc::CLONE_NEWUSER as u64, CLONE_NS_MASK as u64] {
        let r = evaluate_args(&p, X86, libc::SYS_unshare as u32, with_arg(0, f));
        assert_eq!(r, errno_action(EPERM), "unshare flags {f:#x}");
    }
    let r = evaluate_args(&p, X86, libc::SYS_setns as u32, with_arg(1, libc::CLONE_NEWUSER as u64));
    assert_eq!(r, SECCOMP_RET_KILL_PROCESS);
    for nr in [libc::SYS_unshare, libc::SYS_setns] {
        assert!(is_denied(nr) && widened(&[nr]).is_err(), "syscall {nr} can be allowed");
    }
}

#[test]
fn trace_names_namespace_refusals() {
    // Named like any soft refusal, while a plain clone runs.
    let p = build_program_with(BASE_ALLOWLIST, libc::SECCOMP_RET_USER_NOTIF).unwrap();
    let ns = with_arg(0, (libc::CLONE_NEWUSER | libc::SIGCHLD) as u64);
    assert_eq!(evaluate_args(&p, X86, libc::SYS_clone as u32, ns), libc::SECCOMP_RET_USER_NOTIF);
    assert_eq!(evaluate_args(&p, X86, libc::SYS_unshare as u32, ns), libc::SECCOMP_RET_USER_NOTIF);
    let fork = with_arg(0, libc::SIGCHLD as u64);
    assert_eq!(evaluate_args(&p, X86, libc::SYS_clone as u32, fork), SECCOMP_RET_ALLOW);
}

#[test]
fn trace_answers_as_a_zone() {
    /* seccomp-trace hears of every call the zone filter refuses, and answers
     * each as a zone hears it: a soft refusal's errno, or ENOSYS where a zone
     * is killed. */
    let zone = build_program(BASE_ALLOWLIST).unwrap();
    let trace = build_program_with(BASE_ALLOWLIST, libc::SECCOMP_RET_USER_NOTIF).unwrap();
    let ns = with_arg(0, (libc::CLONE_NEWUSER | libc::SIGCHLD) as u64);
    let mut calls: Vec<(libc::c_long, [u64; 6])> = DENIED_RATIONALE
        .iter()
        .map(|&(nr, _)| nr)
        .chain(REFUSED_SOFTLY.iter().map(|&(nr, _)| nr))
        .map(|nr| (nr, [0; 6]))
        .collect();
    calls.extend([(libc::SYS_clone, ns), (libc::SYS_unshare, ns), (libc::SYS_ioctl, with_arg(1, TIOCSTI as u64))]);
    for (nr, args) in calls {
        assert_eq!(evaluate_args(&trace, X86, nr as u32, args), libc::SECCOMP_RET_USER_NOTIF, "syscall {nr} is not named");
        let call = libc::seccomp_data { nr: nr as i32, arch: X86, instruction_pointer: 0, args };
        let heard = soft_errno(&call).map_or(SECCOMP_RET_KILL_PROCESS, errno_action);
        assert_eq!(evaluate_args(&zone, X86, nr as u32, args), heard, "syscall {nr}");
    }
    // Another architecture is killed in a zone whatever the number.
    let i386 = libc::seccomp_data { nr: libc::SYS_unshare as i32, arch: 0x4000_0003, instruction_pointer: 0, args: ns };
    assert_eq!(soft_errno(&i386), None);
}

#[test]
fn clone3_gets_enosys() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    let r = evaluate_args(&p, X86, libc::SYS_clone3 as u32, [0; 6]);
    assert_eq!(r & 0xffff_0000, SECCOMP_RET_ERRNO);
    assert_eq!(r & 0xffff, ENOSYS);
}

#[test]
fn tty_injection_ioctls_are_killed() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for cmd in [TIOCSTI, TIOCLINUX] {
        assert_eq!(
            evaluate_args(&p, X86, libc::SYS_ioctl as u32, with_arg(1, cmd as u64)),
            SECCOMP_RET_KILL_PROCESS,
            "ioctl {cmd:#x} must be killed"
        );
    }
    // The kernel reads cmd as 32 bits, so high-word junk must not hide TIOCSTI.
    assert_eq!(
        evaluate_args(&p, X86, libc::SYS_ioctl as u32, with_arg(1, (1u64 << 40) | TIOCSTI as u64)),
        SECCOMP_RET_KILL_PROCESS
    );
    for cmd in [libc::TCGETS, libc::TIOCGWINSZ, libc::FIONREAD, libc::FIOCLEX] {
        assert_eq!(
            evaluate_args(&p, X86, libc::SYS_ioctl as u32, with_arg(1, cmd as u64)),
            SECCOMP_RET_ALLOW,
            "ioctl {cmd:#x} should be allowed"
        );
    }
}

#[test]
fn socket_families_are_limited() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    for fam in [AF_UNIX, AF_INET, AF_INET6] {
        assert_eq!(
            evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, fam as u64)),
            SECCOMP_RET_ALLOW,
            "family {fam} should be allowed"
        );
    }
    // netlink: only NETLINK_ROUTE
    let mut a = [0u64; 6];
    a[0] = AF_NETLINK as u64;
    a[2] = NETLINK_ROUTE as u64;
    assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, a), SECCOMP_RET_ALLOW);
    a[2] = 12; // NETLINK_NETFILTER
    let r = evaluate_args(&p, X86, libc::SYS_socket as u32, a);
    assert_eq!(r, errno_action(EAFNOSUPPORT), "NETLINK_NETFILTER must be refused");
    for fam in [40u32 /* VSOCK */, 38 /* ALG */, 17 /* PACKET */, 15 /* KEY */, 21 /* RDS */, 30 /* TIPC */, 44 /* XDP */] {
        let r = evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, fam as u64));
        assert_eq!(r, errno_action(EAFNOSUPPORT), "family {fam} must be refused");
    }
}

#[test]
fn socketpair_unix_only() {
    let p = build_program(BASE_ALLOWLIST).unwrap();
    assert_eq!(evaluate_args(&p, X86, libc::SYS_socketpair as u32, with_arg(0, AF_UNIX as u64)), SECCOMP_RET_ALLOW);
    for fam in [AF_INET, AF_INET6, AF_NETLINK, 17 /* PACKET */, 30 /* TIPC */, 40 /* VSOCK */] {
        let r = evaluate_args(&p, X86, libc::SYS_socketpair as u32, with_arg(0, fam as u64));
        assert_eq!(r, errno_action(EAFNOSUPPORT), "family {fam} must be refused");
    }
    // A policy's families widen socket(2), not this.
    let sp = SocketPolicy { families: vec![17], netlink_protocols: vec![], netlink_all: true };
    let p = build_program_full(BASE_ALLOWLIST, SECCOMP_RET_KILL_PROCESS, &sp).unwrap();
    assert_eq!(evaluate_args(&p, X86, libc::SYS_socketpair as u32, with_arg(0, 17)), errno_action(EAFNOSUPPORT));
}

#[test]
fn tsync_failure_is_error() {
    /* TSYNC fails on a thread with a filter of its own: the kernel returns its id and attaches
     * nothing. Run in a forked child, which exits while that thread still waits. */
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let own = install_with(BASE_ALLOWLIST, SECCOMP_RET_KILL_PROCESS, &SocketPolicy::default(), 0);
            let _ = tx.send(own.is_ok());
            loop {
                std::thread::park();
            }
        });
        let rc = match rx.recv() {
            Ok(true) => match install(BASE_ALLOWLIST) {
                Err(SeccompError::Unsynced(_)) => 0,
                Ok(()) => 1,
                Err(_) => 3,
            },
            _ => 2,
        };
        unsafe { libc::_exit(rc) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status), "child died: status {status:#x}");
    match libc::WEXITSTATUS(status) {
        0 => {}
        1 => panic!("a filter that reached no thread was reported as installed"),
        2 => panic!("the thread could not install a filter of its own"),
        other => panic!("install failed some other way ({other})"),
    }
}

#[test]
fn arg_rules_leave_allowlist_alone() {
    // A skipped rule block must leave the syscall number loaded; these arguments trip any rule.
    let p = build_program(BASE_ALLOWLIST).unwrap();
    let args = [CLONE_NS_MASK as u64, TIOCSTI as u64, 40, 7, 1 << 33, 9];
    for &nr in BASE_ALLOWLIST {
        if ARG_RULES.iter().any(|r| r.nr() == nr) {
            continue;
        }
        assert_eq!(
            evaluate_args(&p, X86, nr as u32, args),
            SECCOMP_RET_ALLOW,
            "syscall {nr} was affected by an argument rule"
        );
    }
}

#[test]
fn widened_refuses_denied() {
    let e = widened(&[libc::SYS_ptrace]).unwrap_err();
    assert!(matches!(e, SeccompError::Denied(libc::SYS_ptrace)) && e.to_string().contains("ptrace"), "{e}");
    let w = widened(&[libc::SYS_sched_setscheduler, libc::SYS_read]).unwrap();
    assert_eq!(w.len(), BASE_ALLOWLIST.len() + 1, "a base call is not added twice");
    assert!(w.contains(&libc::SYS_sched_setscheduler));
}

#[test]
fn everyday_calls_allowed() {
    // tar, gzip, cp -a, rsync, install, asyncio, timeout, mmap.flush and chrt -p need these.
    let allowed: HashSet<libc::c_long> = BASE_ALLOWLIST.iter().copied().collect();
    for nr in [
        libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat, libc::SYS_fchmodat2,
        libc::SYS_chown, libc::SYS_fchown, libc::SYS_fchownat, libc::SYS_lchown,
        libc::SYS_setxattr, libc::SYS_lsetxattr, libc::SYS_fsetxattr,
        libc::SYS_removexattr, libc::SYS_lremovexattr, libc::SYS_fremovexattr,
        libc::SYS_pidfd_open, libc::SYS_pidfd_send_signal,
        libc::SYS_timer_create, libc::SYS_timer_settime, libc::SYS_timer_gettime,
        libc::SYS_timer_getoverrun, libc::SYS_timer_delete,
        libc::SYS_msync, libc::SYS_sched_getattr, libc::SYS_ioprio_get,
    ] {
        assert!(allowed.contains(&nr), "syscall {nr} must be allowed");
    }
}

// --- zone policy widenings ---------------------------------------------

#[test]
fn socket_policy_extras() {
    let sp = SocketPolicy { families: vec![17], netlink_protocols: vec![12], netlink_all: false };
    let p = build_program_full(BASE_ALLOWLIST, SECCOMP_RET_KILL_PROCESS, &sp).unwrap();
    for fam in [AF_UNIX, AF_INET, AF_INET6] {
        assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, fam as u64)), SECCOMP_RET_ALLOW, "{fam}");
    }
    assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, 17)), SECCOMP_RET_ALLOW);
    assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, 40)), errno_action(EAFNOSUPPORT));
    // NETLINK_ROUTE and the extra protocol pass, another does not.
    let mut a = [0u64; 6];
    a[0] = AF_NETLINK as u64;
    for (proto, want) in [(0u64, SECCOMP_RET_ALLOW), (12, SECCOMP_RET_ALLOW), (9, errno_action(EAFNOSUPPORT))] {
        a[2] = proto;
        assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, a), want, "netlink proto {proto}");
    }
    // The rest of the program is unchanged.
    assert_eq!(evaluate_args(&p, X86, libc::SYS_ptrace as u32, [0; 6]), SECCOMP_RET_KILL_PROCESS);
    assert_eq!(evaluate_args(&p, X86, libc::SYS_read as u32, [0; 6]), SECCOMP_RET_ALLOW);
    for (i, ins) in p.iter().enumerate() {
        if ins.code & 0x07 == BPF_JMP {
            assert!((i + 1 + ins.jt as usize) < p.len() && (i + 1 + ins.jf as usize) < p.len(), "instruction {i} jumps off the end");
        }
    }
}

#[test]
fn netlink_all_lifts_protocol_check() {
    let sp = SocketPolicy { families: vec![], netlink_protocols: vec![], netlink_all: true };
    let p = build_program_full(BASE_ALLOWLIST, SECCOMP_RET_KILL_PROCESS, &sp).unwrap();
    let mut a = [0u64; 6];
    a[0] = AF_NETLINK as u64;
    a[2] = 12;
    assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, a), SECCOMP_RET_ALLOW);
    assert_eq!(evaluate_args(&p, X86, libc::SYS_socket as u32, with_arg(0, 17)), errno_action(EAFNOSUPPORT));
}

#[test]
fn base_socket_block_is_exact() {
    let mut generated = Vec::new();
    emit_arg_rule(&mut generated, ArgRule::SocketFamilies, SECCOMP_RET_KILL_PROCESS, &SocketPolicy::default());
    let expected = [
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, arg_lo(0)),
        (BPF_JMP | BPF_JEQ | BPF_K, 5, 0, AF_UNIX),
        (BPF_JMP | BPF_JEQ | BPF_K, 4, 0, AF_INET),
        (BPF_JMP | BPF_JEQ | BPF_K, 3, 0, AF_INET6),
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 3, AF_NETLINK),
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, arg_lo(2)),
        (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, NETLINK_ROUTE),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
        (BPF_RET | BPF_K, 0, 0, errno_action(EAFNOSUPPORT)),
    ];
    assert_eq!(generated.len(), expected.len() + 1); // + the leading jeq SYS_socket
    for (ins, (code, jt, jf, k)) in generated[1..].iter().zip(expected.iter()) {
        assert_eq!((ins.code, ins.jt, ins.jf, ins.k), (*code, *jt, *jf, *k));
    }
}

#[test]
fn each_call_named_once() {
    let mut seen = HashSet::new();
    for &(name, nr) in names() {
        assert!(seen.insert(name), "{name} is named twice");
        assert_eq!(syscall_by_name(name), Some(nr));
        assert_eq!(name_of(nr), Some(name));
    }
    assert_eq!(seen.len(), DENIED_RATIONALE.len() + BASE_ALLOWLIST.len() + ADDABLE.len());
    for &(name, nr) in ADDABLE {
        assert!(!is_denied(nr) && !BASE_ALLOWLIST.contains(&nr), "{name} is on a list already");
    }
    assert_eq!(name_of(libc::SYS_futex), Some("futex"));
}
