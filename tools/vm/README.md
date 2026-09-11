# The Kryptik developer VM

Three scripts that boot a machine, start s6, and run the zone test suites
inside it.

    mkinitramfs.sh   build a bootable initramfs
    run-qemu.sh      launch it under QEMU
    boot-smoke.sh    assert on the serial log afterwards

## Why this exists

The zone launcher is tested on the developer's host by
`compartments/tests/launcher.sh`. On a Windows workstation that host is WSL2,
which runs a Microsoft kernel with its own patch set and its own Landlock ABI
level. "The launcher isolates on this machine" and "the launcher isolates on
the kernel Kryptik ships" are different claims, and only the first one can be
checked without a VM.

Concretely, on 2026-09-11 the WSL host reported Landlock **ABI v3** and the VM
reported **ABI v8** — different enough that a confinement behaviour could
easily differ between them. That gap is the reason this exists.

## What one run proves

    make vm-boot

builds the image, boots it, and checks the serial log. A pass means all of:

- the kernel booted and did not panic, oops or BUG
- stage 1 init ran and `switch_root`ed off the initial rootfs
- **PID 1 is `s6-svscan`**, supervising a service directory
- cgroup v2 is mounted, and the log names the available controllers
- seccomp and Landlock are present, and Landlock is in the active LSM list
- `kryptikd check` passed *inside* the VM
- `compartments/tests/launcher.sh` passed *inside* the VM
- `compartments/tests/adversarial.sh` passed *inside* the VM
- the guest reached a clean poweroff

`boot-smoke.sh` asserts on sentinels in the log, never on QEMU's exit status.
QEMU exits 0 when the guest panics under `-no-reboot`, when it hangs until the
timeout, and when it powers off having done nothing — so "qemu exited 0" is
not evidence that anything booted.

## The two things that are NOT proven yet

**The kernel is not the Kryptik kernel.** Stage 05 has not produced one, so the
harness boots a stock distribution kernel. `boot-smoke.sh` reads the kernel
version out of the guest and says so.

**The userspace is not a Kryptik userspace.** Stage 04 has not produced a
sysroot, so the image is assembled from the host's binaries plus packages
unpacked from the signed distribution archive. The image records its own origin
in `/etc/kryptik-userspace-origin`, and `boot-smoke.sh` reports
**PASSED (HARNESS ONLY)** rather than PASSED when it reads `host-binaries`
there.

This is deliberate. A harness that can only be exercised once the distribution
builds is a harness that gets debugged at the worst possible moment. Both gaps
close by passing real inputs:

    tools/vm/mkinitramfs.sh --out img.cpio.gz \
        --kryptikd build/work/sysroot/usr/bin/kryptikd \
        --sysroot  build/work/sysroot \
        --s6root   <unpacked s6 + busybox> \
        --zones    compartments/zones

    tools/vm/run-qemu.sh --kernel build/work/out/bzImage --initrd img.cpio.gz \
        --log serial.log

and `boot-smoke.sh` then reports a real Kryptik boot without being told to.

## Two design decisions worth keeping

**It switch_roots onto a tmpfs, and must.** `pivot_root(2)` returns `EINVAL`
when the current root is the initial ramdisk. kryptikd builds every zone with
`pivot_root` (`rootfs.rs::pivot_into`), so in an initramfs-only boot *every*
zone start fails with "could not build the zone root" — a uniform failure that
says nothing about the launcher. Stage 1 copies the image to a tmpfs and
switch_roots into it so that `/` is an ordinary mount and the suite is
measuring kryptikd.

**kryptikd goes in statically linked.** Build it with
`--target x86_64-unknown-linux-musl`; the image then carries one 550KB file
with no library closure to keep in sync. (`isolate.rs` needs `as _` on the
`ioctl` request argument for this to compile: glibc types it `c_ulong`, musl
types it `c_int`.)

## Safety

`run-qemu.sh` never opens a disk image or a block device — the VM is kernel
plus initramfs only, so there is nothing for it to format. It runs with
`-nic none`, so the guest cannot reach the host's network. `-no-reboot` makes a
panic end the run instead of looping. A wall-clock timeout is enforced by the
harness rather than trusted to the guest. None of it needs root: KVM is used
when `/dev/kvm` is writable, and the run falls back to TCG software emulation
(with a tripled timeout) when it is not.
