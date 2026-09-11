# Building Kryptik

Kryptik must be built on Linux. `make check` refuses to run anywhere else.

## On Windows (WSL2)

```powershell
wsl --install -d Ubuntu
```

Then inside the WSL shell:

```sh
sudo apt update
sudo apt install -y build-essential bison flex texinfo cpio rsync bc \
                    gawk libssl-dev python3 git curl xz-utils

# /bin/sh must be bash, not dash — LFS build scripts use bashisms.
sudo dpkg-reconfigure dash        # answer "No"

# qemu is needed for `make vm-boot` (see "The developer VM" below).
# cryptsetup and sbsigntool are for per-zone LUKS volumes and signed images,
# neither of which is implemented yet.
sudo apt install -y qemu-system-x86 cryptsetup-bin sbsigntool
```

The above was derived from an actual `make check` run against a stock Ubuntu
WSL2 image on 2026-09-10, which reported exactly these as missing: `bison`,
`texinfo`, `cpio`, `flex`, and `/bin/sh -> dash`.

### Build on the Linux filesystem, not `/mnt/c`

Building across the Windows filesystem boundary is slow and, worse, `/mnt/c`
does not preserve POSIX ownership and permission bits — which the LFS chroot
stages depend on.

```sh
git clone <your-remote> ~/kryptik
cd ~/kryptik
```

Keep the repo on `/mnt/c` for editing if you like, but run builds from a clone
inside the WSL filesystem.

### Memory

GCC's bootstrap wants 8 GB. WSL2 defaults to roughly half of host RAM. If
`make check` warns about memory, raise it in `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=12GB
processors=8
```

Then `wsl --shutdown` and reopen.

## First run

```sh
make check      # tells you exactly what your host is missing
make lock       # generates sources.lock — AUDIT IT (docs/supply-chain.md)
make sources    # fetches and verifies
```

Stages 01 through 05 are implemented. Stage 06 (the bootable image) is still a
stub and says so when run. Stages 03 and 04 need root to establish the chroot;
`make system` tells you the exact command rather than attempting it for you.

See [roadmap.md](roadmap.md) for what each stage has and has not been executed
against.

## Testing the compartment layer without building anything

The zone suites need only a Rust toolchain and a kernel with user namespaces,
seccomp and Landlock. They do not need a Kryptik build:

```sh
make zone-tests
```

That runs both suites, and they answer different questions.
`compartments/tests/adversarial.sh` drives the isolation primitives with
`unshare(1)`; `compartments/tests/launcher.sh` drives `kryptikd run` itself.
The primitives can be sound while the launcher applies them in the wrong order,
so a change to the zone path has to pass both.

## The developer VM

WSL2 runs a Microsoft kernel. "The launcher isolates here" and "the launcher
isolates on the kernel Kryptik ships" are different claims, and the gap is not
theoretical — WSL2 reports Landlock ABI 3 where a current kernel reports 8. The
VM is how the second claim gets tested, and it is also the only place the
**privileged** launch path runs, since kryptikd normally runs as root and a
developer host has no sudo in it.

```sh
make vm-boot KERNEL=<path to a bzImage> S6ROOT=<dir with usr/bin/{s6-svscan,busybox}>
```

It builds an initramfs, boots it under QEMU, and asserts on the serial log:
kernel up without panic, `switch_root` off the initial rootfs, PID 1 is
`s6-svscan`, cgroup v2 and Landlock present, and both zone suites passing
*inside* the guest. It opens no disk image, uses `-nic none`, and needs no root
— KVM when `/dev/kvm` is writable, software emulation otherwise.

Until stages 04 and 05 produce a sysroot and a kernel, the image is assembled
from host binaries and boots a stock kernel. It records that in
`/etc/kryptik-userspace-origin` and the check reports **PASSED (HARNESS ONLY)**
rather than claiming Kryptik booted. Pass `SYSROOT=` and a Kryptik `KERNEL=` and
the same command reports a real boot. See [../tools/vm/README.md](../tools/vm/README.md).
