# Building Kryptik

The `Distro` workflow builds and tests every push to `main` on GitHub's
runners, so a local build is optional. It needs Linux; `make check` refuses
to run anywhere else and names what the host is missing.

## Host packages

On Debian or Ubuntu, the same set the Distro workflow installs
(`HOST_PACKAGES` in `.github/workflows/distro.yml`):

```sh
sudo apt install -y build-essential bison flex texinfo gawk m4 patch perl \
    python3 python3-pip xz-utils bzip2 zstd cpio rsync bc curl git openssl \
    libssl-dev libelf-dev e2fsprogs dosfstools mtools xorriso util-linux \
    cryptsetup-bin sbsigntool qemu-system-x86 ovmf musl-tools file
sudo dpkg-reconfigure dash        # answer "No": /bin/sh must be bash
```

The Secure Boot suites also need `virt-fw-vars` (`pip install
virt-firmware`), and the acceptance suites want KVM.

## WSL2

Build from a clone on the Linux filesystem, not `/mnt/c`: it is slow, and it
cannot represent the POSIX ownership the chroot stages depend on. GCC's
bootstrap wants about 8 GB of memory; if `make check` warns, raise the limit
in `%UserProfile%\.wslconfig` and run `wsl --shutdown`:

```ini
[wsl2]
memory=12GB
processors=8
```

## Stages

```sh
make check      # what the host is missing
make lock       # regenerate sources.lock; audit it (docs/supply-chain.md)
make sources    # fetch and verify
make toolchain  # stage 01                     (unprivileged)
make temp-tools # stage 02                     (unprivileged)
make system     # stage 04, inside the chroot  (root for the mounts)
make kernel     # stage 05, inside the chroot
make media      # stage 06: USB image, ISO, signed release payload
```

`make paths` prints where everything goes; `KRYPTIK_WORK` moves the work tree.
Each step is stamped, so a rerun resumes where it stopped and a changed
recipe rebuilds from that step on.

## Testing without a build

The host suites need no build and no root:

```sh
make test         # every tools/test-* suite, then the compartment suites
make zone-tests   # adversarial.sh (the primitives) and launcher.sh (kryptikd run)
```

The compartment suites need a Rust toolchain and a kernel with user
namespaces, seccomp and Landlock. The privileged launch path and cgroup
limits run as root only on the installed system, in `make zones-test`.
