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

`make media KRYPTIK_CHANNEL=https://<host>/<channel>/` names where the
image's network zone asks for new releases
([update channel](design/update-channel.md)). Without it the image fetches
nothing, and updates come only from a payload on a disk.

A development image, the default, is signed with keys the build makes on
first use under `<work>/keys` (`<work>` is `KRYPTIK_WORK`, as `make paths`
prints it). A production image is signed only with keys it is handed, from
the key medium, and names its version as MAJOR.MINOR.PATCH:

```sh
make media KRYPTIK_ROLE=production KRYPTIK_KEYS=/media/<medium> KRYPTIK_VERSION=1.0.3
```

The medium holds `release-signers` (the anchor the image will trust),
`kryptik-release` and `kryptik-release.pub`, `kryptik-sb.key` and
`kryptik-sb.crt`, and optionally `kryptik-latest` and `kryptik-latest.pub`.
Its private keys must be readable by their owner alone, who is root or the
user running the build, and it must not be inside the work or output tree.
Stage 06 checks all of that before it signs anything. It makes no key and
copies none: the keys are read by the tools that sign with them, by path.
Making the keys, publishing with them, and replacing them are in
[release keys](release-keys.md).

To publish a build, add its payload to the channel's directory, which any web
server can then serve at that address:

```sh
tools/release-channel.sh publish --key <work>/keys/release/kryptik-latest \
    --signers <work>/keys/release/release-signers \
    --payload <work>/images/payload-<version> --out /srv/<channel>
```

For a production image, the key and the signers file are the medium's
`kryptik-latest` and `release-signers`. When the medium carries no
`kryptik-latest`, stage 06 leaves publishing to the release host, which holds
that key. Re-sign the channel's statement daily, with `reissue` and the same
key and signers file, from a timer: a machine reports a statement older than
30 days.

## Testing without a build

The host suites need no build and no root:

```sh
make test         # every tools/test-* suite, then the compartment suites
make zone-tests   # adversarial.sh (the primitives) and launcher.sh (kryptikd run)
```

The compartment suites need a Rust toolchain and a kernel with user
namespaces, seccomp and Landlock. The privileged launch path and cgroup
limits run as root only on the installed system, in `make zones-test`.
