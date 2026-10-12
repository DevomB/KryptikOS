# Reproducible builds and the first compiler

[Supply chain](../supply-chain.md#open-problems) names two open problems.
Builds are not reproducible, so "built from source" still means trusting the
machine that built it. And the first compiler comes from the host, so
Thompson's "Reflections on Trusting Trust" applies in full. The
[roadmap](../roadmap.md) asks for reproducible builds checked by CI, then a
bootstrappable toolchain. This document lists what differs between two
builds today, how each difference goes, what CI compares, what happens to
the module signing key, and how live-bootstrap fits in front of stage 01.
The proposed decision is ADR-018 in [decisions](../decisions.md).

## What reproducible means here

Two builds of one commit, on different runners, at different times and in
different work directories, produce the same bytes for everything that
ships, signatures set aside. "What ships" is the root image, each kernel
before it is signed, each module, the ESP's other files, `root.json` and the
update manifest's text. The signatures set aside are the Secure Boot
signature in each kernel's PE certificate table, the manifest's `.sig` and
the media checksums' `.sig`.

Inside the chroot, paths are fixed whatever the host's work directory:
sources at `/kryptik-sources`, work at `/kryptik-work`, the tree at
`/kryptik` (`build/stages/03-chroot-prep.sh`). Stages 04 and 05 therefore
never see the host's paths. Stage 06 and the Rust binaries do.

## What differs between two builds today

### Stage 06's root image

`s_rootfs` in `build/stages/06-iso.sh`:

- **The verity salt** is `openssl rand -hex 32`, so the root hash, and with
  it every kernel's command line, differs in every build. The salt can be
  the SHA-256 of the ext4 image before the tree is appended: still unique to
  that content, and the same in every build of it.
- **The filesystem is made by the host's `mkfs.ext4 -d`.** The Ubuntu 24.04
  runners have e2fsprogs 1.47.0, which copies each file's ctime from the
  staging tree (when rsync wrote it, not when the package was built) and
  takes the current time for the superblock. Support for
  `SOURCE_DATE_EPOCH`, with every time mke2fs writes clamped to it, and a
  tarball as `-d`'s input both arrived in 1.47.1
  ([release notes](https://e2fsprogs.sourceforge.net/e2fsprogs-release.html)).
  Three ways out:
  - run the sysroot's own `mkfs.ext4`, which stage 04 builds at 1.47.1, in
    the chroot, from the step that already enters it to bind the kernels;
  - build a host e2fsprogs at 1.47.1 or later from the pinned tarball before
    stage 06;
  - feed mke2fs a normalised tarball (sorted names, fixed owner, clamped
    times). That needs libarchive in whichever e2fsprogs runs, which the
    sysroot's does not have.

  The first adds no tool and no recipe.
- **The UUID and the directory hash seed** are random unless given:
  `-U <uuid>` and `-E hash_seed=<uuid>`, both derived from the version and
  the commit.
- **Directory order.** mke2fs walks each directory with `scandir` and
  `alphasort` (in 1.47.0 and 1.47.1 alike), so the order follows the
  collation of the locale it runs in. `LC_ALL=C` makes it bytewise.
- **What stage 06 writes into the tree**: `os-release`, `kryptik-image.json`,
  `ld.so.preload`, the trust anchor and role, `update.conf`, `fstab`, and
  the directories it creates. Their contents are fixed by the inputs except
  `built_at`, which is `date -Iseconds`, and the default version,
  `0.1.<date>.<commit>`. Their times are now; mke2fs 1.47.1 clamps them.

The fix is one `SOURCE_DATE_EPOCH`, the commit's time, exported for the
whole build, with `built_at` written from it in UTC, and the same
`KRYPTIK_VERSION` passed to both builds being compared.

**The clock floor moves with it.** `built_at` is the floor kryptikd keeps the
clock above (`floor_from_image_json` in `time.rs`), and the `time-floor`
service raises a dead RTC to it ([clock](time.md)). With the commit's time
there, the floor becomes the time of the commit rather than of the build:
earlier by hours for a dated build, by days at most for a release tagged
after its commit. A floor may be early and never late, so every rule in the
time design still holds. The parser takes the `+00:00` offset that
`date -u -Iseconds` prints.

### Stage 05's kernel

- `/proc/version` carries the build's time, user and host, and a runner's
  host name changes with every run. `KBUILD_BUILD_TIMESTAMP`,
  `KBUILD_BUILD_USER` and `KBUILD_BUILD_HOST` fix them, as the kernel's
  documentation describes (`Documentation/kbuild/reproducible-builds.rst`).
- `RANDSTRUCT_FULL` lays out structures from a seed generated for each
  tree (`scripts/basic/randstruct.seed`). Reproducing the kernel needs that
  seed fixed. For a published kernel this costs nothing: anyone holding the
  image can read the layout from it, with or without the seed.
- The module signing key is made for each build and thrown away
  ([hardening](../hardening.md#kernel)). Its certificate is in the kernel
  and its signature is on every module, so the kernel and the root image,
  which holds the modules, differ in every build. That needs a decision of
  its own (below).

### Stage 04's packages

Paths are fixed in the chroot, so what remains are the usual suspects:
compressed man and info pages (gzip stores a time and a name unless `-n`),
static archives (member times, unless binutils is in deterministic mode),
Python's bytecode (a timestamp in each `.pyc`, unless `SOURCE_DATE_EPOCH`
is set, when `py_compile` writes hash-checked files), and perl's
`Config.pm`, which records when and by whom perl was built.
Exporting `SOURCE_DATE_EPOCH` from `build/lib/common.sh` for every step,
which nothing does today, would take most of them. The comparison finds the rest package by package.

### The Rust binaries

kryptikd and kryptik-wlproxy are built on the runner by cargo, at the
checkout's path and with the runner's `CARGO_HOME`, and both paths end up in
panic locations. `--remap-path-prefix` for each removes them. The toolchain
is already pinned by hash (`build/config/rust.lock`).

### The media

`mkfs.vfat` picks a random volume ID, mtools stamps the ESP's files with the
current time, sfdisk picks random disk and partition GUIDs for the USB
image, and xorriso dates the ISO. All four take fixed values: IDs derived
from the version, times from `SOURCE_DATE_EPOCH`. The media wrap everything
above, so they are compared last.

## The module key

Three ways to make the kernel and its modules reproducible:

- **The same throwaway key in both builds.** CI's two builds take one key,
  made for the comparison and thrown away. Module signatures then match too:
  the kernel's `sign-file` adds no signed attributes (`CMS_NOATTR`), and RSA
  PKCS#1 v1.5 signatures are deterministic. This proves the build is
  deterministic. It does not let anyone else reproduce a release, which was
  signed with a key nobody has any more.
- **The kernel's documented split.** The certificate is an input
  (`CONFIG_SYSTEM_TRUSTED_KEYS`), `CONFIG_MODULE_SIG_ALL` is off, the modules
  are signed in a separate step, and the signatures are published; a second
  build attaches them. Kryptik keeps a key made for each build and thrown
  away, and publishes its certificate and the module signatures with the
  release. The release itself must be built this way, in two passes, since
  `CONFIG_IKCONFIG` embeds the `.config` in the kernel and a verifier's
  configuration has to match it. Anyone can then rebuild the release's root
  image byte for byte, with nothing secret.
- **Hash-based module integrity** (`CONFIG_MODULE_HASHES`). The kernel embeds
  a Merkle root of the modules built with it, and no key exists at all. It
  is proposed upstream and in no released kernel. Carrying the series on
  linux-hardened would add to the rebase cost ADR-009 already names, at every
  kernel update.

Recommendation: the same throwaway key for CI's comparison now; the two-pass
split for releases, so a release can be checked by anyone; hash-based
integrity once a longterm kernel has it, which removes the module key
altogether.

## What CI compares

- **Two builds of one commit.** A Distro workflow run builds the commit on
  two runners, in different work directories, at different times, with the
  same `KRYPTIK_VERSION` and the same throwaway key medium (as
  `make production-pair` already makes one), and no cache, since a cached
  tree can hold what an older recipe installed
  ([status](../status.md#known-gaps)).
- **Compared byte for byte:** `kryptik-root.img`; each kernel variant before
  signing (`images/kernels/<variant>.efi`); `root.json`; the manifest's text;
  the ESP's files other than the kernels; then the media. With one key, the
  signed kernels should match as well. If sbsign's PKCS#7 carries a signing
  time, the certificate table is removed before comparing (`sbattach
  --remove`), as the signatures are set aside anyway.
- **On a difference:** diffoscope on the first file that differs, kept with
  the run's logs.
- **When:** weekly, and for every tag, whose release notes then say whether
  the release reproduced. Not on every push: a second build with no cache is
  about three more hours.
- **Different hosts:** one of the two builds runs on another runner image.
  Stage 01 is built by the host's compiler, and what ships is built in the
  chroot by stage 02's compiler, which descends from it. Matching output
  shows the host's compiler changed nothing that ships, as far as two
  independent compilers can show it.

## A bootstrappable first compiler

Today stage 01 builds the cross toolchain with the runner's GCC, and
everything after descends from it.

[live-bootstrap](https://github.com/fosslinux/live-bootstrap) starts from a
binary seed of a few hundred bytes that a person can read (hex0), and from
sources alone. It climbs through stage0-posix, GNU Mes and its C compiler,
TinyCC, GCC 4.0.4, 4.7.4 and 10.5 to GCC 15.2 with binutils 2.41 and musl
1.2.5, building bash, perl, python and the rest of a usable system on the
way. It runs in a chroot or bubblewrap, in QEMU, or on bare metal, and its
own CI on GitHub's runners splits the run into three jobs.

**How it fits.** A new stage before stage 01 runs live-bootstrap in
bubblewrap on the runner and keeps its final system. Stage 01 then runs with
that system as its host. `make check` runs there first, so anything stages
01 and 02 need that live-bootstrap does not build becomes a named gap,
closed by a recipe. Nothing after stage 01 changes.

**Inputs.** live-bootstrap's source files join the pinned sources, each with
its hash, and with its signature where upstream signed it, under the same
gates as every other source ([supply chain](../supply-chain.md)).

**What it removes and what stays.**

- The host's compiler and binaries leave the chain.
- The host's kernel stays in it while live-bootstrap runs in a chroot. The
  bare-metal path, which starts from a hex0 kernel, removes it, at a much
  larger cost.
- The Rust toolchain stays a binary (ADR-010). mrustc can build an old rustc
  from C++, and each rustc builds the next, but reaching the pinned release
  takes dozens of compiler builds.

**The check.** Once builds are reproducible, the root image built from
live-bootstrap's compiler is byte for byte the root built from the runner's.
Two independent first compilers giving one result is the
diverse-double-compiling test.

## Recommendation

1. **Reproducible root and kernels:** `SOURCE_DATE_EPOCH` from the commit;
   stage 06's mke2fs run in the chroot from the sysroot's e2fsprogs 1.47.1,
   under `LC_ALL=C`, with a fixed UUID and hash seed; the salt from the
   image; `KBUILD_BUILD_*` and a fixed randstruct seed; `--remap-path-prefix`
   for the Rust binaries; fixed IDs and times on the media.
2. **CI compares** two builds weekly and for every tag, with one throwaway
   key medium, on two runner images.
3. **Releases sign modules in two passes** and publish the module
   certificate and signatures; a tool rebuilds a release from its tag and
   compares.
4. **Then live-bootstrap** as the stage before stage 01, and the comparison
   between the two first compilers.

## The check that proves it done

The Distro workflow builds one commit twice, on two runner images, at
different times and in different work directories. The root image and every
kernel before signing come out byte for byte the same, and a tag's run says
so in its release notes. For the second half: the root image built after
live-bootstrap is byte for byte the root image built after the runner's
compiler.
