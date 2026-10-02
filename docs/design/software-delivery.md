# How software reaches zones

Every program a zone runs today comes from the verified root. kryptikd binds
zone 0's `/usr`, `/lib`, `/lib64`, `/bin` and `/sbin` read-only into each
zone (`SYSTEM_PATHS` in `compartments/kryptikd/src/rootfs.rs`), and the root
ships whole in every release. Version 2's applications (a graphical browser,
a mail client, a document viewer) do not fit that model for long. This
document chooses how they arrive: a package manager with a signed binary
repository, zones that carry their own userland, or something between. The
[roadmap](../roadmap.md) asks for an ADR first; the proposed text is
ADR-015 in [decisions](../decisions.md).

## Where things stand

- **The root is one signed object.** Stage 06 packs the sysroot into an ext4
  image with a dm-verity tree, and the root hash goes into each signed
  kernel's command line ([boot and updates](boot-and-updates.md)). On the
  newest main build the USB medium is 2,174,764,032 bytes, 512 MiB of it the
  ESP, so the root image is about 1,560 MiB.
- **Slots are sized once.** The installer makes each slot the image plus half
  again (at least 512 MiB more), rounded up to 64 MiB
  (`tools/install/kryptik-install.sh`). An install from today's medium gets
  2,368 MiB slots, and `kryptik-update apply` refuses an image larger than
  the inactive slot. A machine installed now can take releases about
  800 MiB larger than today's before it needs a reinstall, which
  [releases](../releases.md) numbers as a major version. Draft #179 lets an
  install ask for larger slots; that helps only new installs.
- **A zone can already run what it brings.** A zone's root is a tmpfs sealed
  read-only after `pivot_root`. Its home, `/tmp` and `/dev/shm` are
  writable, and the base Landlock rules allow exec in its home and `/tmp`
  (`landlock.rs`, `zone_rules`). `dev` builds and runs programs this way.
- **Nothing that grants privilege comes from the state partition.** Zone
  definitions and their policy files live on the verified root
  (`/usr/lib/kryptik/zones`). The state partition is encrypted but not
  authenticated: an offline writer can damage blocks, not choose what they
  decrypt to ([state encryption](state-encryption.md)).
- **Updates are verified before they are stored.** The net zone streams a
  release through the broker, and zone 0 keeps no more than the signed
  manifest's sizes ([update channel](update-channel.md)).

## Constraints

- **ADR-001.** What ships is built from source by Kryptik's toolchain with
  its flags. Another distribution's binaries bring that distribution's
  compiler defaults and setuid habits.
- **ADR-003.** Zone 0 runs no user application, and it should parse as
  little from outside as it can. Unpacking archives and solving dependencies
  as root in zone 0 is parsing.
- **ADR-005.** Every zone preloads hardened_malloc from the `/usr` it shares
  with zone 0.
- **ADR-007.** Each zone has its own seccomp and Landlock policy. A policy
  file can widen the seccomp filter only in named ways, and only a file on
  the verified root counts ([zone policy files](zone-policy-files.md)).
- **Code read from the state partition must be verified when it is read,**
  not only when it arrives, since an offline writer can change the blocks
  between the two.
- **The release key stays offline.** Each use is a ceremony with the key
  medium ([release keys](../release-keys.md)). The only online key, the
  statement key, can freeze a machine on an old release but cannot install
  anything.
- **Slots do not grow** on an installed machine (above).

## What has to be decided

Where application files live; who builds and signs them; how a zone gets
them and with which policy; how they are updated; and how they stay
compatible with the root they run on.

## Options

### Everything on the verified root

This is what Kryptik does now. Each application is a recipe in stage 04 and
its files are in the root image.

- **dm-verity** covers it with nothing new.
- **The channel** is unchanged. Every application fix is a whole release:
  Firefox's security releases come every four weeks, so Kryptik would cut a
  release, with the key medium, at least that often.
- **Policies** are the zone files', as now.
- **The slot limit** decides it. The browser and its toolkit stack alone
  take most of the 800 MiB of headroom a 1.0 install has (the browser and
  graphics design, `docs/design/browser-and-graphics.md`, proposed beside
  this one, works it out); a mail client, a document viewer and Mesa do not
  fit after it.
- **Other costs:** every build carries every application; every zone sees
  every application's files, including zones that never run them.

### A package manager and a signed binary repository

Kryptik builds packages with the same toolchain and signs an index, and a
package manager installs them. The question is where.

- **Into zone 0, over `/usr`.** Rejected. Files on the state partition would
  be verified when installed and trusted afterwards, and the package
  manager would unpack downloaded archives as root in zone 0.
- **Into each zone's home, by a package manager inside the zone.** Zone 0
  parses nothing, and a bad package compromises only the zone that installed
  it. The costs:
  - A package manager to adopt or write. apk-tools, xbps and pacman each
    bring their own index format and signature scheme: a second trust root
    beside the release key.
  - A signing key that is used often, since packages change more often than
    releases. If it is online, a stolen copy reaches every zone that installs
    from the repository; if it is offline, every package fix is a ceremony.
  - Packages link against the root's libraries, so a root release can break
    what zones installed unless the repository is rebuilt and reinstalled
    with each release.
  - Every zone stores, updates and pays for its own copy, and ephemeral zones
    (`untrusted`, `net`) lose everything at stop, so they can run only what
    the root ships.
  - A program that needs a wider filter, such as Firefox's
    `allow-syscall seccomp`, fails until a release changes its zone's policy
    file. A package cannot change its zone's policy, and should not.

### Zones that carry a foreign distribution's userland

A zone's volume holds a Debian or Alpine root, kept current by that
distribution's package manager and signed repository, as Qubes templates
are.

- Thousands of packages, updated by another distribution's security team,
  at no build cost here.
- ADR-001 no longer holds inside the zone: other compiler defaults, CET only
  where that distribution enables it, and glibc's allocator. hardened_malloc
  built against Kryptik's glibc 2.40 is not something to preload into
  another distribution's glibc.
- Package managers fight the zone filter. apt drops to its `_apt` user and
  dpkg chowns files to system accounts; a zone maps only its root and
  `nobody`, and the filter answers the id calls with `EPERM`.
- kryptikd would bind the zone's own `/usr` instead of zone 0's: a second
  mount layout, a volume that must be open before the zone has any programs,
  and nothing at all for an ephemeral zone.
- No dm-verity, and the channel is not Kryptik's. The slot limit is
  untouched.

### Signed software images built with each release

The Distro build packs groups of recipes (a browser and its toolkit, a mail
client, a document viewer, Mesa) into read-only images. Each is an ext4
filesystem with a dm-verity hash tree, listed with its root hash in a signed
manifest, stored on the state partition and stacked over zone 0's `/usr` for
the zones whose file names it.

- **dm-verity** checks every block at read, as for the root. An offline
  writer can make an image unreadable, not change what runs. Images run
  without the root's `panic_on_corruption`: a bad block in an application is
  an I/O error in the zone that reads it, not a reboot.
- **The channel** carries images as it carries a root payload, with the same
  verification. A browser fix fetches one image, needs no reboot, and a zone
  gets it at its next start.
- **Signing** stays with the release key, in a namespace of its own, so an
  image manifest can never pass for a root manifest or the reverse. A
  browser fix still needs the key medium, but not a whole release.
- **Compatibility** is exact. An image is built against one root release's
  sysroot and records that release; kryptikd mounts it over that root and no
  other. A root release rebuilds every image.
- **Policies** stay on the verified root. An image's manifest lists the
  policy lines its programs need, and `kryptikd check` refuses a zone that
  names the image without them. The image widens nothing.
- **The slot** keeps its headroom for the kernel, firmware and the base
  system.
- **Costs:** new code in kryptikd (verify the manifest, set up loop and
  dm-verity, stack the images); a build step that captures exactly what a set
  of recipes installs; state-partition space for two generations of each
  image while an update is in flight; and a `/usr` that differs between
  zones, which `kryptikd explain` has to show.

## Recommendation

Signed software images built with each release. A zone's home stays open for
whatever its user builds or downloads, at that zone's own risk, as `dev`
does now. No package manager and no foreign userland are shipped: the first
adds a second trust root, a key that is used often, a dependency solver and
a copy per zone, for a choice a zone's home already gives; the second gives
up ADR-001 in the zones where the applications run.

### The images

- **Built.** A stage after stage 04 builds each image's recipes in the chroot
  over the finished sysroot, through an overlay whose upper directory
  collects what they install. That directory is the image's tree. A recipe
  may add files and must not replace or remove one of the root's: a whiteout
  or a path the root already has fails the step, so the root's files stay
  the ones verified at boot. The build also writes, per image, the policy
  lines its programs need, found with `kryptikd seccomp-trace`.
- **Packed.** Stage 06 makes `image-<name>.img` the way it makes the root
  (ext4 without a journal, then the verity tree) and a manifest:

  ```text
  KRYPTIK-IMAGES-1
  base: 1.2.0
  image: browser 140.4.0 root-hash=<64 hex> salt=<hex> bytes=<n> sha256=<64 hex>
  needs: browser allow-syscall seccomp
  ```

  signed by the release key in the namespace `kryptik-image`, which the
  anchor grants the release key alone.
- **Stored** under `/var/lib/kryptik/images/<name>/<root hash>.img`, root
  only. Zone 0 keeps the generation the committed root uses and, during a
  trial, the one the trial root uses.
- **Fetched** by the same verbs as a release. The statement of what is
  current gains one line per image for each base it serves; zone 0 fetches
  only images whose hash it does not hold, never past the signed size.
- **Mounted** by kryptikd on first use: a read-only loop device, dm-verity
  with the manifest's root hash, and ext4 mounted read-only, `nosuid,nodev`
  at `/run/kryptik/images/<name>`. A mapping that dm-verity has marked
  corrupted is not used again: the next start of a zone that names the image
  is refused, with the reason, until the image is fetched again. For each distinct set of images a zone
  names, kryptikd mounts a read-only overlay (no upper directory; the
  images' `usr` over the root's `/usr`) at `/run/kryptik/usr/<set>` in the
  initial namespace, and the zone's bind of `/usr` takes that instead. Since
  zone 0 mounts it and the zone only receives a bind, the hardened kernel's
  `OVERLAY_FS_UNPRIVILEGED`, which is off, does not come into it. Loop,
  dm-verity and overlayfs are already built in.
- **Named** in the zone file:

  ```toml
  [software]
  images = ["browser"]
  ```

  `untrusted` and `vault` name none in the first release that has images.
  Zone 0 never mounts one: the compositor and zone 0's programs see only the
  root.
- **Not in the loader cache.** A zone's `/etc/ld.so.cache` is bound from zone
  0 and lists the root's libraries; the loader finds an image's libraries by
  its default search of `/usr/lib`. A cache per image set is a later
  optimisation if starting programs is measurably slower.

### What a stolen or misused key can do

The release key already signs what every machine runs, so images give a
thief little that a release would not: an image reaches the zones that name
it without a reboot, which is quieter. The namespace keeps an image manifest
from being replayed as a root manifest. The statement key, which names the
current images, can still only hold a machine on old ones.

### Settings on the state partition

A setting kept on the state partition may take an image away from a zone,
never give one. A user who does not want the browser image in `work` can
say so there; adding an image to a zone takes a zone file on the verified
root.

## The check that proves it done

The update suite installs a release with a browser image, then applies an
image-only update from the channel:

- the net zone fetches only the changed image, and zone 0 verifies it under
  `kryptik-image` before keeping more than its signed size;
- a `personal` zone started afterwards runs the new image's browser, while a
  zone already running keeps the old image until it stops;
- a flipped block in a stored image reads as an I/O error in the zone, the
  machine keeps running, and the next start of a zone that names the image is
  refused with the reason until it is fetched again;
- an image built for another base, an image manifest signed in
  `kryptik-release`, and a root manifest signed in `kryptik-image` are each
  refused;
- `kryptikd check` refuses a zone that names an image without the policy
  lines the image needs;
- `untrusted`, which names no image, finds none of its files.

## Open questions

- Whether images should ever be signed by a key that can be used without
  the key medium, to ship browser fixes faster. This document says no.
- Delta updates of images, which dm-verity's block structure would allow, as
  for the root ([update channel](update-channel.md#open-points)).
- How a user picks images for a zone beyond the shipped files; that waits
  for user-defined zones, which are not designed yet.
- Caches the root keeps for its own files (fontconfig's, an icon theme's)
  cannot be replaced by an image, so an image carries its own under its own
  paths. Whether that is enough for the toolkit stack is found when the
  browser image is first built.
