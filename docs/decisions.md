# Architecture decision records

Each record gives the decision, the reasons and the cost. All are accepted
except those marked proposed, which wait for the owner's decision.

## ADR-001: Build from Linux From Scratch

Kryptik's hardening is toolchain-wide and its init path is unusual. A base
distribution would bring its compiler defaults, package layout and setuid
binaries, and all three would have to be fought.

**Cost:** months before a bootable image, and permanent ownership of security
updates for every package shipped. This is the project's largest cost.

## ADR-002: Kernel isolation, not a hypervisor

Zones are namespaces, cgroup v2, Landlock and seccomp, not Xen. Qubes'
hypervisor boundary is stronger, but it needs VT-d, costs battery life and
makes GPU acceleration painful. Kryptik is for users who would run Qubes but
not pay that hardware cost.

**Cost:** a kernel privilege escalation compromises every zone
([threat model](threat-model.md#kernel-local-privilege-escalation)).

## ADR-003: Zone 0 runs no user applications

Once a browser runs in zone 0 "just this once", the system is a Linux box with
containers.

**Cost:** friction. Every "can I just run this on the host" is refused.

## ADR-004: Wayland only, no X11

X11 lets any client log every other client's keystrokes and capture the whole
screen, which ADR-003 cannot allow.

**Cost:** X11 programs are not supported. No Xwayland is built, and a zone
runs Wayland clients alone; if the graphical applications of Version 2 need
one, it runs inside the zone, where it can leak only that zone.

## ADR-005: hardened_malloc as the system allocator

It adds slab quarantines, guard slabs, randomized allocation and
heap-overflow canaries. Preloaded for every process of the running system and
of every zone ([hardening](hardening.md#allocator)).

**Cost:** slower on allocation-heavy workloads.

## ADR-006: s6-rc as init and service supervisor

PID 1 is s6-svscan; s6-rc manages service dependencies. systemd's sandboxing
is better, but zones already provide it and kryptikd owns zone lifecycle.
Socket activation and journald do not justify a large privileged PID 1 in a
system that assumes a local attacker looking for privileged code.

**Cost:** off the LFS path, so every service definition is written from
scratch; seatd instead of logind; the `net` zone runs its own DHCP client, and
no other zone touches a real interface; logging is s6-log per service, with no
aggregation.

**Revisit if** writing service definitions becomes the main cost of the base
system.

## ADR-007: Landlock and seccomp only, no SELinux or AppArmor

SELinux policy written from zero is plausibly a bigger project than the
distribution, and a policy too large to audit gives confidence, not security.
AppArmor is path-based, which composes badly with per-zone mount namespaces,
where one path means different things in different zones. Isolation rests on
Landlock for file access, seccomp-bpf for syscalls, cgroup v2 for resources,
and namespaces for network and IPC: a zone's network is an absent interface,
not a policy rule, so Landlock's late network support does not matter.

**Cost:** a Landlock bypass has no second MAC layer behind it.

**Revisit** once zone semantics are stable enough to write a policy against.

## ADR-008: glibc

musl is smaller and easier to audit, and fits Kryptik better. But much
software assumes glibc, and time on compatibility shims is time not spent on
the compartment layer, which is the new part of Kryptik.

**Cost:** more attack surface than musl, and switching later means rebuilding
from stage 01.

**Revisit** after the compartment layer, when a libc swap is a contained
experiment.

## ADR-009: An LTS kernel with linux-hardened

Kryptik pins linux 6.18.x (longterm) with the matching linux-hardened patch.
A kernel that is not longterm reaches end of life within months, so
`make check-kernel-eol` fails on a pinned kernel that is EOL or not longterm,
and `make kernel` runs it first.

A kconfig fragment can only turn on what mainline has. linux-hardened adds
what mainline has not merged: stronger ASLR entropy, more slab sanitization,
tighter usercopy checks, less of the surface mainline keeps for compatibility.

**Cost:** the kernel moves only when a matching linux-hardened release exists,
so a fix can land days after mainline stable, and Kryptik kernel patches are
rebased on linux-hardened. linux-hardened is a partial, community-maintained
descendant of grsecurity, which is commercial and unavailable: do not call
Kryptik grsecurity-hardened.

**Rejected:** mainline with kconfig only, which is not enough for what the
project claims; an own patchset, since any kernel hooks zones need go on top
of linux-hardened, not instead of it.

## ADR-010: kryptikd is written in Rust

kryptikd runs privileged in zone 0: it parses zone definitions, builds
namespaces, applies seccomp and Landlock, runs the broker and holds the keys
to zone volumes. A memory-safety bug there breaks what separates every zone.
Kryptik pays for `-D_FORTIFY_SOURCE=3`, hardened_malloc and `INIT_ON_ALLOC`
because memory-safety bugs are the most exploited class; C for this one
process would contradict that.

**Cost:**

- rustc is not built from source: that needs an existing rustc, or mrustc, a
  project of its own. The shipped kryptikd and kryptik-wlproxy are built by
  Rust's release tarballs, held to the hashes in `build/config/rust.lock`
  (checked against the Rust release key when pinned): a trust anchor
  [supply-chain.md](supply-chain.md) otherwise avoids.
- kryptikd depends on `libc` only; every new crate is a supply-chain decision
  justified in review.
- A Rust toolchain is a lot to carry for one daemon.

**Rejected:** C (smallest bootstrap, but see above); Go, whose runtime and
scheduler fight `clone()`, `unshare()` and per-thread namespace state; shell,
unsuitable for holding privilege and parsing untrusted zone state.

Rust is for kryptikd and Kryptik's own tools, not a distribution-wide rule:
coreutils stays coreutils.

## ADR-011: SMT off, every CPU mitigation on

Every signed kernel's command line carries `mitigations=auto,nosmt`: every
mitigation the kernel knows for the CPU, and simultaneous multithreading off.

**Why:** the threat is a compromised zone reaching the kernel or another zone.
L1TF, MDS, TAA and their successors leak between the two hardware threads of a
core, so a zone on one thread can read another zone, or the kernel, on the
other. KSPP recommends the setting and kernel-hardening-checker fails without
it.

**Cost:** half the logical CPUs on an SMT machine, roughly 15 to 30 percent of
parallel throughput. Single-threaded performance is unchanged.

**Decided:** `nosmt` stays. Each zone asks for its own core-scheduling
cookie at launch ([privileged launch](design/privileged-launch.md#core-scheduling)),
which keeps two zones off the two threads of one core; it cannot keep a zone
off the thread beside the kernel, since the kernel's own execution carries no
cookie, and that is the leak the mitigations exist for. Closing it with SMT on
means a flush on every kernel entry, which costs more than the threads give.
No measurement changes which boundary the cookies leave open. The cookies
stay as defence in depth for when SMT is on all the same: plain `nosmt` lets
root turn it back on through `/sys/devices/system/cpu/smt/control`. With no
sibling thread online the kernel refuses the cookie (`ENODEV`) and
`kryptikd status` says `no-smt`.

## ADR-012: Device firmware from linux-firmware, on the verified root

The image ships the firmware laptop graphics and Wi-Fi need, from the pinned
`linux-firmware` release, as selected by `build/config/firmware.list`,
zstd-compressed under `/lib/firmware` on the dm-verity root. The drivers that
load it are signed modules, so they probe after the root is mounted.

**Why:** Intel, AMD and Qualcomm Wi-Fi and AMD GPUs do not run without vendor
firmware, and Intel graphics runs degraded. Without it most laptops have no
Wi-Fi.

These are vendor binaries, not built from source as
[supply-chain.md](supply-chain.md) otherwise requires, and run by the device's
own processor under the kernel's control of the bus (IOMMU on and strict).
Kryptik establishes that the tarball is the one kernel.org signed, its hash is
pinned, each file's licence is the one `WHENCE` records, and the copy the
kernel loads is on the verified root, so replacing it means re-signing the
kernel.

**Left out:** NVIDIA (nouveau needs tens of megabytes of GSP firmware per
generation, and the firmware framebuffer gives those machines a display);
Bluetooth and sound, which no zone uses yet. What is not on the list is not
shipped.

**CPU microcode** is the same decision. The early loader runs before any
filesystem and there is no initramfs, so Intel and AMD microcode is built into
each signed kernel (`CONFIG_EXTRA_FIRMWARE`, stage 05), about 17 MB. Without
it a machine runs whatever microcode its firmware last shipped, which on older
machines means known, unfixed CPU vulnerabilities.

**Cost:** about 135 MB after zstd (385 MB of files; Intel Wi-Fi is 56 MB and
amdgpu 38 MB compressed) on a root image of about 1.7 GB, and an input nobody
here can read.

## ADR-013: A driver is built in only when boot needs it

With no initramfs, a driver is built into the signed kernel only if it finds,
verifies or mounts the root; gives a console and keyboard before the root is
mounted; or cannot work as a module (netfilter for the `net` zone, microcode,
the watchdog, a few platform drivers that misbehave when loaded late).
Everything else, including every network card, GPU and pointing device, is a
signed module that eudev loads at coldplug. What Kryptik never uses (sound,
network filesystems, CardBus, AGP, software RAID, conntrack helpers) is not
built. The rule heads `build/config/kernel/boot.fragment`, and stage 05 fails
a kernel larger than `build/config/kernel/size-budget`.

**Why:** a built-in driver is on every machine whether or not its device is. A
module loads only where it is used, through the path real Wi-Fi and graphics
need anyway. The VM gets no exception: with virtio-net and virtio-gpu as
modules, every acceptance run proves module autoload.

**Not shrunk:** about 17 MB of the kernel is microcode, which is encrypted and
does not compress. Pre-2011 CPUs, which cannot boot Kryptik, account for 0.4 MB,
not worth a rule. Four server-only Xeon families take 6.8 MB and stay while the
README lists server hardware: a server whose microcode is left out still boots
on old microcode, and nobody would notice.

## ADR-014: The signed kernel is the whole boot chain

The firmware loads Kryptik's kernel as the UEFI application, and nothing else
runs before the verified root: no shim, no boot loader, no initramfs. The
command line is compiled in and names the root slot and its dm-verity root
hash, so the firmware's one signature check covers the code and the hash of
everything it will run ([boot and updates](design/boot-and-updates.md)). A
machine trusts that signature once Kryptik's certificate is in its firmware's
database ([release keys](release-keys.md)).

**Why:** every stage between the firmware and the root is a file to sign, a
parser to attack and a place for an unmeasured change. A shim chains from
Microsoft's key, which Kryptik does not use; a boot loader chooses and edits
what boots, which the compiled-in command line forbids on purpose; an
initramfs finds the root, which `dm-mod.create=` does inside the kernel.

**Cost:** the certificate is enrolled by hand on every machine, and firmware
that carries only Microsoft's keys refuses the media; the controller the root
sits on is built into the kernel (ADR-013); A/B updates and recovery are the
firmware's boot entries and a judged trial, not a loader's menu.

**Rejected:** shim and a loader, two more signed stages and a configuration
file; an initramfs inside the signed image, measured but a second userland to
keep small and right.

## ADR-015 (proposed): Applications ship as signed images beside the root

The root keeps the base system: what zone 0 runs and what every zone needs.
Applications (the browser and its toolkit, a mail client, a document viewer,
Mesa) are built by the same toolchain in the same build, packed as read-only
ext4 images with dm-verity trees, and listed with their root hashes in a
manifest the release key signs in a namespace of its own (`kryptik-image`).
They are stored on the state partition and fetched through the update
channel. kryptikd verifies the manifest, opens each image with dm-verity, and
stacks the images a zone file names over zone 0's `/usr` for that zone alone.
An image is built for one root release and mounted over no other, may add
files but never replace the root's, and lists the policy lines its programs
need, which the zone file must already grant
([how software reaches zones](design/software-delivery.md)).

**Why:** the root cannot grow much on an installed machine (a slot is the
image plus half again), and applications change faster than the base. Images
keep every block verified at read on an unauthenticated partition, need no
second trust root, and let a browser fix ship without a whole release or a
reboot.

**Cost:** new mounting code in kryptikd; a build step that captures what a
set of recipes installs; disk on the state partition for two generations of
images; every root release rebuilds every image; a browser fix still needs
an approved signing run.

**Rejected:** a package manager installing into zone 0 (unverified code on
the state partition, unpacked by root); one installing into each zone (a
second trust root, a signing key in frequent use, a copy per zone, nothing for
ephemeral zones); another distribution's userland in a zone (gives up
ADR-001 where the applications run); everything on the root (does not fit
the slots of machines already installed).

## ADR-016 (proposed): Firefox in zones, rendering in software; the GPU and X11 by zone

The browser is Firefox ESR, built by stage 04's GCC for Wayland alone, on
GTK 3 without X11 or D-Bus, and run with its own seccomp sandbox inside the
zone's. Zones render in software into shared memory. A zone gets the GPU's
render node only when its file on the verified root says `gpu = "render"`;
no shipped zone that runs a browser does, the proxy then offers that zone
alone `zwp_linux_dmabuf_v1`, and the compositor imports its buffers with a
GPU renderer. X11 programs run in a rootful Xwayland inside their zone, from
an image of their own; the compositor never acts as an X window manager
([browser and graphics](design/browser-and-graphics.md)).

This amends ADR-004's cost: Xwayland, when built, is rootful and inside the
zone.

**Why:** Chromium's sandbox needs user namespaces or a setuid helper, which
zones refuse, so it would run without one; WebKitGTK's sandbox needs
bubblewrap for the same reason. Firefox degrades to its seccomp layer. A
render node exposes the GPU kernel driver, among the largest in the kernel,
to the zones most likely to be compromised; under ADR-002 that is every
zone's risk. Rootless Xwayland would make the compositor parse X11 from a
zone.

**Cost:** clang, libclang, Node.js and a WASI sysroot to build Firefox, and
hours of build time; video and WebGL on the CPU in browsing zones; the zone
filter answers `clone` and `unshare` with namespace flags with `EPERM`
instead of killing, so Firefox's start-up probe survives; popups, which the
proxy refuses since the desktop-boundary review, return for zones in a form
that cannot leave the zone's own window; a GPU zone, when one exists, brings
Mesa into the compositor.

**Rejected:** Chromium (no sandbox in a zone, clang only); a WebKitGTK
browser (its sandbox off in a zone); rootless Xwayland; copying GPU frames
into shared memory in the proxy (slow reads of write-combined memory).

## ADR-017 (proposed): The state partition may unlock from the TPM, for the exact kernel

A user may enrol the TPM to open the state partition without a prompt. The
key is a second LUKS2 keyslot, sealed by the TPM to a policy kept in an NV
index: PCR 4 (the exact signed kernel, whose compiled-in command line carries
the root hash) and PCR 7 (Kryptik's Secure Boot policy and certificate), for
the committed kernel and, during a trial, the kernel the updater predicted
from this boot's event log. `sysinit` unseals it from the verified root
through a salted session and then extends PCR 15, so nothing later in the
same boot can unseal it again. Every failure falls back to the passphrase,
whose keyslot is never removed
([TPM unlock](design/tpm-unlock.md)).

**Why:** with no initramfs, PCR 4 already names the kernel and the root, so
the binding needs no stub or extra measurement (ADR-014). PCR 7 alone would
let the install medium, signed by the same key, unseal the key from its root
shell, and would let every older kernel do the same.

**Cost:** the threat model changes: an enrolled machine boots to its login
prompt with the state partition open, and an attacker who can extract the
TPM's secrets reads it. The updater rewrites the NV policy for each trial;
a firmware or dbx update, a rollback and a wrong prediction each cost one
passphrase prompt; tpm2-tss and tpm2-tools join the image.

**Rejected:** PCR 7 alone (the medium and old kernels unseal); a policy
signed at release time (old kernels stay valid, a key more, and no
knowledge of each machine's firmware events); enrolment by default.

## ADR-018 (proposed): Builds are reproducible and checked; the first compiler is bootstrapped

Everything that ships is built so that two builds of one commit produce the
same bytes, signatures set aside: `SOURCE_DATE_EPOCH` is the commit's time,
the root image is made by the sysroot's own e2fsprogs in the chroot with a
fixed UUID, hash seed and salt, and the kernel's build identity and
randstruct seed are fixed. CI builds a commit twice, on two runner images,
weekly and for every tag, and compares the root image and the unsigned
kernels byte for byte. Releases sign their modules in a second pass, with a
key made for that build and thrown away, and publish the certificate and the
module signatures, so anyone can rebuild a release's root image exactly.
After that, a stage before stage 01 runs live-bootstrap from its hex0 seed,
and stage 01 is built by its compiler instead of the host's
([reproducible builds](design/reproducible-builds.md)).

**Why:** "built from source" means little while nobody can check that the
binary came from the source; and as long as the first compiler is the
host's, every later stage inherits whatever that compiler does.

**Cost:** a second full build for every comparison; the image's clock floor
becomes the commit's time instead of the build's (earlier, never later);
the randstruct seed is fixed, which costs a published kernel nothing; a
two-pass kernel build for releases; live-bootstrap's sources to pin and
hours of build in front of stage 01. The Rust toolchain stays a binary
(ADR-010).

**Rejected:** a long-lived module signing key (a second key that would let
its holder load kernel code on every machine); waiting for hash-based module
integrity before starting (it is in no released kernel).

## ADR-019 (proposed): The kernel is built with Clang for kernel CFI

Stage 05 builds the kernel and its modules with a pinned Clang, version 21
or later, from an LLVM stage built in the chroot and kept out of the image,
with `CONFIG_CFI=y`, `CFI_PERMISSIVE` and `CFI_AUTO_DEFAULT` off, and
`cfi=kcfi` on the command line. Userspace stays on GCC. The GCC plugin for
latent entropy is given up and recorded in the checker's accepted list, and
the size budget is measured again under its rule
([Clang kernel](design/clang-kernel.md)).

**Why:** a corrupted function pointer is among the commonest steps of a
kernel exploit, and a kernel privilege escalation breaks every zone
(ADR-002). Since Linux 6.18 the option is keyed on `-fsanitize=kcfi`, which
only Clang has in a released compiler.

**Cost:** an LLVM build of hours with a cache of its own (shared with the
browser's bindgen and Mesa when they come); linux-hardened built by a
compiler its main users do not use; latent entropy lost; a few percent more
kernel code; a second compiler to pin and review.

**Rejected:** waiting for GCC 17's kCFI (unreleased; when Kryptik's
toolchain reaches it, the kernel can return to GCC with no configuration
change); FineIBT by default (`cfi=auto`), which the hardening checker does
not accept.

## ADR-020 (proposed): Anonymity is a zone property, enforced by how the zone is wired

A zone file may give a routed zone an anonymous uplink: `uplink = "tor"` or
`uplink = "vpn"`. A Tor zone's only interface is a veth into a gateway zone
(`network.mode = "gateway"`, the shipped ephemeral `tor` zone) that runs Tor
alone, forwards nothing, and lets the anonymous zone reach only Tor's ports,
under rules kryptikd loads and the gateway cannot change. A VPN zone's only
interface is a WireGuard device created in the net zone's namespace, moved
into the zone and keyed from zone 0. Either way the zone has no clearnet
route, its DNS goes through the uplink, and it is left with loopback when
the uplink goes. The threat model changes first: anonymity becomes a
property a zone can have, with the limits the design lists
([anonymous uplinks](design/anonymous-uplinks.md)).

**Why:** the threat model calls anonymity a non-goal, and a design that
contradicts it changes it first. Tor in the net zone would hand the Tor
client to whoever compromises the zone that faces the local network; a
gateway zone keeps it one hop further in, as Whonix does. Fail-closed by
wiring holds when daemons crash; fail-closed by rules holds only while they
load.

**Cost:** a new network mode and a second bridge in kryptikd; a zone more
running whenever an anonymous zone does; Tor and WireGuard to build and keep
current; an anonymous zone still shares the kernel, the screen, the fonts
and the clock with every other zone.

**Rejected:** Tor in the net zone; userspace VPNs, which need a tun device
and `CAP_NET_ADMIN` in a zone; any setting on the state partition that could
give an anonymous zone a clearnet route.

## ADR-021 (proposed): Sound is mixed in zone 0; Bluetooth carries audio from a zone of its own; input methods run per zone

Sound drivers are built as signed modules, and Intel's SOF firmware comes
from the SOF project's releases, a second firmware source beside
linux-firmware. A mixer in zone 0, `kryptik-sound`, runs as its own user
and reads one fixed-format stream per zone (48 kHz, stereo, 16-bit) from a
socket kryptikd binds into the zone. A zone records only after a gesture in
the chrome grants it the microphone, one zone at a time, and the chrome
shows it. Bluetooth, when it comes, runs in a zone of its own with its own
bus, after a kernel patch lets one network namespace use `AF_BLUETOOTH`;
it carries audio only, never keyboards. Input methods run inside each zone,
and the compositor routes their keys and commits to that zone's surfaces
alone; the virtual keyboard is never offered to a zone
([the laptop](design/laptop.md)).

This amends ADR-013, which lists sound among what is never built, and
ADR-012, which leaves sound and Bluetooth firmware out.

**Why:** a fixed format leaves zone 0 nothing to parse, and the microphone's
gate stays in trusted code; a sound zone would gate the microphone from the
place an attacker controls. The kernel refuses Bluetooth sockets outside the
initial network namespace, and bluetoothd faces a radio and could type into
the chrome through uhid. An input method shared by all zones would learn
from every zone and offer one zone's words in another.

**Cost:** sound drivers, alsa-lib and a new daemon in zone 0; a firmware
source that is not linux-firmware; a Kryptik kernel patch for Bluetooth,
rebased with linux-hardened (ADR-009); no Bluetooth keyboards; compositor
work to route input methods by zone.

**Rejected:** PipeWire in zone 0 with a socket per zone; a sound zone;
bluetoothd in zone 0; one input method for all zones.

## ADR-022 (proposed): Suspend wipes the disk keys

Before the machine sleeps, the launch daemon locks the screen, freezes every
zone, and suspends the state partition and every open zone volume with
their keys wiped (`cryptsetup luksSuspend`). At resume the lock asks for the
state partition's passphrase, never the TPM, and each zone stays frozen
until its own passphrase is given. Everything on the resume path runs from
the verified root and `/run`. Hibernation stays off. The threat model
changes: a suspended machine holds no disk key, though memory still holds
what the zones were using ([the laptop](design/laptop.md#suspend-and-resume-with-the-keys-dropped)).

**Why:** a laptop is suspended far more often than it is off, and today a
suspended Kryptik keeps every key in RAM.

**Cost:** a passphrase at every resume, and one for each zone the user
wants back; a lock client in zone 0; zone 0 programs that touch `/var`
stall until resume.

**Rejected:** resuming with the TPM, which would let whoever holds the
machine resume it; keeping the state partition's key while dropping only
the zones' keys.

## ADR-023 (proposed): Slots grow at the end of the disk; beside another OS, Kryptik keeps its own ESP and boot entry

Slots default to twice the image or 4 GiB, whichever is larger. When a
release no longer fits, `check-manifest` refuses it before its image is
fetched, and `kryptik-recover --grow-slots` from the medium shrinks the state
partition at its end, creates two larger slots there and moves the
`kryptik-a` and `kryptik-b` labels to them in one GPT write; the old slots'
space stays unused. A release that needs this is a major version. Beside
another OS, the installer uses free space alone, makes an ESP of Kryptik's
own, and boots by a `Boot####` entry of its own instead of the
removable-media path; Kryptik's certificate sits in db beside Microsoft's.
Across disks, the state partition's identity is recorded on the ESP
([installer choices](design/installer-choices.md)).

**Why:** the slots are fixed at install time and every Version 2 item makes
the root larger. Moving the state partition's start would risk the
partition that holds everything; growing at the end moves no data, and the
signed kernels already find their slots by label. Sharing another system's
ESP would not leave room for Kryptik's kernels, and the removable path is
ambiguous with two ESPs on one disk.

**Cost:** about 3.4 GiB more disk at install; the old slots' space lost after
a migration; a medium step for the release that needs it. Beside another
OS, boot integrity also rests on everything Microsoft's keys sign and on a
current dbx, which the threat model must say, and enrolling Kryptik's
certificate sends Windows to its BitLocker recovery key once.

**Rejected:** moving the state partition's start; extending slots with a
linear table in the shared command line; a shared ESP; a boot loader to
choose between systems (ADR-014).

## ADR-024 (proposed): Zones reach the compositor through sockets it filters, by proxies that run as users of their own

dwl serves each zone on a socket of its own, offers it only the globals the
proxy allows (`wl_display_set_global_filter`), and takes a window's zone
from the socket, not from the app_id. Each zone's `kryptik-wlproxy` runs as
a uid of its own, outside groups `kryptik` and `seat`, under seccomp, with a
Landlock ruleset that grants no files, in an empty network namespace,
started by the launch daemon. Later, dwl runs as a `compositor` user and
confines itself after start-up, with commands run by a fixed spawner. Last,
Wayland parsing moves into the zones, and only pixels and input cross
([compositor separation](design/compositor-separation.md)).

**Why:** today every proxy runs as the login user and connects to dwl's own
socket, which offers screencopy, the virtual keyboard and layer-shell. A bug
in the parser zones reach first gives a zone the whole desktop, the consent
directory and the launch daemon, and lets it draw another zone's border.

**Cost:** changes to dwl (sockets per zone, the filter, then the sandbox
and a spawner); the launch daemon starts proxies and the compositor; uids
per zone; a crate shared by kryptikd and the proxy for seccomp and Landlock.
A compromised compositor still controls what the user sees and types.

**Rejected:** splitting dwl into an input process and a renderer, which
leaves the renderer drawing the borders and every zone talking to it.
