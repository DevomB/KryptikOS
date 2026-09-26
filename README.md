# Kryptik

A from-scratch Linux distribution built on two commitments:

1. **Nothing runs uncompartmentalized.** Every application lives inside a named
   security zone with its own namespaces, filesystem, network path, and policy.
   There is no "just run it on the host" escape hatch.
2. **Every binary is hardened before it ships.** Hardening is a property of the
   toolchain, not a package you install afterward. If it is in the image, it was
   compiled with the full mitigation set.

Kryptik is built from source via Linux From Scratch, with no upstream distro
base. Its binaries carry their own target triple:

```
$ sysroot/usr/bin/bash --version
GNU bash, version 5.2.32(1)-release (x86_64-kryptik-linux-gnu)
```

## Status

Pre-alpha. The build produces a hardened kernel with the linux-hardened
patchset; install media (a USB image and an ISO) that boot by UEFI firmware
alone; an installer; an installed system that verifies its root with
dm-verity on every boot and keeps its state on an encrypted partition; A/B
updates with a judged trial boot and recovery from the medium; and a zoned
Wayland desktop. `make acceptance` runs every suite against the built images.

What is tested, and what the last acceptance run proved, is in
[docs/status.md](docs/status.md). Everything so far has run under QEMU with
OVMF firmware; nothing has run on physical hardware, and releases are signed
by a key the build generates.

## Hardware

x86-64 with UEFI firmware. There is no initramfs, so the storage controller
the root sits on must be compiled into the signed kernel; everything else can
be a signed module (`build/config/kernel/boot.fragment`, ADR-013). Drivers
that need vendor firmware are modules, loaded once the verified root supplies
the firmware from the pinned linux-firmware release
(`build/config/firmware.list`, ADR-012).

- **Storage:** NVMe (including Intel VMD), AHCI and PIIX SATA, eMMC and SD on
  SDHCI, LSI MegaRAID and MPT3 SAS, HPE Smart Array, USB mass storage and UAS,
  virtio, VMware PVSCSI, Hyper-V.
- **Wired network:** Intel e1000/e1000e, igb, igc, ixgbe, i40e; Broadcom tg3
  and bnxt; Realtek r8169; Aquantia AQtion; Mellanox ConnectX-4 and later;
  USB adapters (AX88179, RTL8152); virtio, VMware vmxnet3, Hyper-V.
- **Wi-Fi:** Intel from the 7260 on; Qualcomm QCA6174, QCA9377, QCA6390,
  WCN6855, WCN7850; MediaTek MT7921, MT7922, MT7925; Realtek rtw88, rtw89 and
  rtl8xxxu; Broadcom over PCIe. The net zone owns the radio
  ([net zone design](docs/design/net-zone.md)). No Bluetooth.
- **Display:** the firmware framebuffer (simpledrm) everywhere; Intel (i915,
  xe) and AMD (amdgpu) with their firmware; ASPEED and Matrox server BMCs;
  virtio-gpu, VMware SVGA, Hyper-V. NVIDIA machines use the firmware
  framebuffer. The compositor renders with pixman, so no GPU acceleration is
  needed.
- **Input:** USB HID, PS/2, I2C touchpads and touchscreens on Intel and AMD
  laptops, VMware and Hyper-V input.

CPU microcode for Intel and AMD is built into the signed kernel. Hyper-V
trusts only Microsoft's keys, so run Kryptik there with Secure Boot off.

A machine outside that list boots a kernel that cannot find its disk or its
network. Adding a driver is one line in the fragment, a firmware file one line
in the list.

## What a zone does

`kryptik` is the command; `kryptikd` is what it calls. A zone has its own pid
namespace and hostname, and sees four processes where the host has 142:

```
$ kryptik run untrusted -- /bin/sh -c \
    'echo pid=$$; echo host=$(hostname); echo procs=$(ls /proc | grep -c "^[0-9]*$")'
kryptikd: zone "untrusted": ephemeral storage is a tmpfs freed on exit; its pages can reach swap, so this is not secure erasure
pid=1
host=untrusted
procs=4
```

A zone with `storage.mode = "encrypted"` lives on its own LUKS2 volume and
asks for its passphrase when it starts; the passphrase reaches the daemon on a
file descriptor, never on a command line. `kryptikd explain <zone>` prints the
whole boundary (namespaces, Landlock rules, the synthesized `/etc`, the `/dev`
node list, the environment allowlist, the syscall count) without starting
anything.

Files cross zones only through the broker socket inside the sending zone, in a
direction the zone's policy allows, after the user answers the question the
trusted chrome shows. Each zone has its own clipboard; one payload moves when
zone 0 asks for it through the chrome's menu.

## Why this exists

| Distro | Model | Gap Kryptik targets |
| --- | --- | --- |
| **Qubes OS** | Xen paravirtualization, per-app VMs | Requires VT-x/VT-d and heavy hardware; poor laptop battery life; GPU passthrough is painful |
| **Tails** | Amnesic live system, Tor-routed | Stateless by design, so not a daily driver |
| **Kali / Parrot / BlackArch** | Offensive tooling collections | Tooling on a normal, unhardened base |
| **Whonix** | Two-VM Tor gateway | Network anonymity only, not general compartmentalization |

Kryptik aims for Qubes-style isolation with kernel primitives instead of a
hypervisor: namespaces, cgroups v2, Landlock, seccomp and per-zone encrypted
storage. That is weaker than a hypervisor, since a shared kernel is a shared
attack surface, but it runs on ordinary hardware with ordinary battery life.
The tradeoff is spelled out in [docs/threat-model.md](docs/threat-model.md).

## Repository layout

```
build/
  stages/           Ordered build stages (00-host-check → 06-iso)
  config/           Pinned versions, hardening flags, kernel config fragments
  patches/          Patch sets with provenance (glibc-2.40/, util-linux-2.42.3/)
  services/         The s6-rc service tree
  service-scripts/  What those services run
  desktop/          dwl config and the zone colour table
  guest-tests/      Checks that run inside the installed system
  lib/              Shared shell helpers
compartments/
  kryptikd/         The compartment manager (Rust): zones, volumes, broker, launch daemon
  zones/            The shipped zones and their policy
  tests/            adversarial.sh (primitives), launcher.sh, cli.sh, serve.sh
compositor/
  wlproxy/          kryptik-wlproxy, the per-zone Wayland proxy
  zoneid/           Zone colour identity
tools/
  acceptance.sh     Every acceptance suite, one verdict
  image/            Stage 06 helpers, the OVMF runner, the VM drivers
  install/          kryptik-install
  update/           kryptik-update and kryptik-recover
  efi/              kryptik-efiboot, the firmware side of the A/B trial boot
  desktop/          kryptik-session, kryptik-chrome, kryptik-launch, the dwl patch
  net/              The net zone's setup
  git-hooks/        The pre-commit and pre-push hooks
docs/               Architecture, threat model, decisions, status
  design/           One document per part of the system
```

## Building

The `Distro` workflow (`.github/workflows/distro.yml`) builds and tests
everything on GitHub's runners: stages 01–02, then stages 04–06, then
`make acceptance` under KVM, uploading the acceptance report and the tested
images. To build locally, on Linux:

```sh
make check      # what the host is missing
make sources    # fetch and verify upstream tarballs
make toolchain  # stage 01: cross toolchain       (unprivileged)
make temp-tools # stage 02: temporary tools       (unprivileged)
make system     # stage 04: base system, in the chroot (needs root)
make kernel     # stage 05: hardened kernel
make media      # stage 06: install media and the signed release payload
```

```sh
make test                   # every host-side suite; no build, no root
make acceptance EXPORT=DIR  # every suite on the newest media; root and KVM
```

Host setup: [docs/building.md](docs/building.md). Booting, installing,
updating and recovering a release: [docs/user-guide.md](docs/user-guide.md).

## Documentation

- [Architecture](docs/architecture.md): the zone model
- [Threat model](docs/threat-model.md): what Kryptik defends against, and what it does not
- [Hardening](docs/hardening.md): toolchain and kernel hardening
- [Decisions](docs/decisions.md): architecture decision records
- [Supply chain](docs/supply-chain.md): source integrity and its gaps
- [Status](docs/status.md): what is tested and what the last run proved
- [Roadmap](docs/roadmap.md): what remains for 1.0 and 2.0
- [Building](docs/building.md) and the [user guide](docs/user-guide.md)

Designs of the individual parts:

- [Privileged launch](docs/design/privileged-launch.md): starting a zone as root on the Kryptik kernel
- [Resource limits and ephemeral zones](docs/design/resource-limits-and-ephemeral-zones.md): cgroup limits, supervision, crash cleanup, tmpfs zones
- [Zone registry](docs/design/zone-registry.md): persistent zone lifecycle, `stop`, concurrency
- [Zone policy files](docs/design/zone-policy-files.md): per-zone seccomp additions
- [Net zone](docs/design/net-zone.md): the only zone that holds the NIC
- [Encrypted volumes](docs/design/encrypted-volumes.md): per-zone LUKS2 volumes and their keys
- [Broker](docs/design/broker.md): file transfer, clipboards and the trusted desktop boundary
- [Time](docs/design/time.md): keeping the clock right without a network in zone 0
- [Boot and updates](docs/design/boot-and-updates.md): firmware boot, A/B slots, signed updates, recovery
- [Update channel](docs/design/update-channel.md): fetching releases through the net zone
- [State encryption](docs/design/state-encryption.md): the encrypted state partition

## License

GPL-2.0-or-later for Kryptik's own tooling. Built packages keep their upstream
licenses. See [LICENSE](LICENSE).
