# Audit scope

What an outside auditor of Kryptik's boundary gets: the boundary on one page,
the entry points an attacker actually has, the documents that set the
limits, what earlier reviews found, how to build and test everything without
the maintainer, the known gaps, and what is out of scope. The
[roadmap](roadmap.md#housekeeping) asks for an independent audit of the
whole boundary, published.

Audit a tagged release, or main at a named commit. The tree is all there is:
everything below is built from it by the workflows in `.github/workflows/`.

## The boundary on one page

| Part | What it enforces | Code | Tests | Design |
| --- | --- | --- | --- | --- |
| Zone launch | user, pid, mount, ipc, uts, cgroup and network namespaces; uid maps from a declared range; a sealed tmpfs root with the system paths bound read-only; supervision by parent-death signals | `compartments/kryptikd/src/spawn.rs`, `isolate.rs`, `rootfs.rs`, `zone.rs`, `caps.rs` | `compartments/tests/launcher.sh`, `adversarial.sh`; `build/guest-tests/zones-check.sh` | [privileged launch](design/privileged-launch.md), [zone registry](design/zone-registry.md) |
| Syscall filter | default-deny seccomp-bpf, about 200 calls, argument rules on `clone`, `ioctl`, `socket`; kill on the rest | `seccomp.rs`, `policy.rs`, `compartments/zones/policy/` | `seccomp.rs` unit tests, the boundary suite | [hardening](hardening.md#zone-syscall-filter), [zone policy files](design/zone-policy-files.md) |
| File access | Landlock over the pivoted root: read and exec on `/`, write only in home, `/tmp`, `/dev` nodes, `/proc` | `landlock.rs` | `landlock::tests`, the launcher suite | [zone policy files](design/zone-policy-files.md) |
| Resources | cgroup v2 leaves with memory, pids, cpu and io limits; ephemeral homes on a bounded tmpfs | `cgroup.rs`, `rootfs.rs` | the launcher suite's cgroup sections | [resource limits](design/resource-limits-and-ephemeral-zones.md) |
| Encrypted volumes | a LUKS2 volume per persistent zone, open only while it runs | `volume.rs` | `volume.rs` tests, `zones-check.sh` | [encrypted volumes](design/encrypted-volumes.md) |
| The net zone | sole holder of the NICs; isolated bridge ports; NAT and a resolver; Wi-Fi credentials | `netzone.rs`, `netlink.rs`, `wifi.rs`, `tools/net/netzone-init.sh` | `netzone.rs`, `netlink.rs` tests; `zones-check.sh` | [net zone](design/net-zone.md) |
| The broker | one socket per zone, identity by peer uid; clipboard, consented file transfer; time and update verbs for the net zone alone | `broker.rs`, `consent.rs`, `serve.rs`, `tools/desktop/kryptik-chrome` | `broker::tests` with a fuzz corpus, `compartments/tests/serve.sh`, `tools/tests/chrome-confirm.py`, `gui-check.sh` | [broker](design/broker.md), [clock](design/time.md) |
| The desktop boundary | one Wayland proxy per zone offering eight globals, app_id and title rewritten; dwl drawing zone borders | `compositor/wlproxy/`, `compositor/zoneid/`, `tools/desktop/dwl-zone-borders.py`, `build/desktop/dwl-config.h`, `tools/desktop/kryptik-launch.c` | `make test-compositor`, `make gui-test` | [architecture](architecture.md#gui), [broker](design/broker.md#compositor-proxy) |
| Boot | the signed kernel as the EFI application with its command line and root hash compiled in; dm-verity root; no initramfs | `build/stages/05-kernel.sh`, `06-iso.sh`, `06-kernel-bind.sh`, `build/config/kernel/` | `make integrity-test`, `media-smoke`, `media-refused-foreign-keys` | [boot and updates](design/boot-and-updates.md) |
| State encryption | LUKS2 state partition on the root's disk; `/etc` overlay allow-list; degraded state | `build/service-scripts/sysinit.sh`, `devices.sh`, `ask.sh` | `make state-test`, `install-test` | [state encryption](design/state-encryption.md) |
| Installer and recovery | whole-disk install with every check before the first write; slot and header recovery from the medium | `tools/install/kryptik-install.sh`, `tools/update/kryptik-recover` | `make install-test`, `tools/tests/installer.sh` | [boot and updates](design/boot-and-updates.md#installer) |
| Update chain | a signed manifest checked before any write; A/B slots with a judged trial; a channel fetched by the hostile net zone and bounded by zone 0 | `tools/update/kryptik-update`, `tools/efi/kryptik-efiboot.c`, `build/service-scripts/boot-success.sh`, `update.rs`, `tools/net/update-fetch.py`, `tools/release-manifest.sh`, `tools/release-channel.sh` | `make update-test`, `tools/tests/update-*.sh`, `release-*.sh` | [boot and updates](design/boot-and-updates.md#updates), [update channel](design/update-channel.md) |
| Release signing | keys made offline, a build that signs only with a key medium it is handed, namespaces per key; development releases signed by throwaway keys in CI; the statement key in a repository secret for the channel workflow | `build/lib/release-keys.sh`, `.github/workflows/distro.yml`, `channel.yml`, `tools/channel-host.sh` | `tools/tests/release-keys.sh`, the production acceptance suite | [release keys](release-keys.md), [releases](releases.md) |

kryptikd is about 12,600 lines of Rust with 5,300 lines of tests beside it,
`kryptik-wlproxy` about 1,900 and `zoneid` about 1,600; the rest is C and
shell named above. The hardening applied to everything else is in
[hardening](hardening.md); the kernel configuration is three fragments
under `build/config/kernel/`.

## Entry points

**From inside a zone** (code execution as the zone's root, which is host
uid N with no capabilities in the initial namespace):

- the kernel, through the syscalls the zone's filter allows, and the
  devices in its `/dev` (null, zero, full, random, urandom, tty, its own
  devpts);
- its broker socket at `/run/kryptik/broker`: `version`, `clipboard-set`,
  `clipboard-get`, `transfer` with one descriptor;
- its Wayland proxy socket at `/run/kryptik/wayland-0`, every message of the
  eight globals it is offered;
- its veth into the net zone's bridge: the net zone's resolver, NAT, and
  whatever the net zone forwards;
- what it can read: zone 0's `/usr` read-only, a masked `/proc`, a minimal
  `/sys`, the few `/etc` files `rootfs.rs` lists.

**From inside the net zone**, which is treated as hostile: everything above
except a display, plus `CAP_NET_ADMIN` and `CAP_NET_RAW` in its own
namespace, packet and netfilter and generic netlink sockets, every routed
zone's traffic, the Wi-Fi credentials file, and the broker's `time-offset`,
`update-latest`, `update-poll` and `update-put` verbs, which reach zone 0's
clock and update state.

**From the local network or radio:** the NIC and Wi-Fi drivers' parsing in
the kernel, and dhcpcd, wpa_supplicant and dnsmasq in the net zone.

**With the disk in hand:** the ESP (FAT, unauthenticated; the kernels on it
are signed), the root slots (dm-verity), the state partition (LUKS2 with
XTS: damage is possible, chosen plaintext is not), its header in the clear,
and control disks, which arm an unattended install only when the medium's
`kryptik-testctl` key signed them.

**Through the release path:** the release host and the channel's pointer
and payload, all verified against the anchor on the verified root; the
workflows that build, test and publish; the repository secret that holds
the statement key.

## What sets the limits

- [The threat model](threat-model.md): the assets, the adversaries defended
  against and those that are not.
- [The decisions](decisions.md): ADR-002 (namespaces, not a hypervisor: a
  kernel privilege escalation breaks every zone), ADR-003 (zone 0 runs no
  user application), ADR-004 (Wayland only), ADR-005 (hardened_malloc),
  ADR-006 (s6, no systemd), ADR-007 (Landlock and seccomp, no other MAC),
  ADR-009 (longterm kernel with linux-hardened), ADR-010 (kryptikd in Rust),
  ADR-011 (SMT off), ADR-012 (vendor firmware on the verified root), ADR-013
  (what is built into the kernel), ADR-014 (the signed kernel is the whole
  boot chain). Records marked proposed are not decisions yet.
- [The architecture](architecture.md), including its known weaknesses.

## Earlier reviews by someone who did not write the code

The [roadmap](roadmap.md) names four reviews, each by someone other than
the author, with their findings fixed:

- **kryptikd's launch path.** Found: a transfer copied up to the cap after
  the user had been shown a smaller size; an ephemeral zone's leftover file
  names reached the operator's terminal unescaped, and names that were not
  UTF-8 were not counted; zone pid 1 carried on unsupervised if the
  intermediate died before pid 1 armed its parent-death signal; a failed
  detach of the sysfs mounted aside was ignored; and a zone could read the
  per-line interrupt and context-switch counts. Each is fixed, and the
  broker and launch designs describe the result.
- **The update chain.** Nothing above low: a slot being rewritten could still
  be named on the ESP after a cut write; the commit kept no firmware entry
  of its own; `kryptik-efiboot` could take another system's entry by its
  number. Fixed: a slot being rewritten is named by nothing on the ESP, the
  committed slot keeps an entry, and entries are recognised by description
  and file. The net zone's place in the trial's health check was kept, with
  its reason recorded ([boot and updates](design/boot-and-updates.md#updates)).
- **The broker.** Medium: the consent window took keys typed before it
  appeared, so a zone could time a request under the user's typing. Low: no
  pause after a refusal. Fixed: the window drops what was typed in its first
  second and answers yes only to a code it shows; a refused zone may not ask
  again for a minute, and only a question the user saw pauses the next
  ([broker](design/broker.md#consent)).
- **The desktop boundary.** High: a zone's floating and fullscreen windows
  could be placed in layers above zone 0's windows, without borders. Medium:
  mapping a window took focus from another zone. Medium: shared-memory pools
  could exhaust memory. Fixed in dwl's change and the proxy: zone clients
  stay out of the layers above trusted windows, mapping does not move focus
  across zones, and pools are bounded per connection and per zone. Whether
  the compositor's share of that memory is charged to the zone's cgroup is
  still a measurement to make
  ([resource limits](design/resource-limits-and-ephemeral-zones.md#tests)).

The broker's request parser and the proxy's wire parser have seeded mutation
tests with corpora in the tree. Coverage-guided fuzzing is not run.

## Building and testing without the maintainer

Everything runs on GitHub's runners, so a fork is enough:

- **CI** (`.github/workflows/ci.yml`) runs on every push and pull request:
  commit identity, shell lint and syntax, the tool suites, the source
  manifest with strict signature and provenance gates, kryptikd's and the
  compositor's unit tests, the compartment suites unprivileged, and the
  kernel configuration checks.
- **Distro** (`.github/workflows/distro.yml`) builds stages 01 to 06 from
  source and runs every acceptance suite under QEMU with OVMF and KVM on the
  exact images. Start it with "Run workflow" (`workflow_dispatch`), as a
  development build or as a production one signed with a throwaway key
  medium. Its `acceptance-report` artifact holds `REPORT.md`, one row per
  item, `results.tsv`, and every item's log and serial transcript
  ([status](status.md#the-last-full-pass)). A run from no cache takes about
  three hours.
- **Locally**, [building](building.md) lists the host packages and stages;
  `make test` and `make zone-tests` need no build, and `make acceptance`
  needs KVM and two built releases.

## Known gaps

From [status](status.md#known-gaps) and the designs' own lists:

- Nothing has run on physical hardware.
- The production keys have not been made; every release so far is signed by
  a key its build generated.
- The watchdog resets a machine that has stopped, not a crashed service or a
  frozen desktop.
- Builds are not reproducible, and the first compiler is the host's
  ([supply chain](supply-chain.md#open-problems)).
- dhcpcd runs without its own privilege separation; the net zone is its
  sandbox.
- Every `kryptik-wlproxy` runs as the login user and connects to the
  compositor's own socket, which offers capture and input injection, so a
  bug in a proxy would reach the whole desktop.
- The artifact audit's soft findings, each with its reason in
  `build/config/artifact-accepted.txt`.
- The net zone's "not built" list: no MAC or IP pinning on bridge ports, and
  routed zones may address the uplink's own addresses
  ([net zone](design/net-zone.md#not-built)).

## Out of scope

- **Kernel bugs as a class.** A kernel privilege escalation breaks every
  zone (ADR-002). How Kryptik configures and confines the kernel is in
  scope; finding bugs in Linux is not.
- **Firmware, hardware, microcode and vendor device firmware** (ADR-012).
- **Microarchitectural side channels** beyond the SMT decision (ADR-011).
- **A running or suspended machine's memory**, coercion, and cold-boot or
  DMA attacks on a running machine.
- **Traffic analysis and anonymity**, which the threat model does not claim.
- **Upstream packages' own code** (glibc, the GNU tools, wlroots, dwl
  itself), except where Kryptik patches them, configures them or exposes
  them to a zone.
- **GitHub's infrastructure**, beyond what the workflows ask of it.

## What the report should give

Each finding with the commit, the file and line, what an attacker in which
position gains, how to reproduce it, and its severity. A summary that can be
published as it stands. Fixes land as reviewed changes that cite the
finding, and the roadmap's housekeeping item is closed by the published
report and the fixes.
