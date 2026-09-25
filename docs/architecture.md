# Architecture

## Zones

A zone is the unit of isolation, and every process belongs to exactly one.

| Component | Mechanism |
| --- | --- |
| Processes | user, pid, ipc, uts, mount and cgroup namespaces |
| Network | own namespace; routed zones get a veth into the `net` zone's bridge |
| Files | own root; persistent zones get a LUKS2 volume |
| Syscalls | seccomp-bpf, default-deny allowlist |
| File access | Landlock |
| Resources | cgroup v2 memory and pids limits |
| Identity | border colour and pattern, titlebar glyph and label |

### Zone 0

The trusted base, like Qubes' `dom0`: PID 1, the services, kryptikd, the
compositor and the desktop session. It has no route out and runs no user
applications (ADR-003). kryptikd creates the other zones as root; unprivileged
user namespaces are off ([privileged launch](design/privileged-launch.md)).

### Shipped zones

Defined in `compartments/zones/`, installed on the verified root.

| Zone | Network | Storage | Purpose |
| --- | --- | --- | --- |
| `vault` | none (loopback) | encrypted | keys, passwords, secrets |
| `net` | owns the physical NICs | ephemeral | the only route out |
| `work` | via `net` | encrypted | daily work |
| `personal` | via `net` | encrypted | a separate identity |
| `untrusted` | via `net` | ephemeral | unknown files and links |
| `dev` | via `net` | encrypted | toolchains, builds |

## Between zones

Nothing crosses by default. The broker in kryptikd identifies a caller by its
socket's peer uid and carries two things ([broker](design/broker.md)): a file
transfer, one file one way to a zone the sender's policy names, after the user
approves it; and the clipboard, one per zone, moved between zones only by a
user gesture in zone 0.

Routed zones reach the network through isolated ports on the `net` zone's
bridge. The `net` zone can also send zone 0 a clock offset and releases, both
treated as untrusted ([time](design/time.md),
[update channel](design/update-channel.md)). There is no general RPC, shared
D-Bus or shared `/tmp`: every channel is a confused-deputy risk.

## GUI

No zone can reach the compositor's socket. A zone started from the desktop
gets its own `kryptik-wlproxy`, which hides the capture, clipboard,
input-injection and similar Wayland globals and stamps each window with its
zone; the compositor draws the zone's border and title prefix from that.

The border is load-bearing, not decoration: if a user cannot tell at a glance
which zone a password prompt belongs to, compartmentalization has failed.
`zoneid audit` checks that every pair of zones stays distinguishable.

## Storage

- **Root**: dm-verity, read-only. A modified block panics the kernel when read.
- **State partition** (`/var`, `/home`, the `/etc` overlay, zone volumes):
  LUKS2, unlocked at boot ([state encryption](design/state-encryption.md)).
- **Persistent zones**: a LUKS2 volume each, open only while the zone runs
  ([encrypted volumes](design/encrypted-volumes.md)).
- **Ephemeral zones**: a size-bounded tmpfs home, freed with the zone.
- No swap, and no writable mount shared by two zones.

## Boot chain

```text
UEFI Secure Boot
  → signed kernel, run directly by the firmware (EFI stub)
  → compiled-in command line: root slot, verity root hash and salt
  → dm-init builds the dm-verity root; no initramfs
  → s6-rc, kryptikd, compositor
```

With the command line compiled in (`CMDLINE_OVERRIDE`), the kernel's signature
covers the root hash, and there is no boot loader or initramfs to swap it
([boot and updates](design/boot-and-updates.md)).

## Known weaknesses

- **Shared kernel.** A kernel privilege escalation breaks every zone
  ([threat model](threat-model.md)).
- **Shared compositor.** Code execution in it reaches zone 0.
- **Side channels.** SMT is off (ADR-011); caches and predictors shared
  between cores, and with the kernel, remain.
- **The `net` zone is a chokepoint.** It sees all traffic and the Wi-Fi
  passphrases, and once compromised can route between zones, but it reaches
  no zone's files.
