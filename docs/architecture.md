# Kryptik Architecture

## The zone model

A **zone** is Kryptik's unit of isolation. Every process on the system belongs
to exactly one zone. There is no unzoned process except PID 1 and the
compartment manager.

A zone is defined by a tuple of:

| Component | Mechanism |
|---|---|
| Process isolation | user, pid, ipc, uts, mount, cgroup namespaces |
| Network isolation | dedicated net namespace + veth pair into a per-zone bridge |
| Filesystem isolation | dedicated LUKS2 volume, unlocked only while the zone runs |
| Syscall restriction | per-zone seccomp-bpf filter (default-deny allowlist) |
| Filesystem policy | Landlock ruleset applied at zone entry, unprivileged and unbypassable |
| Resource limits | cgroup v2 memory / cpu / pids / io limits |
| Visual identity | per-zone window border color and titlebar tag |

### Zone 0 — the trusted base

Zone 0 is the analog of Qubes' `dom0`. It runs:

- PID 1 and the service supervisor
- The compartment manager (`kryptikd`)
- The Wayland compositor
- The disk encryption layer

Zone 0 has **no network namespace with a route to the outside world** and runs
**no user applications**. Ever. If a user wants a browser, it goes in a zone.
This is the single most important invariant in the system — if it erodes, the
entire model collapses into "a Linux box with some containers on it."

### Default zone set

| Zone | Network | Storage | Purpose |
|---|---|---|---|
| `vault` | **none** (loopback only) | encrypted, persistent | keys, password store, secrets. No network stack at all — not firewalled off, but absent |
| `net` | full | ephemeral | the only zone holding a route to the physical NIC; other zones route through it |
| `work` | via `net` | encrypted, persistent | daily productivity |
| `personal` | via `net` | encrypted, persistent | separate identity, separate cookies, separate everything |
| `untrusted` | via `net` | ephemeral, wiped on exit | opening unknown files, sketchy links |
| `dev` | via `net` | encrypted, persistent | toolchains, build environments |

Zones are user-definable; the above is the shipped default, not a fixed list.

## Inter-zone communication

**Default: none.** Zones cannot see each other's processes, filesystems, IPC
objects, or network interfaces.

All cross-zone interaction goes through `kryptikd` as a policy-checked broker:

```
  zone A                    zone 0                     zone B
 ┌────────┐   AF_UNIX    ┌───────────┐   AF_UNIX    ┌────────┐
 │  app   │─────────────▶│ kryptikd  │─────────────▶│  app   │
 └────────┘   request    │  ┌─────┐  │   delivery   └────────┘
                         │  │policy│ │
                         │  └─────┘  │
                         │  ┌─────┐  │
                         │  │prompt│ │──▶ user confirmation
                         │  └─────┘  │
                         └───────────┘
```

Three brokered operations, and only three:

1. **File transfer** — one-way copy, explicit destination zone, user-confirmed.
   The source zone names a file; it never gets a handle into the target.
2. **Clipboard** — not shared. A copy in zone A stays in zone A until the user
   performs an explicit cross-zone paste gesture, which moves exactly one
   payload, once.
3. **Network** — zones do not touch the NIC. They get a veth into a bridge
   owned by the `net` zone, which is the sole holder of a physical route.

There is deliberately no general-purpose RPC, no shared D-Bus, and no shared
`/tmp`. Every additional channel is an additional confused-deputy risk, and
the model only works if the channel list stays short enough to audit.

## GUI isolation

The compositor runs in zone 0. Zoned applications do **not** get a socket to it
directly. Each zone gets a per-zone proxy socket that:

- strips clipboard access (routed through the broker instead)
- blocks screen capture of other zones' surfaces
- blocks global input grabs and keyboard-layout snooping
- tags every window with the zone's border color

The color is load-bearing, not decoration. If a user cannot tell at a glance
which zone a password prompt belongs to, compartmentalization has failed at the
only layer that matters — the human one.

## Storage

- Zone 0 root: dm-verity, read-only, signed. Tampering is detected at boot.
- Per-zone data: individual LUKS2 volumes, unlocked on zone start, closed and
  key-wiped on zone stop.
- Ephemeral zones (`untrusted`): tmpfs overlay, discarded at teardown.
- No shared writable mount exists between any two zones.

## Boot chain

```
UEFI Secure Boot
  → signed shim
  → signed bootloader
  → signed kernel + baked-in initramfs
  → dm-verity root (signature checked)
  → kryptikd
  → zone 0 compositor
```

The initramfs is embedded in the kernel image so it falls inside the signature.
An unsigned initramfs is an unmeasured initramfs, and an unmeasured initramfs
means the verity root hash can be swapped.

## Known weaknesses

Stated up front, because a security architecture that only lists its strengths
is marketing:

- **Shared kernel.** A kernel LPE breaks every zone at once. Qubes survives this
  class of bug; Kryptik does not. This is the price of running on ordinary
  hardware. See [threat-model.md](threat-model.md).
- **Shared compositor.** A compositor RCE reaches zone 0.
- **Side channels.** Shared CPU caches mean cross-zone side channels are
  possible and are not currently mitigated.
- **`net` zone is a chokepoint.** It sees all traffic. Compromising it yields a
  network-wide vantage point, though not zone filesystem access.
