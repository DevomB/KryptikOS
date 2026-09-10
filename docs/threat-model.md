# Kryptik Threat Model

A security distribution that does not say what it fails against is not making a
security claim. This document is binding: if a design change violates something
here, the document changes first, in a reviewed commit.

## Assets

1. Long-term secrets (keys, credentials) — held in `vault`
2. Per-identity data (documents, history, cookies) — held in per-zone volumes
3. Identity separation itself — the fact that `work` and `personal` are not
   linkable is an asset independent of either zone's contents
4. Boot integrity — the guarantee that running code is the code that was signed

## Adversaries Kryptik defends against

### A1 — Malicious application

*Capability: arbitrary code execution as the user, inside one zone.*

**Defended.** This is the core case. The application sees only its own zone's
filesystem, cannot enumerate other zones' processes, has no route to the
physical NIC, and is confined by a default-deny seccomp filter and a Landlock
ruleset. Escaping requires a kernel bug (see L1).

### A2 — Malicious document or link

*Capability: exploits a parser in a viewer or browser.*

**Defended.** Opened in `untrusted`, which is ephemeral. Exploitation yields a
tmpfs overlay that is destroyed at teardown and a network path that is already
assumed hostile.

### A3 — Network attacker (passive or active, on-path)

*Capability: observes and modifies traffic.*

**Partially defended.** Kryptik does not provide anonymity — it is not Tails and
does not route through Tor by default. It provides *segmentation*: a compromise
of the `net` zone does not yield zone filesystem access or `vault` contents.
Confidentiality on the wire remains the application's responsibility.

### A4 — Opportunistic physical access ("evil maid", stolen laptop)

*Capability: offline access to the disk; boot from external media.*

**Defended at rest.** Per-zone LUKS2 volumes are meaningless without their
keys. dm-verity plus Secure Boot means a modified root filesystem or a swapped
kernel fails to boot rather than silently running.

**Not defended while running or suspended.** Keys are in RAM. See L3.

### A5 — Cross-zone data leakage through user error

*Capability: the user pastes the wrong thing into the wrong window.*

**Partially defended.** This is the failure mode that actually happens to real
people, which is why clipboard is brokered and per-zone window colors are
mandatory rather than cosmetic. Deliberate cross-zone paste remains possible —
by design, because a system that makes it impossible gets circumvented.

## Adversaries Kryptik does NOT defend against

### L1 — Kernel local privilege escalation

Every zone shares one kernel. A working LPE compromises all zones
simultaneously. Hardening (see [hardening.md](hardening.md)) raises the cost;
it does not eliminate the class.

**If this is your threat model, use Qubes OS.** Its Xen hypervisor gives a
smaller and genuinely separate trust boundary. Kryptik trades that away for
running on hardware you already own, at battery life you will tolerate. That
trade is the entire premise of the project, and it is not the right trade for
everyone.

### L2 — Firmware, hardware, and supply-chain implants

UEFI implants, Management Engine compromise, malicious microcode, or backdoored
silicon all sit beneath everything Kryptik controls. Secure Boot assumes the
firmware enforcing it is honest.

### L3 — Coercion, and access to a running or suspended machine

Keys live in RAM while zones run. Cold-boot and DMA attacks against a live or
suspended system are out of scope. Kryptik cannot help against rubber-hose
cryptanalysis, and no software can.

### L4 — Microarchitectural side channels

Shared caches and shared branch predictors permit cross-zone inference.
Mitigating this properly requires core scheduling or physical separation;
neither is implemented today. Treated as a known gap, not a solved problem.

### L5 — Targeted attack by a well-resourced state actor

Chained zero-days across kernel, compositor, and firmware defeat this design.
Kryptik raises cost substantially against commodity and criminal attackers. It
is not a defense against an adversary willing to spend seven figures on you
specifically.

### L6 — Traffic analysis and anonymity

Out of scope entirely. Kryptik separates identities on the host. It does not
hide that traffic originated with you. Compose with Tor or a VPN in the `net`
zone if you need that; Kryptik will not do it silently on your behalf.

## Non-goals

- **Anonymity.** That is Tails and Whonix. Different problem.
- **Offensive tooling.** Kryptik is a hardened workstation. Run Kali in a zone.
- **Amnesia by default.** Kryptik is a daily driver with persistent state.
- **Beginner friendliness.** The zone model imposes real workflow friction.
  Making it invisible would mean weakening it.
