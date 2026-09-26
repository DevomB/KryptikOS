# Threat model

What Kryptik defends against, and what it does not. A design change that
contradicts this document changes the document first.

## Assets

1. Long-term secrets (keys, credentials), held in `vault`.
2. Per-identity data (documents, history, cookies), held in per-zone volumes.
3. Identity separation: that `work` and `personal` cannot be linked is an
   asset apart from either zone's contents.
4. Boot integrity: the code running is the code that was signed.

## Adversaries Kryptik defends against

### Malicious application

*Capability: arbitrary code execution as the user, inside one zone.*

**Defended.** The application sees only its own zone's files and processes, has no route to the physical NIC, and runs under a
default-deny seccomp filter and a Landlock ruleset. Its `/proc` hides the
machine-wide interrupt and scheduling counters, which would time keystrokes
typed in any zone, and gives it a boot ID of its own. Escaping needs a kernel
bug ([kernel local privilege escalation](#kernel-local-privilege-escalation)).

### Malicious document or link

*Capability: an exploit for a parser in a viewer or browser.*

**Defended.** Opened in `untrusted`, which is ephemeral. The exploit gets a
tmpfs home that is freed when the zone stops, and a network path that is
already assumed hostile.

### Network attacker

*Capability: observes and modifies traffic, passively or on-path.*

**Partially defended.** Kryptik segments; it does not anonymize. A compromised
`net` zone gets no zone's files and not `vault`. Confidentiality on the wire
is the application's job.

### Offline physical access

*Capability: the disk in hand, an evil maid, a stolen laptop; booting external
media.*

**Defended at rest against a reader, not against a writer of the state
partition.** dm-verity and Secure Boot make a modified root or a swapped kernel
fail to boot. The state partition (`/home`, `/var`, the Wi-Fi passphrases, the
shadow file, the `/etc` overlay, the zone volumes' headers) is LUKS2 with a
passphrase at every boot, and the zone volumes inside it are encrypted again;
a stolen disk gives up none of it. It is not authenticated: someone holding
the disk cannot choose what a block decrypts to, but can damage blocks or
destroy the header, so what the system honours from `/etc` without asking is
limited to a list on the verified root
([state partition](design/state-encryption.md)). The ESP, the root slots and
the LUKS header are in the clear, so the disk shows it is Kryptik.

**Not defended while running or suspended.** Keys are in RAM; see
[coercion, and access to a running or suspended machine](#coercion-and-access-to-a-running-or-suspended-machine).

### User error across zones

*Capability: the user pastes the wrong thing into the wrong window.*

**Partially defended.** This is the failure that actually happens, which is
why the clipboard is brokered and zone borders are mandatory. A deliberate
cross-zone paste stays possible, because a system that forbids it gets
circumvented.

## Adversaries Kryptik does not defend against

### Kernel local privilege escalation

Every zone shares one kernel, so a working LPE compromises all of them at
once. [Hardening](hardening.md) raises the cost; it does not remove the class.

**If this is your threat model, use Qubes OS.** Its Xen hypervisor is a
smaller, separate trust boundary. Kryptik gives that up to run on hardware you
already own, at battery life you will tolerate (ADR-002).

### Firmware, hardware and supply-chain implants

UEFI implants, a compromised Management Engine, malicious microcode and
backdoored silicon sit below everything Kryptik controls. Secure Boot assumes
the firmware enforcing it is honest, and device firmware and microcode ship as
vendor binaries (ADR-012).

### Coercion, and access to a running or suspended machine

Keys are in RAM while zones run. Cold-boot and DMA attacks on a running or
suspended machine are out of scope, and no software helps against coercion.

### Microarchitectural side channels

Shared caches and branch predictors allow cross-zone inference. The signed
command line carries `nosmt`, so no two zones share a core's threads; if SMT
were turned back on, each zone would need a core-scheduling cookie of its own
to start (ADR-011 in [decisions](decisions.md); the cost of `nosmt` on real
hardware is not yet measured). Caches and predictors shared between cores, and
between a zone and the kernel, remain a known gap.

### Well-resourced targeted attack

Chained zero-days across kernel, compositor and firmware defeat this design.
Kryptik raises the cost substantially for commodity and criminal attackers,
not for an adversary willing to spend seven figures on you specifically.

### Traffic analysis

Out of scope. Kryptik separates identities on the host; it does not hide that
traffic came from you, and it ships no Tor or VPN uplink.

## Non-goals

- **Anonymity**: that is Tails and Whonix.
- **Offensive tooling**: Kryptik is a hardened workstation; run Kali in a zone.
- **Amnesia by default**: Kryptik is a daily driver with persistent state.
- **Beginner friendliness**: the zone model imposes real friction, and hiding
  it would weaken it.
