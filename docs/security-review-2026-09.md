# Claude handoff: adversarial review of KryptikOS

Work in `C:\Coding-Projects\Linux Distro`. Review the real implementation and
fix reproducible security defects. Do not use Tectonix. Do not commit, push,
publish, or disturb another session's changes. First inspect `git status`,
the current revision, applicable instructions, and the diff. Read the actual
callers before changing a shared helper. Use existing dependencies and tests.

## Evidence and scope

The previous review's changes are present in revision `42bf4f7`: fail-closed
`/etc` upper-layer pruning, Wayland descriptor ownership and resource limits,
window-title control-character filtering, and the browser launcher correction.
Earlier commits added update-manifest snapshot verification, initial Wayland
identity stamping, CI private-key exclusions, acceptance-gated release upload,
and OpenSSL 3.5.8. Verify these against the current tree; do not report them as
new discoveries or assume their tests establish complete protection.

A further local change in `compartments/kryptikd/src/broker.rs` bounds socket
response writes. Before the fix, requesting a full clipboard without reading
the response held the zone supervisor in a blocking `send`. Its new socketpair
regression failed before the fix. Preserve it and inspect sibling paths.

The supplied build schedule and old acceptance-suite counts are historical. A successful
build or unit test is not boot, isolation, physical-hardware, or release proof.
Keep every media result tied to its commit, image digest, and exported report.

Read `docs/threat-model.md`, `docs/architecture.md`, `docs/design/`,
`docs/hardening.md`, `docs/supply-chain.md`, and the implementations below.
Some design documents lag the code: for example, Design 05a still describes
the consent prompt as unbuilt, although `consent.rs` and `kryptik-chrome` exist.

## Highest-value investigations

These are investigation leads, not established exploits. Establish attacker
capabilities and a reachable path before assigning severity.

1. **Consent channel crossing from session user to root.** Inspect
   `compartments/kryptikd/src/consent.rs`,
   `tools/desktop/kryptik-chrome`, and `build/service-scripts/sysinit.sh`.
   The root broker writes predictable PID/counter question names using
   `std::fs::write` in a group-writable directory. Investigate symlink/hardlink
   preplacement, stale answers and PID reuse, FIFOs that bypass deadlines,
   oversized answers, watcher-lock replacement, and session teardown.
   Distinguish the authority to approve a transfer from authority to overwrite
   arbitrary root-owned files. Prove any local-user escalation using separate
   UIDs and harmless temporary victims. Do not describe this directory as
   directly accessible from a zone unless you demonstrate that access.

2. **Broker, launcher, and proxy denial of service.** Inspect `broker.rs`,
   `serve.rs`, `spawn.rs`, and `compositor/wlproxy/src/{main,session,wire}.rs`.
   Test silent and trickling peers, stalled writes, malformed and truncated
   ancillary data, FD ownership on every error path, partial framing,
   connection floods, retained children, and limits across all connections.
   A per-connection limit is not a process-wide limit. Check whether every
   claimed deadline covers the operation it describes, including consent,
   copying and fsync. Separate per-zone disruption from host-wide exhaustion.

3. **Transfer identity, filesystem races, and consent fidelity.** Follow
   `handle_transfer` through `registry_target`, `deliver`, and `copy_capped`.
   Race destination exit/relaunch against `/proc/<pid>/root` acquisition;
   race source writes and shared file offsets against validation and consent;
   investigate the strength of `st_dev` as proof of source provenance.
   Exercise renames of `incoming`, ownership changes, mount boundaries,
   partial-copy cleanup, and checked credential switching. Confirm the actual
   namespace and capability restrictions before claiming a reachable race.

4. **Mutable state bypassing verified boot.** Trace `sysinit.sh`, first-boot
   setup, login, home/session hooks, and volume unlock. Pruning unexpected
   `/etc` names does not authenticate allowlisted `passwd`/`shadow`, account
   backups, overlay metadata, home files, or other persistent state. Test
   offline tampering in a disposable image, including whiteouts/opaque dirs.
   Explain what locked per-zone LUKS protects and whether an offline attacker
   can alter the next unlock environment. Encryption alone is not proof of
   integrity or rollback resistance. Correct overbroad threat-model claims;
   do not improvise a new boot trust architecture in a small patch.

5. **Updates and release identity across independent builds.** Inspect
   `tools/update/kryptik-update`, `tools/apply-update.sh`, `tools/image/`,
   release manifests, and `.github/workflows/`. Check payload mutation after
   verification, destination-device identity, signed manifest parsing,
   rollback/replay, concurrent installs, power-loss recovery, and boot-success
   authorization. Build A and B with independent build runs when testing key
   continuity; two images signed by one temporary test key do not prove it.
   Audit actual artifact contents for private keys and fail-open publication.

6. **Shipped privilege and advisory coverage.** Use the existing
   `tools/audit-setuid.sh`, `tools/check-artifact-hardening.sh`,
   `tools/release-check.sh`, and source/support inventory tooling.
   An earlier local sysroot audit found 16 setuid/setgid executables against an
   empty allowlist; that sysroot is not evidence about the newest image.
   The earlier build-suite log also contained soft hardening findings. Inspect the
   actual image, justify necessary privilege, and check whether acceptance
   enforces the relevant audits. Do not strip permissions blindly and break
   authentication, or count every missing ELF flag as an exploitable flaw.
   Check glibc 2.40 and its patch coverage using current upstream advisories;
   determine build/runtime applicability before asserting any CVE is exposed.

7. **Network and desktop trust under real lifecycle events.** Test all NICs,
   hotplug, DHCP renewal and resolver changes, IPv6, net-zone failure/restart,
   and deny-by-default behavior throughout transitions. Review trusted lock,
   suspend, logout, clipboard cleanup, zone stop, and encrypted mapping close.
   Preserve browser sandboxing. Verify what privileged Wayland globals and
   objects can reach the compositor, including object creation before client
   identity setters. A shared-kernel namespace design must not be presented
   as equivalent to VM isolation without a defensible, explicit comparison.

## Method and deliverables

For each confirmed finding provide: attacker role; exact prerequisite;
source location; violated security property; reachable execution path;
minimal harmless reproducer; observed result; scope of impact; and fix.
Label source-only concerns and untested hypotheses separately. Prefer a
regression that fails before and passes after, using the smallest existing
test harness. Check all callers and sibling paths of the changed function.

On this Windows host Linux syscall tests run in WSL `kryptik-build`. Example
from PowerShell (use a private target directory if another build is active):

```powershell
wsl -d kryptik-build --cd 'C:\Coding-Projects\Linux Distro' --exec env PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin cargo test --offline --locked --manifest-path compartments/kryptikd/Cargo.toml --target-dir /tmp/kryptik-claude-review-target broker::tests
```

Use temporary files, disposable images, and bounded test processes. Never
alter the host's real accounts, mounted production volumes, firmware, or
release credentials to demonstrate a defect. Run relevant tests and
`git diff --check`; record any skipped tests and why.

Produce a concise report separating confirmed/fixed issues, unresolved
findings, hypotheses, and validation limitations. Implement the smallest
reviewable fixes for up to three confirmed defects in this pass. Leave
architectural changes as concrete proposals with acceptance criteria.
If no additional defect is established, report the paths tested and the
remaining uncertainty. Do not manufacture findings or declare the distro
secure because its current acceptance suites pass.
