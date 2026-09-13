# Kryptik: single-session overnight implementation scope

Prepared from repository inspection on 2026-09-13. This is an implementation
brief for one Claude Code session. Read the complete brief before editing.

## Objective and working contract

Produce a usable, independently bootable and installable x86_64 Kryptik
developer alpha, built from Kryptik's own source recipes, with its compartment
model functioning in the installed desktop. Finish the work through the
acceptance gates below. This is substantial, potentially multi-night systems
work; neither spending a particular number of tokens nor reaching a checkpoint
constitutes completion. There is no two-hour cutoff or first-milestone stop.

The user will be away. Implement, build, boot, diagnose, repair and retest
autonomously within the permitted workspace and disposable VMs. Make ordinary
engineering decisions from the repository's architecture and explain them in
the run record. Do not return a plan and wait for someone to implement it.
Do not invoke another Claude, create agents, depend on another tab, or wait for
another agent's handoff. Background compilation and VM processes are fine;
record their owners, commands, logs and exit codes and collect their results.

Kryptik is a from-source Linux distribution using a shared hardened kernel,
s6 supervision, namespaces, cgroups, Landlock, seccomp and encrypted zones.
WSL may be a build host. The delivered system must boot from firmware without
Windows, WSL, a host-provided kernel or a mounted host root filesystem.
Preserve the documented separation: zone 0 hosts trusted infrastructure and
has no external network route; user applications run in zones. A shared
kernel is not equivalent to Qubes' VM isolation. Correct claims accordingly.

Follow the applicable AGENTS.md instructions. Trace the real execution path
and all affected callers before choosing a fix. Reuse existing helpers,
platform facilities and dependencies. Add dependencies only for concrete
missing product capabilities, with pinned sources and provenance. Avoid
inventing frameworks, a new package manager, a full custom compositor engine,
or cosmetic features to fill time. Each nontrivial fix needs the smallest
runnable regression that detects the failure, including an appropriate
positive control. Improve software behavior rather than test counts or lines.

## Inspection baseline: verify before relying on it

The following are source observations and recorded historical evidence, not
freshly rerun Linux/VM results. Branch tips can move. Inspect them again and
reconcile newer work before editing.

| Area | Observed state and consequence |
| --- | --- |
| Main checkout | `C:\Coding-Projects\Linux Distro` is on `main`, `d2abaef`. Sixteen tracked shell-file changes were mode-only. `compositor/` is untracked and contains real user work. Preserve it. |
| Integration | `overnight-2026-09-11/integration` is at `75f1cc3`, substantially ahead of main. Start from its current successor, after checking ancestry and dirty worktrees. Do not develop against stale main. |
| Outstanding build fix | `overnight/build-2026-09-11` contains unmerged `a67b1ba`: installer success previously reflected `sed`'s status; required partitioning tools were absent; partition names were wrong. Review and integrate its actual fix and tests. |
| Outstanding security work | `overnight-2026-09-11/security` contains unmerged `ffff72f` (tracked regression probes) and `3fcf4bf` (per-zone narrowing Landlock policy layer). Review and integrate in ancestry order. |
| Provenance | `overnight-2026-09-11/provenance`, observed at `740e8ab`, had no commits absent from integration. Preserve later source-verification improvements and reconcile recipe/pin consistency. |
| Existing system | Later sections of `build/HANDOFF.md` record 67 base-system entries wired, a built Kryptik kernel, real s6 service startup and the shutdown fix. Earlier sections and README contradict these later records. Verify artifacts rather than restarting these completed investigations. |
| Fundamental runtime defect | `build/BLOCKER.md` records target glibc 2.40 misidentifying dlopened objects in `_dl_find_object`, causing `pthread_exit`, cancellation and backtrace aborts. Kernel host-tool eager-linking of libgcc is a workaround, not a runtime fix. |
| Boot medium | `build/stages/06-iso.sh` is still a stub. `tools/image/mkdisk.sh` creates a root disk without an ESP/bootloader. `run-qemu-disk.sh` and both installer-test phases require an external `--kernel`. Existing direct-kernel boot evidence does not establish firmware boot. |
| Compartments | Lifecycle, isolation, cgroups, ephemeral storage, networking setup and authenticated broker operations have substantial implementations. Audit and complete them; do not replace them with parallel implementations. Encrypted storage remains a missing guarantee. |
| Desktop | Untracked `compositor/zoneid` contains identity/color/accessibility code. `compositor/wlproxy/src/wire.rs` contains parser work, but `wlproxy/src/main.rs` is only `fn main() {}` and does not wire in the parser. Building that entry point proves no functional proxy. |
| Updates | `tools/apply-update.sh` verifies and replaces a directory tree. `compartments/tests/update.sh` exercises a kryptikd program/config tree in temporary directories. These are useful tests, but do not prove an installed OS survives a root update, interrupted update or reboot. |
| Image signatures | Developer Ed25519 image verification exists on the host. It does not implement firmware Secure Boot or guest dm-verity. Reuse it for its actual purpose. |
| Environment | During this inspection Ubuntu WSL2 could not attach its `ext4.vhdx`: `Wsl/Service/CreateInstance/MountDisk/HCS/ERROR_SHARING_VIOLATION`. Linux worktrees and old build artifacts could not be revalidated. |

Tectonix on the Windows checkout reported quality_signal 6852, with modularity
4687 and equality 5288 the lowest root-cause scores. This scanned old main plus
visible local source, not the integrated tree; the CLI also returned exit 1.
Do not use these numbers as an integration baseline or release criterion.

## Work sequence

Work in this dependency order. A blocked item remains open while you advance
independent items. During a long build, useful independent source work is
allowed, but do not mutate the inputs of the build already in progress.

### 1. Recover a trustworthy working baseline

Inspect `git status`, refs, worktree ownership and running processes. Preserve
dirty tracked changes and all untracked compositor sources before creating a
fresh, uniquely named local implementation branch/worktree from integration.
Do not reset, clean, prune or delete existing worktrees. Windows can describe
Linux worktrees as prunable merely because it cannot resolve their paths.
Copy the source-only compositor work into the implementation tree deliberately;
inspect and preserve its lockfiles, and exclude compiled `target/` contents.
Review the outstanding commits above and integrate them, resolving callers and
tests together. Use small local commits for your own completed changes only;
do not stage unrelated work, push or publish.

Diagnose the WSL disk lock read-only first and reuse an available legitimate
Linux build environment if one exists. Do not unregister/recreate Ubuntu,
delete or forcibly detach its VHD, stop someone else's VM, terminate unrelated
sessions or change security policy to obtain access. An unavailable Linux
runtime blocks execution evidence, not source inspection and independent
repairs. Keep working on those while documenting the exact blocker. Do not
present Windows or host tests as target tests. If privileged operations need
approval, honor the actual permission system; the brief cannot grant a bypass.

Use native Linux storage for `KRYPTIK_WORK`; preserve the three-path contract
in `build/HANDOFF.md`. Check available disk/RAM and size jobs to the machine.
Record one authoritative worktree, build directory, source cache and output
directory. Verify old artifacts actually exist: earlier work lost an untracked
shared run directory, so historical absolute paths are not reliable evidence.

Create `docs/OVERNIGHT_STATUS.md` containing the acceptance table, current
facts, source revisions, active job IDs/logs, next commands and unresolved
blockers. Keep it concise and replace superseded status instead of appending
contradictory reports. Preserve raw logs separately under ignored build output.
Run Tectonix scan/health and session-start on the real implementation root
before nontrivial coding; use its root causes as triage, not release proof.

### 2. Repair the target runtime and build correctness

Reproduce `make test-libc-unwind` against the built TARGET loader/libc, including
dynamic loading of multiple libraries. Read `build/BLOCKER.md` before pursuing
the already-ruled-out BZ 32245 explanation. Investigate actual compiler,
configuration, loader layout and upstream source. CET mismatch is a lead,
not an established root cause. Fix the cause with the smallest supported
configuration correction or authenticated upstream patch/version change.
Do not mask it by system-wide preloading or by eagerly linking every program.
Prove thread exit, cancellation, backtrace and dynamic-object resolution work
in the target guest without those workarounds. Retain regression coverage.

Audit `step()` fingerprinting and every caller. Prior step names alone do not
invalidate downstream outputs after a dependency changes. Correct the relevant
dependency/toolchain invalidation, preserving useful resumability. Rebuild the
affected target closure after the libc fix; do not mix a repaired loader with
stale incompatible artifacts. Prove a dependency change cannot reuse a stale
result and an unchanged input can resume without rebuilding everything.

Check every shipped executable/library for target loader paths and accidental
host/bootstrap contamination. Run existing userspace, ELF hardening, setuid,
source signature/provenance and kernel configuration checks. Reconcile pinned
versions, recipes and patches; fetch current upstream security information
from primary sources when needed. Do not silently disable failing hardening
or substitute Ubuntu's rootfs/kernel for Kryptik's.

### 3. Deliver a firmware-bootable medium and a real installer

Implement stage 06 and wire documented public build targets to it. Choose the
smallest maintainable UEFI loader/initramfs approach compatible with s6 and
the verified-root/update requirements below. Reuse upstream implementations.
Plan a consistent ESP, root-slot and persistent-state layout once; make the
installer, bootloader and updater consume that same format.

Produce a self-contained bootable USB disk image and make the advertised ISO
target produce a bootable installer ISO. Both must contain Kryptik's kernel,
boot assets and userland. Resolve the actual root using a supported mechanism;
an fstab UUID alone does not teach an early kernel how to discover the root.
Support ordinary UEFI removable-media discovery and a clean firmware variable
store, not just an existing developer VM's saved boot entry.

Create an OVMF/QEMU test path that boots the medium without `-kernel`,
`-initrd`, `-append`, host root sharing or host-supplied guest boot files.
Normal guest kernel arguments must come from the medium's boot configuration.
Retain direct-kernel tooling as a developer diagnostic with honest names.

Integrate `a67b1ba`, then audit the complete installer path again. The existing
`install-test.sh` expects `verify: 1 partition`, whereas the updated runner
reports a different partition-2 marker; repair this contract and validate real
partition state. Do not just edit a marker to make the test green.

Preflight all tools, sizes and devices before writing. Guard canonical device
identity, source/target aliases, hardlinks/symlinks in host image paths, mounted
descendants, active swap and the running root's underlying disks, including
stacked devices. Handle virtio/SCSI, NVMe and digit-suffixed device names.
The existing root-copy tar pipeline needs correct producer AND consumer error
handling. Preserve ownership, permissions, links and required xattrs/ACLs;
exclude pseudo-filesystems, test credentials, live zone secrets and build junk.
Propagate failures through scripts, services, logging and test runners.

All destructive installation tests must target freshly created, explicitly
owned virtual disk files attached only to disposable guests. Never install to
a physical host disk. Install from the medium onto a blank second virtual disk,
power down, remove the medium, reset firmware variables and boot that disk
alone. Repeat cold boot, reboot and clean shutdown. Validate files and services
from inside the installed system. Inject missing-tool, copy-failure and
insufficient-space cases and prove refusal/failure cannot be reported as success.

### 4. Finish boot integrity and installed-system recovery

Implement the documented read-only dm-verity root with authenticated boot
metadata. Bind the kernel, initramfs and verity root hash to the trusted boot
chain, not to an editable unsigned command line or host wrapper. Use a signed
combined artifact or equivalently authenticated chain appropriate to the
chosen loader. Keep mutable runtime/user state off the verified root.

Validate UEFI Secure Boot in an owned OVMF test instance with locally generated
developer keys. Enrollment is limited to disposable firmware variables. Do
not enroll keys in the physical machine's firmware, ship private keys, call
developer signatures production certification or depend on obtaining a
third-party production certificate overnight. Keep signing keys outside Git
and distributable images, with restrictive access.

Prove an untampered installed system boots with enforcement enabled, an
untrusted boot artifact is rejected, and root tampering causes integrity
failure rather than reaching the normal desktop. Boot recovery using an
authenticated prior system or dedicated recovery path. Preserve serial logs
and guest checks demonstrating which validation layer refused the change.

### 5. Complete networking, encrypted storage and zone lifecycle

Integrate and exercise the outstanding Landlock layer and tracked security
probes. Verify the shipped zone definitions reference policy files that are
actually installed and applied. Exercise real `kryptik`/`kryptikd` entrypoints
under Kryptik's hardened kernel, not only hand-built unshare demonstrations.

Complete routed egress and DNS through the NIC-owning `net` zone. Verify zone 0
has no external route, vault has loopback only, application zones cannot reach
each other, and IPv6 cannot bypass the policy. Test `net` startup failure,
restart and crash, repeated zone start/stop, resource exhaustion and NIC
ownership restoration. Preserve fail-closed behavior during transitions.
Use disposable VM networks and an owned test endpoint for attack traffic.

Implement the documented per-zone LUKS2 storage using existing kernel and
cryptsetup facilities, with authenticated/pinned build inputs. An ordinary
directory or fscrypt is not a silent substitute for that contract. Define
provisioning, unlock, mount, lock and recovery behavior. Keep passphrases and
keys out of argv, logs, Git and shared storage. Bound and document key lifetime;
do not claim physical RAM erasure beyond what is demonstrated.

Test wrong credentials, interrupted setup, full volume, repeated unlock,
concurrent starts, zone crash and reboot. Persistent zone data must survive;
stopped-zone mounts/mappings and usable key references must be gone. Other
zones must not read the backing device or mounted data. Ephemeral-zone state
must disappear on teardown and reboot; configure/document swap consistently
with the actual confidentiality promise. Test backup and restoration of an
owned test volume and keep recovery credentials outside the image.

### 6. Turn the compositor sources into a usable zoned desktop

Read and preserve `compositor/zoneid` and `wlproxy` before choosing what to add.
Wire existing parser code into compiled, tested execution paths; an empty
binary or tests in an unreferenced Rust module are not implementation.
Use a suitable upstream Wayland compositor/seat implementation as the engine,
with the smallest extension needed for trusted zone identity. Pin/build its
required libraries, fonts and applications from source. Do not bundle another
distribution's filesystem or develop a compositor engine from scratch.

Complete a functioning per-zone Wayland mediation path. Test fragmented and
malformed messages, object lifecycle/IDs, version negotiation, SCM_RIGHTS
descriptor handling, partial writes, disconnects, backpressure and bounded
resource use. Disconnect offending clients cleanly. Untrusted apps must not
reach the compositor directly or acquire screenshot, global-input or shared
clipboard channels through an unfiltered protocol extension.

Connect the existing authenticated broker file/clipboard operations to actual
trusted user actions. A static transfer allowlist is not user confirmation.
Identify both zones in trusted UI; make cancel/refusal work; prevent a source
from choosing a destination path outside policy, racing symlinks or retaining
a writable cross-zone descriptor. Clipboard transfer moves only the explicit
payload once. Test replay, forged identity, disconnected peers, oversize data
and incomplete delivery, alongside successful transfers.

Ship a minimal usable desktop: keyboard/mouse input, terminal, text editor,
browser in a networked application zone, and a small trusted zone launcher/
status/transfer interface. Test the browser against an owned local HTTP test
endpoint through `net`; it must not need zone-0 networking. Respect the vault's
offline status. Make identities compositor-controlled, visible in fullscreen
and understandable through text as well as color. Reuse zoneid's contrast and
color-vision work. Test input focus and that zone A cannot capture, spoof the
trusted chrome of, or keylog zone B. A screenshot alone proves appearance;
negative tests must exercise the isolation boundary.

Use an ordinary authenticated user session and a deliberate first-boot setup
flow. The current passwordless root getty is a development facility; do not
ship it as the normal desktop/login path. Keep administrative and recovery
operations explicit and protected. Exercise login/logout, zone launch,
file creation/reopening, denied actions, controlled transfers and shutdown
from the installed image, including restart after a failed app/proxy process.

### 7. Make updates apply to the installed OS and survive interruption

Reuse the release manifest/trust verification code. First audit and fix
`tools/apply-update.sh`: inconsistent documented option syntax, destructive
staging cleanup before `--dry-run`, unchecked destructive path aliases,
mutable payload verification followed by an unverified copy, predictable log
paths, missing concurrent-operation locking, and incomplete recovery states.
Trace all callers and preserve useful application-tree tests.

Implement an installed-root update flow consistent with the boot layout:
verify the completed inactive payload and its authenticated boot metadata,
flush required persistent state, then activate it with boot-success tracking
and bounded fallback. Preserve the previous bootable root and user volumes.
Two directory renames alone do not prove a power-fail-safe OS update. Make
version/role/trust checks and rollback policy explicit; distinguish authorized
recovery from accepting an arbitrary older signed payload. The guest must
perform verification using tools and trust anchors shipped in the image.
Fetching may use the network zone; zone 0 remains without an external route.

Build versions A and B from real Kryptik outputs, install A, update to B,
reboot, verify a real changed behavior, then recover/rollback and verify A.
Inject wrong key, modified payload, truncated download, incompatible target,
full disk, simultaneous update and power interruption at persistent-state
transitions. Boot after each. Keep persistent zone data intact. Do not use
QEMU `cache=unsafe` for durability claims, or substitute killing an updater
process for all power-loss tests. State the limits of VM power-loss evidence.

### 8. Make validation comprehensive and release artifacts reviewable

Repair aggregate test reporting at the shared boundary. GNU make does not
preserve a recipe's exit 77 as make's exit code, so the current skip handling
needs a real contract. Missing-cargo suites are excluded from `SUITES` and
also subtracted from its length, which miscounts passes. Fix literal `\n`
tokens in Makefile declarations. Inventory the existing source verification,
Rust unit, broker, storage, networking, installer and VM suites; wire the
appropriate existing runners together rather than creating duplicate suites.

Provide one public `make acceptance` command backed by real tests. A missing
required tool, missing artifact, skipped required VM case or unavailable
runtime must produce INCOMPLETE/nonzero, never a pass. Keep optional host
checks distinguishable from mandatory installed-system evidence. Add positive
controls so a launcher that starts nothing cannot pass every denial test.
Reports must identify the tested source revision/content, exact image hashes,
firmware, kernel, command, exit status and log paths. Retest changed dependencies;
old logs do not validate a new image.

Run the final checks against freshly assembled install media and the system
installed from that exact media. Check install from a different working path,
spaces in documented build paths, build resume and missing prerequisites.
Do one justified final full run after integration; do not repeatedly run green
unchanged suites just to spend time. Run Tectonix session-end and investigate
actual regressions; a structural score cannot override failing runtime checks.

Update README, building instructions, roadmap and the authoritative status to
agree with the actual result. Replace stale claims about unwired packages,
unbuilt kernels and entirely absent brokers with evidence at the appropriate
level. Preserve known weaknesses. Avoid promising complete hardware support,
production signing, independent security certification or reproducible builds
that this session has not demonstrated.

Export the final image/ISO, checksums, public verification material and concise
boot/install/recovery instructions under `out/overnight/` in the original
Windows-accessible project. Include source branch/worktree/revision and where
to resume development. Keep large artifacts, generated manifests and private
keys out of source commits. Do not leave the only finished result in an obscure
Linux worktree or an untracked temporary directory.

## Mandatory completion gates

All gates apply to the final assembled artifact, with fresh supporting results.
Maintain this table in the run status as OPEN, ACTIVE, PASS or BLOCKED, with
evidence paths. BLOCKED and skipped are not PASS. Do not weaken these gates to
make the goal easier to satisfy.

| Gate | Required observable result |
| --- | --- |
| G1 Baseline | Latest relevant branches and preserved compositor sources integrated; changes attributable; real build inputs and output paths recorded. |
| G2 Runtime/build | Target libc dynamic-loading/unwind regressions pass without masking; target userspace/kernel and dependency invalidation checks pass. |
| G3 Firmware boot | ISO and USB image boot through clean OVMF using their own boot files, kernel and userspace, without host direct-kernel boot or root sharing. |
| G4 Installation | Blank virtual disk installation passes; media is detached and firmware reset; installed disk cold-boots, reboots and shuts down successfully; installer failure cases report failure. |
| G5 Boot integrity | Enforced developer-key Secure Boot and dm-verity positive/tamper tests pass in disposable firmware; authenticated recovery works. |
| G6 Zones/network | Real shipped zone definitions, policy, lifecycle, resource limits and routing pass on the installed Kryptik kernel; vault/zone-0/network separation remains intact. |
| G7 Storage | LUKS2 persistent and ephemeral-zone lifecycle, restart, denial, failure and test-backup recovery checks pass without embedded secrets. |
| G8 Desktop | Installed authenticated desktop launches usable zoned apps; trusted identity/input/capture/clipboard boundaries and explicit broker transfer flows have positive and negative runtime evidence. |
| G9 OS updates | Installed A-to-B upgrade, reboot, authenticated recovery/rollback and interruption/failure tests pass while preserving persistent zone data. |
| G10 Delivery | Final `make acceptance` exits 0 with no skipped mandatory gate; exported images and hashes match tested artifacts; accurate run/boot/install/recovery documentation and final status are accessible in the original project. |

At each checkpoint, report concrete changes and test results in the session
transcript, name remaining gates and choose the next executable action. The
goal evaluator sees the transcript, not the filesystem. A summary, local
commit, finished phase, green unit suite or long-running build is not a reason
to announce completion while another mandatory gate is open.

On a failed approach, retain the concise failure evidence, change the
hypothesis and continue. If external access blocks one branch of work, advance
the others; revisit the blocked path when there is new evidence. Do not invent
success, spin without tool work, wait indefinitely on nonexistent jobs or
sleep to simulate an overnight run. If all useful permitted work is truly
exhausted behind an external blocker, report exactly what remains and how to
resume, explicitly marking the goal incomplete. Prompt wording cannot prevent
Claude Code from stopping on exhausted usage, fatal errors or an evaluator
verdict. Completion means all ten gates actually pass.
