# Kryptik overnight resume: verified checkpoint, 2026-09-13

This brief supplements `docs/OVERNIGHT_GOAL.md`. Keep its G1-G10 completion
requirements. Resume the existing implementation; do not repeat the earlier
branch integration or replace working subsystems with parallel implementations.
The work is one autonomous Claude session. The user is away and has explicitly
requested periodic local commits. No other agents or Claude sessions are needed.

## What was independently checked

Inspection reached branch `overnight-2026-09-13/impl`, commit `76599a1`, in
WSL distro `kryptik-build`, worktree `/root/kryptik/impl`. The tree was clean
before the audit documents were added. The expected integration/import and
implementation commits are present. Windows `main` and its original dirty
files/untracked compositor have been preserved.

Tests below were rerun against this source on the BUILD HOST. They are not
installed-Kryptik or firmware-boot results.

| Check | Observed result |
| --- | --- |
| `bash tools/test-step-errexit.sh` | All 58 checks pass. The reported old-harness negative control was not rerun in this audit. |
| `cargo test --locked -j1 --manifest-path compartments/kryptikd/Cargo.toml` as root | 143 pass, including `volume::tests::luks2_lifecycle_when_root` and existing broker/network tests. |
| `cargo test --locked -j1 --manifest-path compositor/Cargo.toml --workspace` | wlproxy: 35 pass. zoneid library: 56 pass, 1 fails. The workspace run stops at the failure; do not claim later workspace targets passed. |
| zoneid failure | `palette::tests::a_passing_six_colour_palette_exists`: proposed palette scored 14.08 but still failed its invariant (`palette.rs:323`). |
| Actual wlproxy executable | Crashes on its first accepted client: index out of bounds in `wlproxy/src/main.rs:149`; process exit 101. Reproduced with an owned temporary upstream Unix socket and client, without Wayland or a VM. |
| Actual title transformation | `policy::title_for("vault", &"\u{00e9}".repeat(200))` panics at `policy.rs:52`, exit 101. ASCII title positive control passes first. |
| `make -n update-test` | Warns that Makefile line 462 overrides line 349, and resolves to `compartments/tests/update.sh`. The OS-update VM driver is currently shadowed. |
| glibc patch files | All three files match their committed SHA256SUMS. The upstream 31943 backport exists and addresses loader segment gaps. Target runtime proof is still pending. |
| Build process/artifacts | `/root/build-run.sh` was alive, stage 04 active. Its glibc step subsequently completed with `ok glibc (595s)` and proceeded to bzip2/xz. No final kernel or boot image was present. No system/kernel completion exit files had appeared. Recheck on resume. |

Saved probe/test evidence lives at
`/root/kryptik/logs/codex-verify-20260913/`: `kryptikd.log`,
`compositor.log`, `wlproxy-build.log`, `proxy-connect.py`,
`proxy-connect.log`, `title-unicode.rs`, `title-unicode.log`.
The latter two probes use the real source/binary; they do not modify product
source. Turn them into appropriate maintained regressions when fixing the bugs.

The upstream glibc change was inspected here:
[release/2.40 backport 2193f426](https://github.com/bminor/glibc/commit/2193f42655a9687ce66362905add03a4cfbc580e).
That verifies the patch's stated upstream purpose, not that Kryptik's rebuilt
loader has passed its runtime tests. Use the [upstream security information](https://sourceware.org/glibc/security.html)
to evaluate applicable outstanding security fixes; do not assume this one
backport makes the entire 2.40 release current.

## Correct the checkpoint before continuing

`OVERNIGHT_STATUS.md` is useful but not fully current:

- `tools/net/netzone-init.sh` and its s6 service exist (commit `e892b42`).
- `tools/image/integrity-test.sh`, `tools/image/update-test.sh` and recovery
  tooling exist (commit `a5ecf2e`). Review and repair them rather than writing
  second versions because the table says they are missing.
- The proxy is implemented and unit-tested, but its executable is not usable
  until the reproduced connection crash is fixed.
- The Cargo PACKAGE is `wlproxy`; the BINARY is `kryptik-wlproxy`. The saved
  `-p kryptik-wlproxy` build command is wrong. Use `-p wlproxy --bin
  kryptik-wlproxy`, with the intended target and manifest/workspace.
- The original goal file was absent from the Linux implementation tree. This
  audit supplies a copy there along with this brief. Read both, including all
  original acceptance gates, rather than assuming the status table is the scope.
- Checksums for 102 locked sources and unaudited signing keys are different
  from independently established source authenticity. Keep those labels honest.

The alternate build distro works. Do not spend the next run repairing the
unneeded original Ubuntu attachment or create yet another distro.

## First: fix the demonstrated failures and immediate integration defects

1. **Proxy poll loop:** `main` builds its pollfd array from existing sessions,
   accepts and appends a new session, then indexes that old array for every
   session including the new one. Fix the event/snapshot relationship at the
   shared loop. Add a real executable/socket regression covering first
   connection, multiple clients, disconnect/reconnect and continued service.
   Keep protocol/descriptor/resource checks intact. A pass in `Session` unit
   tests is not coverage of `main`'s event loop.

2. **UTF-8 title handling:** byte index 253 need not be a UTF-8 boundary.
   Preserve a bounded valid string for accented text, emoji and other
   multi-byte input, including long zone names and titles. Fix the shared
   transformer; do not strip Unicode or weaken the size limit. Test the actual
   proxy's handling as well as the small unit case. Release `panic=abort`
   makes malformed-boundary panics process failures.

3. **Palette failure:** investigate the candidate scoring/acceptance mismatch
   and the non-color identity requirements before changing expected values.
   Do not simply lower the invariant or delete the test. Ensure the generated
   and shipped palette plus text/pattern identity obey the same documented
   accessibility contract. Then run the whole compositor workspace to the end.

4. **Make target collision:** give application-tree and installed-OS update
   suites distinct public targets. Fix Makefile, help, test-runner labels,
   documentation and the future acceptance target together. Verify with
   `make -n` that the OS target selects `tools/image/update-test.sh`; then
   actually execute it when real A/B artifacts exist.

5. **dwl build integration:** `s_dwl()` currently copies `dwl-config.h` but
   neither copies `zone-colours.h` nor applies `dwl-zone-borders.py`.
   The config includes that header and uses `ZoneColor`, introduced only by
   the patch. Wire all three into the real build, and hash them as recipe
   inputs. Applying the patch in a scratch directory and compiling the launch
   client separately do not prove that stage 04 installs a working desktop.

## Preserve the active build and complete the target runtime proof

Inspect `/root/build-run.sh`, current child processes and fresh log tails. Do
not trust old PID numbers alone. Paths are:

```
KRYPTIK_WORK=/root/kryptik/work
KRYPTIK_SOURCES=/root/kryptik/sources
KRYPTIK_OUT=/root/kryptik/out
logs=/root/kryptik/logs
```

The orchestrator runs stages 01/02, then stage 04, waits for
`/root/kryptik/GO-05`, and finally runs stage 05. It will not finish media,
tests or exports for you. Take responsibility for those steps in this session.
Do not leave the goal waiting indefinitely for a GO file only you can create.

Do not edit a running stage script in place or let a build consume a changing
set of inputs. Prepare changes away from the running inputs; integrate them
at a verified build boundary and rerun the affected steps with correct stamp
invalidation. Do not run a second chroot driver against the same sysroot:
its cleanup can unmount the active build. Collect the current build exit code,
preserve its log and fix the first real failure before resuming.

After the current system build ends, run `make SUDO= test-libc-unwind` against
the TARGET loader, then target userspace and artifact/hardening checks. Test
dlopened libraries, thread exit/cancel and backtrace without eager-linking or
preload workarounds. Patch checksums and a successful glibc compilation do not
close G2. Update `build/BLOCKER.md` only with fresh runtime evidence. If it still
fails, investigate the resulting target artifacts rather than declaring the
upstream bug title conclusive.

Rebuild kryptikd and wlproxy with their intended static target after changes;
pass the exact binaries into the system build and verify the installed bytes.
The pending desktop step must actually consume `KRYPTIK_WLPROXY_BIN`; naming
an environment variable in the checkpoint does not implement its transport.
Reconcile the daemon, proxy, configs, services and target image versions.
Release the stage-05 gate only after the intended system build has succeeded.

## Finish the desktop through the real launch path

Complete `kryptik-chrome`, `kryptik-session`, the `kryptikd-serve` s6 service,
the `info` and `runtime` requests expected by `kryptik-launch`, and the stage-04
desktop step. Implement the smallest usable trusted launcher/status/confirmation
UI. Reuse dwl, existing zone identity code and broker channels. Ship and test
ordinary authenticated login, terminal, editor and the chosen browser inside
zones; no escape into unconfined user applications in zone 0.

Review the existing daemon before extending it:

- Its request reader handles connections serially and has no receive deadline;
  a client can hold it before sending a complete request. Bound this behavior
  with simple platform facilities and prove other clients recover.
- `recv_request` does not reject `MSG_CTRUNC`; descriptor limits, ownership and
  cleanup on error need explicit checks. `spawn_launcher` can return on an
  early log/fork error without closing the passed descriptor. Trace every
  caller and give descriptor ownership one consistent rule.
- `wayland_path_ok` currently checks only a string prefix/suffix and `/../`.
  Verify requested zone, session UID, socket type, symlink/rename races and
  peer/proxy identity. A path under a session-owned directory is not proof of
  a specific trusted proxy or of which zone the socket belongs to.
- An `ok <pid>` reply immediately after fork does not establish that exec or
  zone startup succeeded. Make UI success and readiness follow actual startup
  and preserve meaningful errors. Do not log passphrase material.

Test daemon requests and the actual proxy executable, then booted GUI flows:
trusted identity at focus/fullscreen changes; isolated input and capture;
explicit broker file transfer and one-shot clipboard consent; cancellations,
forged requests, malformed/fragmented traffic, dropped peers and resource limits.
Keep zone IDs controlled by trusted infrastructure and visible beyond color.

## Fix security and persistence failures visible in current source

These are source-reviewed gaps requiring regression tests, not claims that
their final guest behavior was already reproduced in this audit.

**Network startup:** `netzone-init.sh` logs missing/failed nftables and proceeds
to enable forwarding and report ready. Fail closed when firewall setup fails;
validate the atomic ruleset before exposure, and avoid a forwarding window
before policy exists. DHCP/DNS failure must have truthful readiness and recovery.
Test routed IPv4/IPv6 egress, zone separation, vault/zone-0 isolation, service
crashes and restart/NIC ownership in the target VM. Fix actual shared setup
paths rather than adding a successful-looking service marker.

**State failure:** `sysinit.sh` falls back to tmpfs if the installed state
partition is absent or fails to mount. Distinguish an intentional live medium
from a damaged installed system. An installed-system failure must enter explicit
recovery or fail safely, not silently boot a fresh nonpersistent user state.
Test missing, corrupt and ambiguous state devices, preserving existing data.

**Trust boundary:** the verified root is overlaid with an unauthenticated
writable `/etc`, while updater trust anchors/required role and service config
live beneath `/etc`. Audit paths by which state can shadow trust policy or
privileged startup. Protect security-critical configuration in authenticated
immutable storage or through an explicit authenticated design; do not claim
whole-system tamper protection solely because the lower root passes verity.
Add an offline state-tamper VM test as well as a root-image byte-flip test.

**Device identity:** sysinit, updater and boot-success find partitions by
global label and select the first result. Resolve state, ESP and slots to the
actual installation and reject ambiguities/aliases before writes. Test two
attached disks carrying matching labels. Never test installation on a host
physical disk or modify host firmware; use owned disposable guest disks/vars.

**Update authentication and recovery:** preserve the new A/B implementation,
but audit mutable payload paths between verification and copying, signed
metadata/file parsing, destination readback and inactive-kernel identity.
Test interruption between `set-next` and the trial-state write, and between
trial boot success and replacement of `BOOTX64.EFI`/commit metadata on FAT.
`boot-success` currently depends on sysinit, eudev-trigger and kryptikd-check;
it must not commit an unusable desktop/network installation merely because
those three completed. Define essential readiness and bounded recovery.
BootNext consumption alone does not restart a machine stuck in a bad kernel:
prove failure detection/reboot/fallback with a deliberately broken trial.

## Execute and repair the existing firmware/installation/update drivers

Keep the implemented EFI-stub/compiled-command-line/verity A/B approach if it
works; prove it against the pinned kernel and actual artifacts. Repair real
incompatibilities rather than rewriting the boot stack on speculation. Build
stage 05 and stage 06, and run USB, ISO, developer-key Secure Boot, blank-disk
installation, cold boot, reboot, shutdown, integrity and recovery tests.
Firmware must load the system's own boot assets: no host `-kernel`, `-initrd`,
`-append`, root sharing or substitute distro userland.

Fix the false-positive Secure Boot test before relying on its result:
`media-smoke.sh --expect-refused` accepts the regex
`Access Denied|Security Violation|failed to load|BdsDxe|Boot Failed|.`.
The final `.` matches any nonempty log. No Linux banner plus any firmware text
does not distinguish authentication rejection from a missing/broken image.
Require actual enforcement evidence, same-image enrolled-key success and a
specific rejected-artifact result; unexpected boot failure must fail the test.
Treat logs as belonging to the exact run, not stale shared `latest` files.

Inspect every VM driver for real exit propagation, complete expected state,
positive controls and persistent-data assertions. The update driver's existing
interruption tests use QMP quit and disclose their limits; keep that distinction
from storage-controller power loss and extend coverage at the persistent-state
boundaries above. Use appropriate QEMU caching and preserve raw logs/VM states
needed to reproduce a failure. Never count a skipped guest test as passed.

Build and preserve distinct A/B payloads and release-A install media. Run the
OS updater through the corrected Make target, boot B, prove a real behavior
change, preserve zone data, recover/rollback, then boot again. Include wrong
key, altered/truncated payload, incompatible version, full disk, concurrent
update and interrupted write/activation cases. Finish target LUKS lifecycle,
backup/restore, ephemeral teardown and GUI/network adversarial scenarios.

## Continue through final acceptance and commit regularly

Implement or extend one `make acceptance` entrypoint covering all G1-G10 gates
from the original scope. It must fail/incomplete on missing required artifacts,
tools or tests, including the palette/proxy failures. Source availability and
host test passes cannot stand in for installed-image verification.

After each coherent tested change, make a focused LOCAL commit. Aim to leave
no more than roughly 30-45 minutes of completed implementation uncommitted.
Review `git diff` and stage explicit files. Commit before a major rebuild or
context checkpoint when the change is coherent; keep incomplete work clearly
labeled if it must be saved. Record relevant test outcomes in commit messages
and `OVERNIGHT_STATUS.md`. Do not mix unrelated work, commit secrets or large
build outputs, amend others' commits, push, or publish. This is an explicit
user request to commit periodically, not a request for one final mega-commit.

Each checkpoint should surface current evidence, remaining gates and the next
executable step in the transcript. Continue after intermediate successes,
commits and compaction. Long builds are opportunities for independent work
outside their inputs, not a reason to announce completion. Keep original
acceptance criteria; do not lower them to fit the night or burn tokens on
unchanged green tests. There is no two-hour cutoff.

Export the tested ISO/USB image, hashes, public verification material, exact
source revision and concise boot/install/update/recovery instructions to
`C:\Coding-Projects\Linux Distro\out\overnight\`. Include the final truthful
gate table and remaining limitations. Update README/roadmap/status to match
actual evidence, then run the justified final complete acceptance pass against
those exact artifacts. Follow the project's Tectonix session workflow for your
implementation, using metrics for triage rather than as a boot/security gate.

All ten gates passing is completion. If an external blocker truly exhausts all
useful permitted work, save a resumable checkpoint and explicitly report
INCOMPLETE. Do not invent success or conceal failures to satisfy the goal.
