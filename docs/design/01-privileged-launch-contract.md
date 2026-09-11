# Design 01 — The privileged launch contract on Kryptik's kernel

Status: security design for Opus implementation. Depends on nothing.
Blocks: M1 (cgroup ownership needs root), M3, M4.

## The fact WSL cannot show

Kryptik's kernel is linux 6.18 + linux-hardened with
`CONFIG_USER_NS_UNPRIVILEGED` **off** (`build/config/kernel/hardened.fragment`).
On that kernel `unshare(CLONE_NEWUSER)` and `clone(CLONE_NEWUSER)` from a
process without `CAP_SYS_ADMIN` in the initial user namespace fail with
`EPERM`, and the sysctl `kernel.unprivileged_userns_clone` reads `0`.
Every unprivileged `kryptikd run` result on WSL or a stock Ubuntu VM therefore
exercises a path that **does not exist on the target**. On the target, zones
are created only by a root kryptikd. That is the design (ADR-003, ADR-010);
this document makes it a checked contract instead of an assumption.

## Contract

**P1. kryptikd creates zones as uid 0 in the initial user namespace, and only
there.** The unprivileged path stays for developer hosts and CI; it is not a
supported way to run Kryptik.

**P2. Unprivileged user-namespace creation is off on the target, and
`kryptikd check` proves it.** `check` forks a child that does
`setresgid(65534); setresuid(65534)` then `unshare(CLONE_NEWUSER)`. Result
`EPERM` = restriction in force. Success = the restriction is NOT in force;
on a target build this is a `check` failure. `check` also reads
`/proc/sys/kernel/unprivileged_userns_clone` when it exists and requires `0`.
`build/config/sysctl.d/99-kryptik-hardening.conf` gains
`kernel.unprivileged_userns_clone = 0` explicitly, so the setting does not
depend on the hardened default alone.

**P3. Each zone has a fixed, declared, unique host identity range.** Zone
files gain `[identity] uid_base = N` (integer). Validation: `N >= 131072`
(the first aligned range; 100000 is not a multiple of 65536, an error in
the first draft), `N % 65536 == 0`, unique across the zone set, and the range
`[N, N+65536)` must not overlap any other zone's. The mapping written is
`0 -> N` (one uid) and `65534 -> N+65534` (so "nobody" inside is a distinct
host uid, not an unmapped 65534 alias); gid likewise. `--zone-uid/--zone-gid`
remain as an override only for zones without `[identity]`, and a root launch
without either is still refused. Ordinal-derived ranges are rejected as a
design: adding a zone must never change another zone's file ownership.
Shipped zone files get `uid_base` values `131072, 196608, …` in name order,
once, by hand.

**P4. The data directory belongs to the zone's identity and nothing else.**
`/var/lib/kryptik/zones/<zone>` is created `0700 N:N` by kryptikd on first
launch; on every launch `check_data_dir` (existing) refuses any other owner,
a symlink, or a directory with submounts.

**P5. A privileged launch carries nothing of root into the zone.**
Before `unshare`: `setgroups(0)`, `setresgid(N)`, `setresuid(N)` (existing),
plus `prctl(PR_SET_KEEPCAPS, 0)` is *not* set (default), so effective
capabilities are cleared by the uid change; then
`prctl(PR_CAPBSET_DROP, c)` for every capability and
`PR_CAP_AMBIENT_CLEAR_ALL`. Inside the new user namespace the zone's root
regains a full set *scoped to that namespace* — that is unavoidable and
acceptable until M3 (see Design 03, which drops the bounding set inside the
zone as well).

**P6. `KRYPTIK_EXPERIMENTAL` is inert for a root launch on the target.**
When P2 holds (restriction in force) and euid is 0, the variable is ignored
and a zone that needs it is refused. Development overrides are for
development hosts.

**P7. Refusals are named.** An unprivileged launch on a kernel where P2
holds fails at `unshare` with `EPERM`; kryptikd must print
`this kernel does not allow unprivileged user namespaces (kernel.unprivileged_userns_clone=0); zones are started by the kryptikd service as root`
rather than the bare errno.

## Tests

Where: the developer VM as root. Until a Kryptik kernel boots there, the
stock kernel emulates P2 with `sysctl kernel.apparmor_restrict_unprivileged_userns=1`
(Ubuntu) — the *observable* behaviour (EPERM for unprivileged `unshare`) is
the same, and the test must say which knob it used.

| id | check | expected |
|---|---|---|
| T1 | `kryptikd check --target` with the restriction on | pass; prints `unprivileged userns: disabled (EPERM)` |
| T2 | same with the restriction off | **fail**, names the sysctl |
| T3 | unprivileged `kryptikd run` with the restriction on | exit 1, message of P7, command did not run |
| T4 | root `kryptikd run work -- id -u` with `[identity] uid_base = 165536` | `0` inside; `$ROOTFS/work/x` owned by 165536 on the host; `nobody` inside maps to 231070 (`touch` as nobody via `su`/`setpriv` is optional) |
| T5 | two zone files with the same `uid_base` | `kryptikd check` fails: `identity ranges overlap` |
| T6 | `uid_base = 1000` or `uid_base = 100001` | refused by validation |
| T7 | root launch of a zone with no `[identity]` and no `--zone-uid` | refused (existing K1) |
| T8 | `KRYPTIK_EXPERIMENTAL=1` root launch of `untrusted` (ephemeral) with the restriction on | refused; message says the override is ignored on the target |
| T9 | inside a zone, `/proc/self/status` `CapAmb` = 0; `NoNewPrivs` = 1 | as listed |
| T10 | positive control: with the restriction off, unprivileged launch still works on the dev host | launcher suite unchanged |

Regression location: `compartments/tests/launcher.sh` group K (root) and a
new group P (privileged contract); unit tests in `zone.rs` for P3 validation.

## Files

`zone.rs` (parse/validate `[identity]`), `spawn.rs` (`launch_identity` reads
it; P5 capability drop; P6; P7 message), `main.rs` (`check --target`),
`build/config/sysctl.d/99-kryptik-hardening.conf`, six zone files,
`docs/architecture.md` one paragraph under "Zone 0".
