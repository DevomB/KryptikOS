# Design 05a — The broker as built (security increments c22c1be…, clipboard, transfer)

Design 05 is the contract. This is what exists, in the words of the wire.

## Built

- **Identity.** Every connection is `SO_PEERCRED`-checked against the one
  uid the launcher mapped its zone to; anything else gets
  `error: unidentified peer` and nothing more (`broker::serve_connection`).
  On an unprivileged developer launch every zone maps to the launching
  user, so identity distinguishes nothing there; on the target each zone's
  range is disjoint (Design 01) and the check is the authentication.
- **One socket per zone**, in the zone's registry entry, bound into the
  zone at `/run/kryptik/broker` (0600, zone identity), through a
  descriptor the child opens after `unshare(CLONE_NEWNS)` and before the
  identity switch (`50ebe29`). The launcher serves it between `waitpid`
  polls while it supervises the zone; one request per connection, a
  5-second deadline end to end, every refusal from the header before a
  payload byte is read, every attached descriptor closed afterwards.
- **Wire format** — one header line; `clipboard-set` carries `len` bytes
  after it, `transfer` carries one `SCM_RIGHTS` descriptor with it:

  ```text
  version\n                            -> kryptik-broker 1 zone=NAME\n
  clipboard-set <mime> <len>\n<bytes>  -> ok\n
  clipboard-get\n                      -> ok <mime> <len>\n<bytes>   |  empty\n
  transfer <zone> <name>\n  (+1 fd)    -> ok <final name>\n
  clipboard-move ...                   -> error: clipboard-move is a zone 0 act, not a zone verb\n
  anything else                        -> error: <reason>\n
  ```

- **The clipboard.** One payload per zone in the zone's registry entry as
  `clipboard` (first line the MIME type, from a fixed list; at most
  1 MiB; 0600, written to a fresh `O_EXCL|O_NOFOLLOW` file and renamed
  into place, read with `O_NOFOLLOW`). The zone 0 gesture
  `kryptikd clipboard move FROM TO` copies FROM's payload onto TO's (both
  running; the source keeps its payload). No zone can trigger it.
- **Transfer** (B1–B8, B12). Checked in order, refusing on the first
  failure: exactly one descriptor; the destination is not the sender, is
  named in the sender's `[transfer] to`, is a configured zone, and is
  never the one holding the NIC (refused in the zone directory
  invariants and again at request time); consent; the descriptor is a
  regular file, `O_RDONLY`, not `O_PATH`, on the sender's data mount
  (`st_dev` of `/home/<zone>` read through pid 1's root at request time),
  within the 1 GiB cap; the destination is running. The copy lands in
  `<destination home>/incoming/`, resolved with `openat2` from the
  destination's root (`/proc/<pid 1>/root`, an O_PATH descriptor into
  its mount namespace) with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`: a
  planted symlink anywhere on the way is refused or skipped, never
  followed, so nothing zone 0 writes can leave the destination's tree
  whoever runs the copy — which is why the uid-switching helper Design 05
  sketched is not needed. The name is chosen by `O_EXCL` (a collision or
  a planted link moves to `-2`, `-3`, …), the file is 0600 owned by the
  destination identity, the cap is enforced on bytes actually copied, a
  failure unlinks the partial file. Ephemeral and persistent
  destinations are reached the same way. The zone learns the final name
  and nothing else.
- **Policy**: `[transfer] to = "work personal"` in the sender's zone
  file; absent means the zone sends nothing. `kryptikd check` refuses a
  directory where a zone names a non-zone or the NIC zone. No shipped
  zone declares one.

## Consent

Design 05 puts a user prompt before a transfer and makes the clipboard
move a compositor gesture. There is no desktop yet, so the clipboard
gesture is the command run by whoever holds zone 0, and a transfer needs
the launcher started with `--auto-approve-transfers`, a development flag
that warns at every launch; without it every transfer is refused for want
of approval. The prompt itself is desktop work (M5) and will replace the
flag, not sit beside it.

## Evidence

- Unit: `broker::tests` drive `serve_connection` over socketpairs with
  real `SCM_RIGHTS` — clipboard round trip, a payload in pieces, every
  clipboard refusal with the exact reply; the transfer landing, the `-2`
  name, the planted symlink as a name and as `incoming` itself, every
  transfer refusal with its reason and nothing created, the
  descriptor-leak check, the copy cap. `zone::tests` cover the policy
  list and the directory invariants.
- Probes (`security/probes/fixed-checks.sh`): BR1–BR3 identity and tree;
  BR4–BR9 the clipboard through the launcher, including the zone 0 move
  between two concurrently running zones; BR10–BR16 a transfer between
  two concurrently running zones read back byte-identical and 0600 from
  inside the destination, and the refusals for consent, policy, a
  directory descriptor, a bad name, a file from the zone's tmpfs, and a
  destination that is not running.
- Integration suite (integration's): BRK1–BRK4, including the root-side
  refusal of a peer that is not the zone.

## Not built

- **The prompt** (above).
- **`transfer.max_bytes`** per zone: the cap is the 1 GiB default only.
- **The Wayland proxy socket** (`wayland-0`) — identity only, later. When
  it lands it is the second entry under `/run/kryptik` inside a zone
  (integration's LC6b should allow the set {broker, wayland-0}).
- **A zone-side client.** Zones speak the wire format directly today (the
  probes use python sockets); a tiny `kryptik-clip` / `kryptik-send` in
  the image would be integration's.
