# Design 05a — The broker as built (security increments c22c1be…, clipboard)

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
  polls while it supervises the zone; one request per connection.
- **Wire format** — one header line, then for `clipboard-set` exactly
  `len` bytes:

  ```text
  version\n                            -> kryptik-broker 1 zone=NAME\n
  clipboard-set <mime> <len>\n<bytes>  -> ok\n
  clipboard-get\n                      -> ok <mime> <len>\n<bytes>   |  empty\n
  clipboard-move ...                   -> error: clipboard-move is a zone 0 act, not a zone verb\n
  transfer ...                         -> error: transfer is not implemented yet\n
  anything else                        -> error: <reason>\n
  ```

  Every refusal happens from the header, before a payload byte is read:
  MIME outside the fixed list (`broker::MIME_TYPES`), length over 1 MiB,
  wrong arity. A request has a 5-second deadline end to end (a zone that
  dribbles bytes stalls only its own supervision, and only that long); a
  payload shorter than announced is refused and nothing is written.
- **The payload** lives in the zone's registry entry as `clipboard`: first
  line the MIME type, the bytes after it; 0600, written to a fresh
  `O_EXCL|O_NOFOLLOW` file and renamed into place, so a failure leaves the
  previous payload and no partial file, and a planted symlink is replaced
  rather than followed. Read with `O_NOFOLLOW`. The entry is 0700 and, on
  the target, root-owned: a zone reaches its payload only through its
  broker. Reclaiming an entry removes the file.
- **The zone 0 gesture**: `kryptikd clipboard move FROM TO` copies FROM's
  payload onto TO's (both running; same zone refused; a missing payload
  refused). The source keeps its payload — copy semantics for the user —
  and the destination's previous one is replaced. Run by the operator, or
  by the compositor on their behalf, in zone 0. No zone can trigger it.

## Evidence

- Unit: `broker::tests` drive `serve_connection` over socketpairs
  (round trip, a payload arriving in pieces, every refusal with the exact
  reply and the clipboard left intact, the peer-uid refusal, the move with
  its source preserved and the symlink cases, the parser).
- Probes (`security/probes/fixed-checks.sh`): BR1–BR3 identity and tree;
  BR4 round trip inside a zone; BR5 oversize refused from the header; BR6
  MIME refused; BR7 `clipboard-move` refused as a zone verb (B10); BR8
  zone 0 moves `probe`'s payload to a concurrently running `packet`, which
  reads it; BR9 the move is refused when the zones are not running.
- Integration suite (integration's): BRK1–BRK4, including the root-side
  refusal of a peer that is not the zone.

## Not built, and what it needs

- **`transfer`** (Design 05 B1–B8, B12): the `[transfer] to = ...` policy in
  zone files, `SCM_RIGHTS` receive, the fstat/st_dev/O_RDONLY checks, the
  uid-switching copy helper into `<dest>/incoming/`. The verb answers
  "not implemented yet". Next.
- **Consent.** Design 05 puts a user prompt before a transfer and makes
  the clipboard move a compositor gesture; there is no UI, so the gesture
  is the command, run by whoever holds zone 0. `--auto-approve` does not
  exist because nothing asks yet.
- **The Wayland proxy socket** (`wayland-0`) — identity only, later. When
  it lands it is the second entry under `/run/kryptik` inside a zone
  (integration's LC6b should allow the set {broker, wayland-0}).
- **A zone-side client.** Zones speak the wire format directly today
  (the probes use python sockets); a tiny `kryptik-clip` in the image
  would be integration's.
