# Pending security fixes

Base reviewed: `44d2b1e`. Keep this work uncommitted for the combined review.
The user's latest instruction is **source review only: no WSL builds or test
runs**. Do not run the commands below without a later change to that instruction.

## Changes in the working tree

| Area | Defect and change | Evidence |
| --- | --- | --- |
| Display launcher | A passphrase FD could survive exec into a newly started Wayland proxy. The proxy child now establishes stdio, closes every other descriptor, and fails if that cleanup fails. TTY-created memfds use CLOEXEC; the scratch secret uses explicit zeroing. | The new process regression failed before and passed after: the daemon receives the secret and the proxy has no secret FD. |
| Launch daemon | Connecting to a session-owned proxy listener could block indefinitely when its accept backlog was full, before peer checks. The verification connection is now nonblocking and refuses a full backlog. | Socket regression failed before and passed after. Existing real-proxy acceptance also passed in the isolated integration suite. |
| Passphrase descriptors | A pipe writer could withhold EOF indefinitely. The reader now has a five-second deadline and private nonblocking file description; sender changes to shared flags/offsets do not control subsequent reads. | Stalled-pipe regression failed before and passed after. Positive tests cover memfds, the initial file offset, closed pipes, and size limits. |
| Passphrase files | Permissions were checked by pathname before reopening it; reads were unbounded and CR/LF-only input became an accepted empty secret. The reader checks the opened inode, refuses final symlinks and non-files, bounds input to 4096 bytes, and rejects empty normalized secrets. Partial reads/errors use the existing secret-zeroing Drop path. | Boundary regression failed before and passed after. The pathname race is addressed by source inspection of open-before-fstat, not a separately timed race experiment. |
| Wayland protocol | Global IDs could be bound with a mismatched interface or version; live object IDs could be overwritten; negotiated versions were discarded after binding. Bindings now match advertisements, duplicate IDs are refused, and request/event versions are enforced for objects and inherited by their children. | Negative regressions failed before; valid ID reuse after delete_id remains covered. |
| Launcher diagnostics | The root daemon loaded the entire zone log into memory; any invalid UTF-8 discarded the entire error summary. It now reads at most an 8 KiB tail of a regular file and decodes malformed bytes lossily. | The added binary-prefix/large-log regression failed before. **The final fix has only been source-reviewed; it was not run after the user's stop instruction.** |
| Tree-update verifier log | `tee` opened a predictable temporary filename and could follow a planted symlink where filesystem protections permit it. The log now uses `mktemp`. | Source review; regression added to the existing updater suite but **not run**. This is not a claim that the target's default sticky-directory symlink protections were bypassed. |

## Verification already performed before the stop instruction

- 48 Wayland proxy unit tests and four proxy process/socket tests passed.
- 157 kryptikd tests passed; the real LUKS lifecycle test was explicitly
  excluded. The suite includes tests conditional on host kernel support;
  this count is not evidence that every target-kernel feature was exercised.
- 37 launch-service integration checks passed, none skipped, using freshly
  compiled binaries in a private mount/PID namespace, with private `/run` and
  `/var/log`. Valid proxy verification, launching, stopping, and malformed
  requests were exercised.
- `python3 tools/test-launch-secrets.py` passed using the real C launcher
  with only the fixed proxy executable and daemon socket paths redirected
  to temporary stand-ins.
- Existing compiler warnings remain. No distro image was rebuilt and no
  G1-G10 media-acceptance claim is made.

The final diagnostic-tail and verifier-log changes postdate those runs.
Keep them marked unexecuted until testing is authorized again. The temporary
build directories checked after the stop instruction were already absent.

## Review constraints and remaining leads

- A timeout around regular-file reads cannot promise to interrupt blocked
  filesystem/device I/O: Linux O_NONBLOCK does not provide that guarantee.
  The passphrase deadline closes the demonstrated pipe/EOF stall. See the
  [open manual](https://man7.org/linux/man-pages/man2/open.2.html).
- Negotiated-version inheritance and ID reuse follow the
  [Wayland protocol model](https://wayland.freedesktop.org/docs/book/Protocol.html)
  and [delete_id contract](https://wayland.freedesktop.org/docs/html/apa.html).
  Validation gaps are not proof of a compositor escape.
- **Continue reviewing host log storage.** Zone stdout/stderr still reach a
  host log file through inherited stdio. Bounding the diagnostic reader does
  not bound log growth or establish disk-exhaustion resistance. Trace
  `spawn_launcher` in `serve.rs` and the stdio exception in `rootfs.rs`.
- **Continue reviewing the separate tree updater.** `apply-update.sh` verifies
  a mutable payload and subsequently copies it. `release-manifest.sh` rereads
  the manifest after signature verification, and its exact-file enumeration
  uses `find -type f`. Investigate mutation races and unsigned symlink/special
  entries as a single end-to-end installation boundary. The on-media updater
  already snapshots its manifest; do not mistake that for a fix in these
  separate tools.
- Boot-state authentication, upstream advisory coverage, actual image
  privilege bits, and production signing continuity still require the wider
  review described in `CLAUDE_SECURITY_REVIEW.md`. That older handoff contains
  leads which subsequent commits have addressed; recheck the current code.

No commits or pushes have been made for this bundle.
