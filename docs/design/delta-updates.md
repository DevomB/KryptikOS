# Delta updates

The [update channel](update-channel.md#open-points) leaves delta updates
open: dm-verity's block structure would let a machine fetch only the blocks
that changed instead of the whole image. This document works out how the
client knows which blocks, what stays signed, how a cut download resumes,
where the A/B write takes its bytes from, what a hostile net zone gains, and
whether it is worth doing at today's release sizes.

## Where things stand

- **A payload** is `kryptik-root.img`, `kryptik-a.efi`, `kryptik-b.efi`,
  `root.json`, `manifest` and `manifest.sig`. The manifest lists every
  file's SHA-256 and size and is signed by the release key
  ([boot and updates](boot-and-updates.md#updates)).
- **The channel moves whole files.** `update-put` takes the manifest and its
  signature first. Then it takes only listed files, each from the byte zone 0
  holds, in order, never past the signed size, in pieces of at most 1 MiB
  (`may_put` and `put` in `compartments/kryptikd/src/update.rs`). Zone 0
  stores no more than the release's signed size, and `apply` checks every
  hash before it writes the inactive slot.
- **The image is sent raw.** `kryptik-root.img` is an ext4 filesystem
  followed by its hash tree, about 1,560 MiB today. Stage 06 sizes the
  filesystem at its contents plus an eighth plus 96 MiB, so a large part of
  what crosses the network is free blocks: zeros. The v0.1.0 USB medium, ESP
  and root together, compresses with zstd to 390,968,131 bytes; a medium is
  about 2.2 GB raw. The kernels are about 22 MB each and do not compress,
  since they are zstd inside already.
- **The hash tree is an authenticated index.** `root.json`, which the
  manifest lists, names the root hash, the salt, the number of data blocks
  and where the tree starts. The tree's lowest level holds one SHA-256 per
  4 KiB data block, salted. Its first level is about 1/128 of the data, some
  13 MB.

## Constraints

- **The manifest still covers the whole result.** A delta is a way to
  transport bytes, never a different thing to verify: the staged
  `kryptik-root.img` must hash to the manifest's SHA-256, and `apply` checks
  it as now.
- **Zone 0 stores only what is proven,** which is new with this design, and
  as now never more than the signed size
  ([update channel](update-channel.md#bytes-in-an-order-that-bounds-them)).
- **The net zone is hostile.** It may lie, withhold, reorder and cut.
- **The broker's loop answers each request within 5 s,** so anything long,
  such as hashing a whole slot, runs outside it.
- **`apply` and the trial do not change.** A failed or interrupted fetch
  must leave both slots as they were.

## How the client knows which blocks

1. After the manifest verifies, zone 0 takes `root.json` whole and checks it
   against the manifest. It then takes the image's tree region (from the
   block where the tree starts to the end of the file) and checks the tree
   up to the root hash. From that moment it holds an authenticated hash for
   every 4 KiB block of the new image.
2. A helper outside the broker's loop, `kryptik-update plan-delta`, reads
   the committed slot and hashes each of its data blocks with the **new**
   image's salt. A block of the old image whose salted hash equals the new
   image's hash for some block is that block. The match is by content, so a
   file that moved because something before it grew is found wherever it now
   lies. ext4 keeps file data block-aligned, which is what makes 4 KiB blocks
   match at all.
3. The helper writes into the stage the blocks it found and a plan: the runs
   of blocks it did not find. The plan is all `update-poll` names from then
   on.

Which source it reads does not matter. Every block is checked against the
new tree before it is used, so a damaged or hostile source can only fail to
match.

## The verbs

None of this is built. With delta fetching the verbs would change:

- `update-poll` answers with the next runs still missing, at most 64 per
  answer, as `kryptik-root.img <offset>+<length>`. Runs are whole 4 KiB
  blocks.
- `update-put kryptik-root.img <offset> <len>` is accepted only for bytes
  inside a run of the plan. Each 4 KiB block in it is checked against its
  hash before it is written into the staged image at its own offset; a
  block that does not match refuses the piece, and nothing of it is kept.
  The 1 MiB piece limit stays.
- The kernels and `root.json` still come whole, from the byte held. They
  are small, and a signed PE file differs entirely between builds.

The net zone's fetcher turns runs into HTTP range requests. It may join two
runs separated by a short gap into one request and drop the gap's bytes
itself. Zone 0 takes no byte outside the plan.

## Resuming

The plan, and which of its runs are complete, live in the stage. A cut
fetch resumes from the runs still missing. A block, once verified and
written, is never fetched again. If the committed slot changes before the
fetch completes (a rollback, a recovery), the plan is thrown away with the
stage, since it was made from that slot.

## The write into the inactive slot

Two places to assemble the new image:

- **In the stage on the state partition,** as today: local blocks and fetched
  blocks go into a complete `kryptik-root.img`, and `apply` then verifies and
  writes it exactly as it does a full download. The state partition still
  needs room for one image, as now.
- **Straight into the inactive slot.** That saves the staging space, but the
  inactive slot is the fallback: a fetch that takes hours would leave the
  machine with no slot to fall back to for that time, and `apply`'s rule,
  verify everything before writing anything, would no longer hold. Rejected.

## What a hostile net zone gains

- **Nothing new to install.** Every stored block is proven by the signed tree
  before it is written; the image is still hashed whole against the
  manifest.
- **No more storage.** At most the image's signed size, as now.
- **Knowledge.** The runs zone 0 asks for depend on the release the machine
  runs, so the net zone, and the release host it asks, learn that release.
  Today they learn only that the machine fetches. This is new, small, and the
  user should know it.
- **A little more work for zone 0.** A hostile zone can make zone 0 hash
  rejected 1 MiB pieces, about what it costs today to receive them.

## Is it worth it

Two steps, and the first is cheaper:

- **Compress the image for transport.** The v0.1.0 medium shrinks to a fifth
  with zstd, most of the gain being free blocks and text. The manifest lists
  `kryptik-root.img.zst` with its own SHA-256, and zone 0 decompresses only
  after that hash matches, so the decompressor reads only bytes the release
  key vouched for. That needs no new verb, only a file name and a step in
  `apply`. It brings a full update from about 1.6 GB to a few hundred
  megabytes.
- **Fetch changed blocks only.** It pays when releases change a small part
  of the image. Today they change much more than their content does: every
  build writes new times into every inode, and the salt differs, so
  `root.json` and the whole tree change. Block matching works across salts,
  but inode tables full of new timestamps do not match. Once builds are
  reproducible (`docs/design/reproducible-builds.md`, proposed beside this
  one), an unchanged file gives unchanged blocks, and a routine release, a
  library bump or a new kernel's modules, should touch a small part of the
  image. Blocks travel uncompressed, so the delta wins over the compressed
  full image only when under about a fifth of the image changes.

CI can measure that without building anything new: the update suite already
has two releases. A count of the second image's blocks not found in the
first, added to the acceptance report, says what a delta would have fetched
for every release from now on.

## Recommendation

1. Compress the payload's image for transport, verified before it is
   decompressed.
2. Add the delta count to the acceptance report.
3. Build delta fetching once builds are reproducible and the reported deltas
   stay well under a fifth of the image: the plan from the committed slot,
   blocks checked against the authenticated tree, assembly in the stage, and
   `apply` unchanged.

## The check that proves it done

The update suite's network step, against its own release server:

- a release fetched as a delta from the previous one moves fewer bytes than
  the compressed image, as the server counts them;
- the staged image hashes to the manifest, and the release applies,
  trial-boots and commits as today;
- a block the server alters is refused and fetched again;
- a cut in the middle resumes without fetching a verified block twice;
- a machine two releases behind gets a working delta;
- a server that answers with bytes outside the plan, or past the signed
  size, gets them refused and stored nowhere.
