# Supply Chain

Kryptik builds every shipped binary from source, which moves the trust question
from "do I trust this distro's build servers" to "do I trust these tarballs".

## Source integrity

`sources.lock` pins a SHA-256 for every upstream tarball.
`tools/fetch-sources.sh` refuses to proceed on a mismatch — it does not warn and
continue.

**The lock file is trust-on-first-use.** `--lock` records the hash of whatever
downloaded; it does not prove the download was authentic. Before committing a
lock file or changing an entry:

1. Verify the tarball's upstream GPG signature or published hash by hand.
2. Confirm the signing key against a source independent of the download mirror.
3. Only then commit.

A lock file generated on an untrusted network and committed unaudited provides
the appearance of integrity without the substance. That is worse than no lock
file, because it stops people from looking.

## Checksums are not in versions.env

Deliberately. Keeping versions and hashes in separate files means a version bump
cannot silently carry a hash change through review — the lock diff is visible on
its own.

## Open problems

- **No signature verification in the fetcher yet.** GPG verification against a
  pinned keyring belongs in `fetch-sources.sh`. Currently manual. This is the
  largest gap in the story today.
- **No reproducible builds.** Deferred past Phase 5 (docs/roadmap.md). Until
  then, "built from source" means trusting the machine that built it.
- **No bootstrappable-builds story.** The initial compiler comes from the host
  distro, so Thompson's "Reflections on Trusting Trust" applies in full.
  Mitigating it properly means something like `live-bootstrap`, which is a
  project of its own.
